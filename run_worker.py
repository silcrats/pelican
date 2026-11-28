"""
Pelican worker: a long-running process that asks the admin portal for due
jobs (crawls, ACL syncs, connection tests, removals, index rebuilds) and runs them as the
ordinary one-shot scripts, as many at a time as the portal allows (set on
its Activity page). Replaces the scheduler and the one container per job:
to crawl more in parallel, allow more jobs at once or start more workers.

The worker holds the credentials (SMB, Graph, OpenSearch) in its
environment and passes them on to each job; the portal only says what to
crawl. Each job gets the YAML for just its source, in a private
temporary file.

    ADMIN_URL      the portal, e.g. http://admin:8091
    WORKER_TOKEN   the portal's WORKER_TOKEN
    WORKER_NAME    shown in the portal; must differ between workers (default:
                   the container's Compose name, e.g. pelican-worker-2, else
                   the host name)
    WORKER_STATE_DIR  where each type's state lives: <dir>/smb, /exchange,
                   /sharepoint (default /state; mount each state volume there)
"""

import collections
import json
import os
import re
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

import requests

ADMIN_URL = os.environ.get("ADMIN_URL", "http://admin:8091").rstrip("/")
WORKER_TOKEN = os.environ.get("WORKER_TOKEN", "")
def _container_name(dns_server=("127.0.0.11", 53)) -> str | None:
    """This container's name as Docker's DNS knows it ("lab-worker-1" from
    "lab-worker-1.lab_search"), so a worker keeps the same readable name
    across rebuilds and each `--scale` copy gets its own. Docker answers
    this reverse lookup at 127.0.0.11 on a user-defined network; /etc/hosts
    only has the container ID, so ask that server directly. None outside
    Docker or if it doesn't answer."""
    try:
        ip = socket.gethostbyname(socket.gethostname())
        arpa = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
        query = struct.pack(">HHHHHH", 0x5050, 0x0100, 1, 0, 0, 0)
        query += b"".join(bytes([len(p)]) + p.encode() for p in arpa.split(".")) + b"\0" + struct.pack(">HH", 12, 1)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(1)
            s.sendto(query, dns_server)
            reply = s.recv(512)
        if reply[:2] != query[:2] or not struct.unpack(">H", reply[6:8])[0]:
            return None
        i = len(query)
        i += 2 if reply[i] & 0xC0 else reply.index(b"\0", i) + 1 - i   # the answer's name
        i += 10                                                         # type, class, TTL, length
        label = reply[i + 1:i + 1 + reply[i]].decode()                  # first label of the PTR name
        return label if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", label) else None
    except (OSError, IndexError, struct.error, UnicodeDecodeError):
        return None


WORKER_NAME = os.environ.get("WORKER_NAME") or _container_name() or socket.gethostname()
STATE_DIR = os.environ.get("WORKER_STATE_DIR", "/state")
# Where the crawlers write their progress (pelican/status.py); read for the
# running totals shown in the portal.
STATUS_DIR = os.environ.get("STATUS_DIR", "/status")
POLL_SECONDS = float(os.environ.get("WORKER_POLL_SECONDS", "5"))
HEARTBEAT_SECONDS = 15
STOP_GRACE_SECONDS = 30
LOG_CHARS = 20000
CA_CERTS = os.environ.get("ADMIN_CA_CERTS") or True
APP_DIR = os.path.dirname(os.path.abspath(__file__))

SCRIPTS = {
    ("smb", "crawl"): ["crawl_smb.py"],
    ("smb", "acl"): ["sync_smb_acl.py"],
    ("exchange", "crawl"): ["crawl_exchange.py"],
    ("sharepoint", "crawl"): ["crawl_sharepoint.py"],
}
# Never handed on to a job: it only lets the worker talk to the portal.
PRIVATE_ENV = ("WORKER_TOKEN",)
# Only handed to index jobs (rebuild_index.py), which use nothing else of OpenSearch.
MAINT_ENV = ("OS_MAINT_USERNAME", "OS_MAINT_PASSWORD")


def _version() -> str:
    try:
        with open(os.path.join(APP_DIR, "version")) as f:
            return f.readline().strip() or "dev"
    except OSError:
        return "dev"


VERSION = _version()


class Portal:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers["Authorization"] = f"Bearer {WORKER_TOKEN}"

    def post(self, path: str, body: dict, timeout: float = 30) -> requests.Response:
        return self.session.post(ADMIN_URL + path, json={"worker": WORKER_NAME, **body}, timeout=timeout,
                                 verify=CA_CERTS)


class Job:
    def __init__(self, spec: dict):
        self.spec = spec
        self.id = spec["id"]
        self.type = spec["type"]
        # Index jobs (the portal's Index page) aren't about one source.
        source = spec.get("source") or {"kind": "index", "name": "index"}
        self.kind = source["kind"]
        self.name = source["name"]
        self.api = "index-jobs" if self.type == "index" else "jobs"
        self.log = collections.deque()
        self.log_chars = 0
        self.lock = threading.Lock()
        self.proc: subprocess.Popen | None = None
        self.reader: threading.Thread | None = None
        self.tmpdir = tempfile.mkdtemp(prefix=f"pelican-job-{self.id}-")
        # The first heartbeat comes after a few seconds, so totals show early.
        self.last_heartbeat = time.time() - HEARTBEAT_SECONDS + 3
        self.stopping_since: float | None = None
        self.abandoned = False   # the portal gave the job to someone else
        self.job_name = f"{'acl' if self.type == 'acl' else self.kind}-{self.name}"
        self.started_at = time.time()

    def command(self) -> list[str]:
        if self.type == "index":
            return [sys.executable, "-u", "rebuild_index.py"]
        if self.type == "test":
            return [sys.executable, "-u", "check_source.py", self.kind, self.name]
        if self.type == "purge":
            return [sys.executable, "-u", "purge_source.py", self.kind, self.name]
        script = SCRIPTS.get((self.kind, self.type))
        if not script:
            raise ValueError(f"no {self.type} job for {self.kind}")
        return [sys.executable, "-u", *script]

    def start(self) -> None:
        if self.type == "index":
            env = {k: v for k, v in os.environ.items()
                   if k not in PRIVATE_ENV and k not in ("OS_USERNAME", "OS_PASSWORD")}
            env["INDEX_OP"] = json.dumps(self.spec["op"])
            try:
                os.unlink(self.status_path())   # so no earlier job's progress shows
            except OSError:
                pass
        else:
            config_path = os.path.join(self.tmpdir, "source.yaml")
            with open(config_path, "w") as f:   # mkdtemp's directory is private to this user
                f.write(self.spec["config_yaml"])
            env = {k: v for k, v in os.environ.items() if k not in PRIVATE_ENV and k not in MAINT_ENV}
            env.update({
                self.spec["config_env"]: config_path,
                self.spec["names_env"]: self.name,
                "JOB_NAME": self.job_name,
                "STATE_DB_PATH": os.path.join(STATE_DIR, self.kind, "pelican_state.db"),
            })
        self.proc = subprocess.Popen(self.command(), cwd=APP_DIR, env=env, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, text=True, errors="replace", bufsize=1,
                                     start_new_session=True)
        self.reader = threading.Thread(target=self._read_output, daemon=True)
        self.reader.start()
        what = f"index job ({self.spec['op'].get('action')})" if self.type == "index" else \
            f"{self.type} of {self.kind} source {self.name}"
        print(f"[job {self.id}] started {what}", flush=True)

    def _read_output(self) -> None:
        for line in self.proc.stdout:
            print(f"[job {self.id} {self.name}] {line}", end="", flush=True)
            with self.lock:
                self.log.append(line)
                self.log_chars += len(line)
                while self.log_chars > LOG_CHARS and len(self.log) > 1:
                    self.log_chars -= len(self.log.popleft())

    def log_text(self) -> str:
        with self.lock:
            return "".join(self.log)

    def summary(self) -> str:
        with self.lock:
            lines = [l.strip() for l in self.log if l.strip()]
        return lines[-1][:300] if lines else ""

    def progress(self) -> str:
        """Running totals from the status file the crawler writes, e.g.
        "1,204 indexed · 18,330 unchanged · 19,601 found"; "" before it
        has written one this run, and for tests and removals. Index jobs
        write a line of their own ("12,000 of 91,598 documents copied")."""
        if self.type not in ("crawl", "acl", "index"):
            return ""
        path = self.status_path()
        try:
            if os.path.getmtime(path) < self.started_at - 1:
                return ""   # left from an earlier run
            with open(path) as f:
                data = json.load(f)
            if self.type == "index":
                return str(data.get("progress") or "")[:300]
            s = (data.get("shares") or {}).get(self.name)
        except (OSError, ValueError, AttributeError):
            return ""
        if not s:
            return ""
        if self.type == "acl":
            return (f"{s.get('acl_docs_updated', 0):,} documents updated · "
                    f"{s.get('acl_groups_changed', 0):,} folders changed")
        parts = [f"{s.get('indexed', 0):,} indexed", f"{s.get('skipped_unchanged', 0):,} unchanged"]
        if s.get("skipped_excluded"):
            parts.append(f"{s['skipped_excluded']:,} excluded")
        parts.append(f"{s.get('discovered', 0):,} found")
        return " · ".join(parts)

    def status_path(self) -> str:
        return os.path.join(STATUS_DIR, "status-index.json" if self.type == "index"
                            else f"status-{self.job_name}.json")

    def stop(self) -> None:
        """SIGTERM to the job's process group, then SIGKILL if it lingers."""
        if self.proc and self.proc.poll() is None:
            if self.stopping_since is None:
                self.stopping_since = time.time()
                os.killpg(self.proc.pid, signal.SIGTERM)
            elif time.time() - self.stopping_since > STOP_GRACE_SECONDS:
                os.killpg(self.proc.pid, signal.SIGKILL)

    def cleanup(self) -> None:
        try:
            for f in os.listdir(self.tmpdir):
                os.unlink(os.path.join(self.tmpdir, f))
            os.rmdir(self.tmpdir)
        except OSError:
            pass


class Worker:
    def __init__(self):
        self.portal = Portal()
        self.jobs: dict[int, Job] = {}
        self.unreported: list[tuple[str, int, dict]] = []   # finish reports the portal hasn't taken yet
        self.shutting_down = False
        self.slots: int | None = None   # jobs at once, as the portal last said

    def run(self) -> None:
        if len(WORKER_TOKEN) < 32:
            sys.exit("WORKER_TOKEN must be set (the portal's WORKER_TOKEN, 32+ characters)")
        signal.signal(signal.SIGTERM, self._on_signal)
        signal.signal(signal.SIGINT, self._on_signal)
        print(f"pelican worker {WORKER_NAME} ({VERSION}), portal {ADMIN_URL}", flush=True)
        next_claim = 0.0
        while not (self.shutting_down and not self.jobs and not self.unreported):
            # Every second: running jobs' heartbeats and finishes. New work is
            # asked for every POLL_SECONDS, or straight away after a claim.
            self._reap()
            self._report()
            self._heartbeats()
            if self.shutting_down:
                for job in self.jobs.values():
                    job.stop()
            elif time.time() >= next_claim:
                if self._claim():
                    continue   # another job may be due too
                next_claim = time.time() + POLL_SECONDS
            time.sleep(1)
        print("worker stopped", flush=True)

    def _on_signal(self, signum, frame) -> None:
        if not self.shutting_down:
            print(f"stopping: ending {len(self.jobs)} running job(s)", flush=True)
        self.shutting_down = True

    def _claim(self) -> bool:
        if self.slots is not None and len(self.jobs) >= self.slots:
            return False   # still asked every POLL_SECONDS, to hear of a change
        try:
            r = self.portal.post("/api/worker/claim", {"running": len(self.jobs), "version": VERSION})
            r.raise_for_status()
            reply = r.json()
            spec = reply.get("job")
            slots = reply.get("slots")
            if isinstance(slots, int) and slots != self.slots:
                print(f"runs up to {slots} job(s) at once", flush=True)
                self.slots = slots
        except (requests.RequestException, ValueError) as exc:
            print(f"portal unreachable: {exc}", flush=True)
            return False
        if not spec:
            return False
        job = Job(spec)
        try:
            job.start()
        except Exception as exc:
            job.cleanup()
            self.unreported.append((job.api, job.id, {"ok": False, "exit_code": None, "log": str(exc),
                                             "summary": f"couldn't start: {exc}"}))
            return True
        self.jobs[job.id] = job
        return True

    def _heartbeats(self) -> None:
        now = time.time()
        for job in list(self.jobs.values()):
            if now - job.last_heartbeat < HEARTBEAT_SECONDS:
                continue
            try:
                r = self.portal.post(f"/api/worker/{job.api}/{job.id}/heartbeat",
                                     {"log": job.log_text(), "progress": job.progress()})
                if r.status_code == 409:
                    print(f"[job {job.id}] the portal gave this job up; stopping it", flush=True)
                    job.stop()
                    job.abandoned = True
                elif r.ok and r.json().get("cancel"):
                    if job.stopping_since is None:
                        print(f"[job {job.id}] cancelled in the portal", flush=True)
                    job.stop()
                job.last_heartbeat = now
            except (requests.RequestException, ValueError) as exc:
                print(f"[job {job.id}] heartbeat failed: {exc}", flush=True)
            if job.stopping_since is not None:
                job.stop()   # escalates to SIGKILL after the grace period

    def _reap(self) -> None:
        for job_id, job in list(self.jobs.items()):
            code = job.proc.poll()
            if code is None:
                continue
            job.reader.join(timeout=5)   # the last lines of output
            job.proc.stdout.close()
            del self.jobs[job_id]
            job.cleanup()
            print(f"[job {job_id}] finished with exit status {code}", flush=True)
            if job.abandoned:
                continue
            # A crawl's totals when it worked; otherwise the last line (an index
            # job's result, or usually the error).
            summary = (code == 0 and job.type != "index" and job.progress()) or job.summary()
            if code != 0 and job.stopping_since is not None:
                summary = "stopped" + (" (worker shutting down)" if self.shutting_down else "")
            self.unreported.append((job.api, job_id, {"ok": code == 0, "exit_code": code, "log": job.log_text(),
                                             "summary": summary}))

    def _report(self) -> None:
        still = []
        for api, job_id, body in self.unreported:
            try:
                r = self.portal.post(f"/api/worker/{api}/{job_id}/finish", body)
                if r.status_code in (200, 409):   # 409: the portal already gave it up
                    continue
                print(f"[job {job_id}] finish report refused: HTTP {r.status_code}", flush=True)
            except requests.RequestException as exc:
                print(f"[job {job_id}] finish report failed: {exc}", flush=True)
            if not self.shutting_down:
                still.append((api, job_id, body))
        self.unreported = still


if __name__ == "__main__":
    Worker().run()
