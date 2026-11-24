"""
Pelican admin portal: a web UI and API for adding, changing and removing
the sources Pelican crawls, scheduling their crawls, and delegating that
to other AD groups (see store.py for the rules).

People sign in with their AD account. Workers (run_worker.py in the
pelican image) ask this service for due jobs with a shared token, run the
crawlers and report back; this service never sees a source credential or
the OpenSearch write account.

On every change it also writes each type's YAML file (all sources) into
ADMIN_EXPORT_DIR, for Frogmouth's downloads and the mailbox permission
export, which read shares.yaml / exchange.yaml from a file.
"""

import base64
import hmac
import http.cookies
import http.server
import json
import mimetypes
import os
import re
import secrets
import ssl
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import parse_qs, unquote, urlparse

import store as store_mod
from storage import Storage
from store import FIELDS, KIND_INFO, KINDS, Forbidden, Invalid, NotFound

APP_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(APP_DIR, "static")
PORT = int(os.environ.get("PORT", "8091"))
DB_PATH = os.environ.get("ADMIN_DB_PATH", "/data/pelican-admin.db")
EXPORT_DIR = os.environ.get("ADMIN_EXPORT_DIR", "/export")
IMPORT_DIR = os.environ.get("ADMIN_IMPORT_DIR", "/import")
SUPER_ADMIN_GROUPS = [g.strip() for g in os.environ.get("SUPER_ADMIN_GROUPS", "").split(",") if g.strip()]
WORKER_TOKEN = os.environ.get("WORKER_TOKEN", "")
BREAKGLASS_USER = os.environ.get("ADMIN_BREAKGLASS_USER") or "pelican-admin"
BREAKGLASS_PASSWORD = os.environ.get("ADMIN_BREAKGLASS_PASSWORD", "")
SECURE_COOKIE = os.environ.get("ADMIN_SECURE_COOKIE", "").lower() in ("1", "true", "yes")
SESSION_SECONDS = 8 * 3600
SESSION_COOKIE = "pelican_admin_session"
FAILED_SIGN_IN_DELAY_SECONDS = 1
MAX_BODY_BYTES = 1024 * 1024
MIN_SECRET_LENGTH = {"WORKER_TOKEN": 32, "ADMIN_BREAKGLASS_PASSWORD": 16}
# Mutating API calls must carry this header. A page on another site can't
# add a custom header to a request without a CORS preflight, which this
# server never approves; with the SameSite=Strict cookie, that stops
# cross-site request forgery.
CSRF_HEADER = "X-Pelican-Admin"

# Document counts (shown before a removal) and the Storage page. Optional: an
# account that can search and read index and node stats (pelican-status).
# Host values must match config/pelican.yaml.
OS_HOST = os.environ.get("OS_HOST", "").rstrip("/")
SEARCH_INDEX = os.environ.get("SEARCH_INDEX", "documents")
OS_USERNAME = os.environ.get("OS_USERNAME", "")
OS_PASSWORD = os.environ.get("OS_PASSWORD", "")
_SSL = ssl.create_default_context(cafile=os.environ.get("OS_CA_CERTS") or None)
STORAGE_HISTORY_PATH = os.path.join(os.path.dirname(DB_PATH), "storage-history.jsonl")
STORAGE_REFRESH_MIN_SECONDS = 60   # "Refresh now" at most this often
SOURCE_HOSTS = {"smb": os.environ.get("HOST_SMB", "smb-share"),
                "exchange": os.environ.get("HOST_EXCHANGE", "exchange-online"),
                "sharepoint": os.environ.get("HOST_SHAREPOINT", "sharepoint-online")}


def _read_version() -> str:
    try:
        with open(os.path.join(APP_DIR, "version")) as f:
            version, _, revision = f.read().partition("\n")
    except OSError:
        return "dev"
    version, revision = version.strip() or "dev", revision.strip()[:7]
    if version[:1].isdigit():
        return f"v{version}"
    return f"{version} ({revision})" if revision else version


VERSION = _read_version()


def _check_config():
    problems = []
    if len(WORKER_TOKEN) < MIN_SECRET_LENGTH["WORKER_TOKEN"]:
        problems.append("WORKER_TOKEN must be set, at least 32 characters (workers send it to claim jobs)")
    if BREAKGLASS_PASSWORD and len(BREAKGLASS_PASSWORD) < MIN_SECRET_LENGTH["ADMIN_BREAKGLASS_PASSWORD"]:
        problems.append("ADMIN_BREAKGLASS_PASSWORD must be at least 16 characters")
    if not os.environ.get("LDAP_URL") and not BREAKGLASS_PASSWORD:
        problems.append("set LDAP_URL (and LDAP_BIND_TEMPLATE, LDAP_BASE_DN), or ADMIN_BREAKGLASS_PASSWORD")
    if os.environ.get("LDAP_URL") and not SUPER_ADMIN_GROUPS:
        problems.append("SUPER_ADMIN_GROUPS must name at least one AD group of super admins")
    if problems:
        sys.exit("pelican-admin won't start:\n  " + "\n  ".join(problems))


def _make_ldap():
    if not os.environ.get("LDAP_URL"):
        return None
    from ldap_auth import LdapAuth
    return LdapAuth(os.environ["LDAP_URL"], os.environ.get("LDAP_BIND_TEMPLATE", "{username}"),
                    os.environ.get("LDAP_BASE_DN", ""), os.environ.get("LDAP_USERNAME_ATTR") or "sAMAccountName",
                    start_tls=os.environ.get("LDAP_START_TLS", "").lower() in ("1", "true", "yes"),
                    ca_file=os.environ.get("LDAP_CA_FILE", ""))


def write_exports(st: store_mod.Store) -> None:
    """Each type's YAML file, written atomically, world-readable (the
    readers run as other users)."""
    if not EXPORT_DIR or not os.path.isdir(EXPORT_DIR):
        return
    with st.lock:
        files = st.render_all()
    for filename, text in files.items():
        fd, tmp = tempfile.mkstemp(dir=EXPORT_DIR, prefix=f".{filename}.")
        try:
            os.fchmod(fd, 0o644)
            with os.fdopen(fd, "w") as f:
                f.write(text)
            os.replace(tmp, os.path.join(EXPORT_DIR, filename))
        except OSError as exc:
            print(f"export of {filename} failed: {exc}")
            try:
                os.unlink(tmp)
            except OSError:
                pass


def import_existing(st: store_mod.Store) -> None:
    """On first start only: take the sources and settings from existing
    YAML files, so moving to the portal keeps what's configured."""
    if st.meta("imported"):
        return
    for kind in KINDS:
        path = os.path.join(IMPORT_DIR, KIND_INFO[kind]["file"])
        if os.path.isfile(path):
            with open(path) as f:
                added = st.import_yaml(kind, f.read())
            print(f"imported {added} source(s) from {path}")
    with st.lock:
        st.set_meta("imported", str(time.time()))
        st.db.commit()


def doc_count(kind: str, name: str) -> int | None:
    if not OS_HOST:
        return None
    body = json.dumps({"query": {"bool": {"filter": [{"term": {"share": name}},
                                                     {"term": {"host": SOURCE_HOSTS[kind]}}]}}}).encode()
    req = urllib.request.Request(f"{OS_HOST}/{SEARCH_INDEX}/_count", data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    if OS_USERNAME:
        req.add_header("Authorization", "Basic " + base64.b64encode(f"{OS_USERNAME}:{OS_PASSWORD}".encode()).decode())
    try:
        with urllib.request.urlopen(req, timeout=10, context=_SSL if OS_HOST.startswith("https") else None) as r:
            return int(json.load(r)["count"])
    except (urllib.error.URLError, OSError, ValueError, KeyError) as exc:
        print(f"document count for {name} failed: {exc}")
        return None


class App:
    def __init__(self, st: store_mod.Store, ldap=None, storage: Storage | None = None):
        self.store = st
        self.ldap = ldap
        self.storage = storage
        self.storage_refreshed = 0.0
        self.sessions: dict[str, dict] = {}
        self.sessions_lock = threading.Lock()

    # ---------------------------------------------------------- sessions

    def sign_in(self, username: str, password: str) -> store_mod.User | None:
        if BREAKGLASS_PASSWORD and hmac.compare_digest(username.encode(), BREAKGLASS_USER.encode()):
            if hmac.compare_digest(password.encode(), BREAKGLASS_PASSWORD.encode()):
                user = store_mod.User(BREAKGLASS_USER, [], "Break-glass admin", super_admin=True)
                return user
            return None
        if not self.ldap:
            return None
        from ldap_auth import SignInFailed
        try:
            name, groups, display = self.ldap.authenticate(username, password)
        except SignInFailed as exc:
            if "invalid credentials" not in str(exc):
                print(f"sign-in for {username!r}: {exc}")
            return None
        user = self.store.user(name, groups, display)
        return user if self.store.may_sign_in(user) else None

    def new_session(self, user: store_mod.User) -> str:
        token = secrets.token_urlsafe(32)
        now = time.time()
        with self.sessions_lock:
            for t in [t for t, s in self.sessions.items() if s["expires"] < now]:
                del self.sessions[t]
            self.sessions[token] = {"user": user, "expires": now + SESSION_SECONDS}
        return token

    def session_user(self, token: str | None) -> store_mod.User | None:
        if not token:
            return None
        with self.sessions_lock:
            s = self.sessions.get(token)
            if not s or s["expires"] < time.time():
                self.sessions.pop(token, None)
                return None
            return s["user"]

    def end_session(self, token: str | None) -> None:
        with self.sessions_lock:
            self.sessions.pop(token or "", None)

    # -------------------------------------------------------------- API

    def me(self, user) -> dict:
        st = self.store
        scopes = st.visible_scopes(user)
        if user.super_admin:
            creds = [c["name"] for c in st.credentials()]
            kinds = list(KINDS)
        else:
            creds = sorted({c for s in scopes for c in s["credentials"] if c != store_mod.DEFAULT_CREDENTIALS})
            kinds = [k for k in KINDS if any(k in s["kinds"] for s in scopes)]
        return {
            "username": user.username, "display_name": user.display_name, "super_admin": user.super_admin,
            "version": VERSION, "kinds": kinds,
            "kind_info": {k: {"label": KIND_INFO[k]["label"], "fields": FIELDS[k],
                              "permissions": store_mod.HAS_PERMISSIONS[k]} for k in KINDS},
            "scopes": scopes, "credentials": creds,
            "defaults": st.defaults, "min_minutes": store_mod.MIN_INTERVAL_MINUTES,
        }

    def sources(self, user) -> list[dict]:
        st = self.store
        with st.lock:
            last = st.last_jobs()
            scopes = {s["id"]: s["name"] for s in st.scopes()}
            out = []
            for s in st.visible_sources(user):
                s["scope_name"] = scopes.get(s["scope_id"])
                s["jobs"] = last.get(s["id"], {})
                out.append(s)
            return out

    def activity(self, user) -> dict:
        st = self.store
        with st.lock:
            visible = {s["id"]: s for s in st.visible_sources(user)}
            rows = st._q("SELECT id, source_id, type, status, requested_by, created_at, started_at, finished_at,"
                         " worker, summary FROM jobs WHERE status IN ('queued','running') OR finished_at > ?"
                         " ORDER BY id DESC LIMIT 500", (time.time() - 7 * 86400,))
            jobs = []
            for r in rows:
                if r["source_id"] in visible:
                    j = dict(r)
                    j["source_name"] = visible[r["source_id"]]["name"]
                    j["kind"] = visible[r["source_id"]]["kind"]
                    jobs.append(j)
            workers = st.workers() if user.super_admin else []
            return {"jobs": jobs[:200], "workers": workers, "default_slots": st.default_worker_slots(),
                    "max_slots": store_mod.MAX_WORKER_SLOTS, "now": time.time()}


    # ---------------------------------------------------------- storage

    def _storage_rows(self, user) -> tuple[dict | None, list[dict]]:
        """The latest storage figures and their per-source rows, each matched
        to the portal source it belongs to (by name and type), if any."""
        snap = self.storage.snapshot() if self.storage else {}
        data = snap.get("data")
        if not data:
            return None, []
        with self.store.lock:
            by_key = {(s["name"], SOURCE_HOSTS[s["kind"]]): s for s in self.store.all_sources()}
            visible = {s["id"] for s in self.store.visible_sources(user)}
        growth = (data.get("growth") or {}).get("docs_per_day_by_source") or {}
        rows = []
        for row in data["sources"]:
            source = by_key.get((row["name"], row["host"]))
            if not user.super_admin and (not source or source["id"] not in visible):
                continue
            rows.append({**row, "source_id": source["id"] if source else None,
                         "kind": source["kind"] if source else None,
                         "docs_per_day": growth.get(row["name"])})
        return data, rows

    def storage_view(self, user) -> dict:
        if not self.storage:
            return {"available": False}
        snap = self.storage.snapshot()
        data, rows = self._storage_rows(user)
        out = {"available": True, "updated": snap.get("updated"), "sources": rows,
               "refreshing": self.storage_refreshed > (snap.get("updated") or 0)}
        if user.super_admin:
            # The whole index and the disk: super admins only.
            out["error"] = snap.get("error")
            if data:
                out.update({k: data[k] for k in ("index", "index_bytes", "docs", "deleted_docs", "disk_total",
                                                 "disk_free", "sample_docs")})
                g = data.get("growth")
                out["growth"] = {k: v for k, v in g.items() if k != "docs_per_day_by_source"} if g else None
        elif snap.get("error"):
            out["error"] = "The latest storage figures couldn't be read; these may be out of date."
        return out

    def storage_for(self, user, source: dict) -> dict | None:
        _, rows = self._storage_rows(user)
        return next((r for r in rows if r["source_id"] == source["id"]), None)

    def refresh_storage(self, user) -> dict:
        if not user.super_admin:
            raise Forbidden()
        if not self.storage:
            raise Invalid("storage figures aren't set up (OS_HOST)")
        if time.time() - self.storage_refreshed < STORAGE_REFRESH_MIN_SECONDS:
            raise Invalid("the figures were refreshed less than a minute ago")
        self.storage_refreshed = time.time()
        self.storage.refresh_soon()
        return {"ok": True}


def _json(obj) -> bytes:
    return json.dumps(obj, default=str).encode()


class Handler(http.server.BaseHTTPRequestHandler):
    app: App = None
    server_version = "pelican-admin"
    sys_version = ""

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

    # --------------------------------------------------------- plumbing

    def _send(self, code: int, body: bytes = b"", ctype: str = "application/json", headers: dict | None = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _error(self, code: int, message: str):
        self._send(code, _json({"error": message}))

    def _token(self) -> str | None:
        cookie = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
        return cookie[SESSION_COOKIE].value if SESSION_COOKIE in cookie else None

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY_BYTES:
            raise Invalid("request too large")
        if not length:
            return {}
        if not (self.headers.get("Content-Type") or "").startswith("application/json"):
            raise Invalid("send JSON")
        try:
            body = json.loads(self.rfile.read(length))
        except ValueError:
            raise Invalid("not valid JSON")
        if not isinstance(body, dict):
            raise Invalid("send a JSON object")
        return body

    def _cookie(self, value: str, max_age: int) -> str:
        c = f"{SESSION_COOKIE}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}"
        return c + ("; Secure" if SECURE_COOKIE else "")

    # ------------------------------------------------------------ verbs

    def do_GET(self):
        self._dispatch("GET")

    def do_HEAD(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_PUT(self):
        self._dispatch("PUT")

    def do_DELETE(self):
        self._dispatch("DELETE")

    def _dispatch(self, method: str):
        path = urlparse(self.path).path
        try:
            if path == "/healthz":
                return self._send(200, b"ok\n", "text/plain")
            if path.startswith("/api/worker/"):
                return self._worker(method, path)
            if path.startswith("/api/"):
                return self._api(method, path)
            if method != "GET":
                return self._error(405, "method not allowed")
            return self._static(path)
        except Invalid as exc:
            self._error(400, str(exc))
        except Forbidden:
            self._error(403, "you can't do that")
        except NotFound as exc:
            self._error(404, str(exc) or "not found")
        except BrokenPipeError:
            pass
        except Exception as exc:   # don't leak details to the browser
            print(f"error handling {method} {path}: {exc!r}")
            import traceback
            traceback.print_exc()
            self._error(500, "internal error")

    def _static(self, path: str):
        if path in ("/", "") or not path.startswith("/static/"):
            path = "/static/index.html"   # one page; the app routes in the browser
        rel = os.path.normpath(path[len("/static/"):]).lstrip("/")
        full = os.path.join(STATIC_DIR, rel)
        if rel.startswith("..") or not os.path.isfile(full):
            return self._error(404, "not found")
        with open(full, "rb") as f:
            body = f.read()
        ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript",):
            ctype += "; charset=utf-8"
        self._send(200, body, ctype)

    # ------------------------------------------------------- worker API

    def _worker(self, method: str, path: str):
        auth = self.headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else ""
        if not WORKER_TOKEN or not hmac.compare_digest(token.encode(), WORKER_TOKEN.encode()):
            time.sleep(FAILED_SIGN_IN_DELAY_SECONDS)
            return self._error(401, "bad worker token")
        if method != "POST":
            return self._error(405, "method not allowed")
        body = self._body()
        worker = str(body.get("worker") or "")[:100]
        if not worker:
            raise Invalid("name the worker")
        st = self.app.store
        if path == "/api/worker/claim":
            job = st.claim(worker, int(body.get("running") or 0), str(body.get("version") or "")[:40])
            return self._send(200, _json({"job": job, "slots": st.worker_slots(worker)}))
        m = re.fullmatch(r"/api/worker/jobs/(\d+)/(heartbeat|finish)", path)
        if not m:
            return self._error(404, "not found")
        job_id = int(m.group(1))
        try:
            if m.group(2) == "heartbeat":
                return self._send(200, _json(st.heartbeat(worker, job_id, str(body.get("log") or ""),
                                                          progress=str(body.get("progress") or ""))))
            st.finish(worker, job_id, bool(body.get("ok")), body.get("exit_code"),
                      str(body.get("log") or ""), str(body.get("summary") or ""))
            return self._send(200, _json({"ok": True}))
        except Invalid as exc:
            return self._error(409, str(exc))

    # -------------------------------------------------------- admin API

    def _api(self, method: str, path: str):
        app, st = self.app, self.app.store
        if method != "GET":
            if self.headers.get(CSRF_HEADER) != "1":
                return self._error(403, f"missing {CSRF_HEADER} header")
            origin = self.headers.get("Origin")
            if origin and urlparse(origin).netloc != self.headers.get("Host"):
                return self._error(403, "cross-origin request refused")

        if path == "/api/login" and method == "POST":
            body = self._body()
            user = app.sign_in(str(body.get("username") or "").strip(), str(body.get("password") or ""))
            if not user:
                time.sleep(FAILED_SIGN_IN_DELAY_SECONDS)
                return self._error(401, "Wrong username or password, or this account has no admin access.")
            token = app.new_session(user)
            print(f"signed in: {user.username} ({'super admin' if user.super_admin else 'scoped admin'})")
            return self._send(200, _json(app.me(user)), headers={"Set-Cookie": self._cookie(token, SESSION_SECONDS)})
        if path == "/api/logout" and method == "POST":
            app.end_session(self._token())
            return self._send(200, _json({"ok": True}), headers={"Set-Cookie": self._cookie("", 0)})

        user = app.session_user(self._token())
        if not user:
            return self._error(401, "sign in")
        qs = parse_qs(urlparse(self.path).query)

        if path == "/api/me" and method == "GET":
            return self._send(200, _json(app.me(user)))

        if path == "/api/sources":
            if method == "GET":
                return self._send(200, _json(app.sources(user)))
            if method == "POST":
                return self._send(200, _json(st.save_source(user, self._body())))
        m = re.fullmatch(r"/api/sources/(\d+)(/count|/jobs)?", path)
        if m:
            sid, sub = int(m.group(1)), m.group(2)
            if sub == "/count" and method == "GET":
                source = st.managed_source(user, sid)
                return self._send(200, _json({"count": doc_count(source["kind"], source["name"])}))
            if sub == "/jobs" and method == "POST":
                return self._send(200, _json(st.request_job(user, sid, str(self._body().get("type")))))
            if sub == "/jobs" and method == "GET":
                st.managed_source(user, sid)
                return self._send(200, _json(st.jobs_for(sid)))
            if sub is None and method == "GET":
                with st.lock:
                    source = st.managed_source(user, sid)
                    source["jobs"] = st.jobs_for(sid)
                    source["rendered"] = st.render(source["kind"], [source])
                    source["storage"] = app.storage_for(user, source)
                    source["storage_available"] = bool(app.storage and app.storage.snapshot().get("updated"))
                return self._send(200, _json(source))
            if sub is None and method == "PUT":
                return self._send(200, _json(st.save_source(user, self._body(), sid)))
            if sub is None and method == "DELETE":
                return self._send(200, _json(st.remove_source(user, sid, str(self._body().get("confirm") or ""))))

        m = re.fullmatch(r"/api/jobs/(\d+)(/cancel)?", path)
        if m:
            job_id = int(m.group(1))
            if m.group(2) and method == "POST":
                return self._send(200, _json(st.cancel_job(user, job_id)))
            if not m.group(2) and method == "GET":
                job = st.job(job_id)
                st.managed_source(user, job["source_id"])
                return self._send(200, _json(job))

        if path == "/api/storage" and method == "GET":
            return self._send(200, _json(app.storage_view(user)))
        if path == "/api/storage/refresh" and method == "POST":
            return self._send(200, _json(app.refresh_storage(user)))

        if path == "/api/workers/default" and method == "PUT":
            return self._send(200, _json({"slots": st.set_default_worker_slots(user, self._body().get("slots"))}))
        m = re.fullmatch(r"/api/workers/([^/]+)", path)
        if m and method == "PUT":
            name = unquote(m.group(1))
            return self._send(200, _json({"slots": st.set_worker_slots(user, name, self._body().get("slots"))}))

        if path == "/api/activity" and method == "GET":
            return self._send(200, _json(app.activity(user)))

        if path == "/api/scopes":
            if method == "GET":
                return self._send(200, _json(st.visible_scopes(user)))
            if method == "POST":
                return self._send(200, _json(st.save_scope(user, self._body())))
        m = re.fullmatch(r"/api/scopes/(\d+)", path)
        if m and method == "PUT":
            return self._send(200, _json(st.save_scope(user, self._body(), int(m.group(1)))))
        if m and method == "DELETE":
            st.delete_scope(user, int(m.group(1)))
            return self._send(200, _json({"ok": True}))

        if path == "/api/credentials":
            if not user.super_admin:
                raise Forbidden()
            if method == "GET":
                with st.lock:
                    used = {}
                    for s in st.all_sources("smb"):
                        used[s["credential"] or store_mod.DEFAULT_CREDENTIALS] = \
                            used.get(s["credential"] or store_mod.DEFAULT_CREDENTIALS, 0) + 1
                    creds = st.credentials()
                for c in creds:
                    c["sources"] = used.get(c["name"], 0)
                return self._send(200, _json({"profiles": creds, "default_sources": used.get("default", 0),
                                              "default": st.settings("smb").get("default_credentials")}))
            if method == "POST":
                return self._send(200, _json(st.save_credential(user, self._body())))
        m = re.fullmatch(r"/api/credentials/(\d+)", path)
        if m and method == "PUT":
            return self._send(200, _json(st.save_credential(user, self._body(), int(m.group(1)))))
        if m and method == "DELETE":
            st.delete_credential(user, int(m.group(1)))
            return self._send(200, _json({"ok": True}))

        m = re.fullmatch(r"/api/settings/(\w+)", path)
        if m:
            if not user.super_admin:
                raise Forbidden()
            kind = m.group(1)
            if kind not in KINDS:
                raise NotFound("no such source type")
            if method == "GET":
                data = st.settings(kind)
                return self._send(200, _json({"yaml": store_mod._dump_yaml(data) if data else ""}))
            if method == "PUT":
                st.save_settings(user, kind, str(self._body().get("yaml") or ""))
                return self._send(200, _json({"ok": True}))

        if path == "/api/audit" and method == "GET":
            before = (qs.get("before") or [None])[0]
            return self._send(200, _json(st.audit_entries(user, 200, before)))

        return self._error(404, "not found")


def main():
    _check_config()
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    defaults = {}
    for key, env in (("crawl_minutes", "DEFAULT_CRAWL_MINUTES"), ("acl_minutes", "DEFAULT_ACL_MINUTES")):
        if os.environ.get(env):
            defaults[key] = int(os.environ[env])
    st = store_mod.Store(DB_PATH, SUPER_ADMIN_GROUPS, defaults)
    st.on_change = lambda: write_exports(st)
    import_existing(st)
    write_exports(st)
    storage = None
    if OS_HOST:
        storage = Storage.from_env(STORAGE_HISTORY_PATH)
        storage.start()
    Handler.app = App(st, _make_ldap(), storage)
    server = http.server.ThreadingHTTPServer(("", PORT), Handler)
    server.daemon_threads = True
    who = Handler.app.ldap.describe() if Handler.app.ldap else "the break-glass account only"
    print(f"pelican-admin {VERSION} on port {PORT}; sign-in through {who}; super admins: {', '.join(SUPER_ADMIN_GROUPS) or '-'}")
    server.serve_forever()


if __name__ == "__main__":
    main()
