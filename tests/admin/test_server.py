"""HTTP-level tests for the admin portal (admin/admin_server.py) and the
worker (run_worker.py) talking to it, with a fake directory.

    python -m unittest discover tests/admin
"""

import http.client
import json
import os
import sys
import tempfile
import threading
import time
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
TMP = tempfile.mkdtemp(prefix="pelican-admin-test-")
os.makedirs(os.path.join(TMP, "export"))
os.environ.update({
    "WORKER_TOKEN": "w" * 40,
    "ADMIN_BREAKGLASS_PASSWORD": "Break-Glass-Test-Pw-1",
    "SUPER_ADMIN_GROUPS": "Pelican Admins",
    "ADMIN_EXPORT_DIR": os.path.join(TMP, "export"),
    "ADMIN_IMPORT_DIR": os.path.join(TMP, "import"),
})
os.environ.pop("OS_HOST", None)
sys.path.insert(0, os.path.join(ROOT, "admin"))
sys.path.insert(0, ROOT)
import admin_server  # noqa: E402
import store as S  # noqa: E402
from ldap_auth import SignInFailed, cn_from_dn, primary_group_sid  # noqa: E402

admin_server.FAILED_SIGN_IN_DELAY_SECONDS = 0

DIRECTORY = {
    "alice": ("alice-pw", ["Finance IT", "Domain Users"]),
    "root": ("root-pw", ["Pelican Admins"]),
    "dave": ("dave-pw", ["Domain Users"]),
}


# Accounts the Access page can look up: groups as Frogmouth counts them,
# nested-only groups, disabled flag.
LOOKUP = {
    "erin": (["Finance", "Domain Users"], ["All Staff"], False),
    "olduser": (["Domain Users"], [], True),
}


class FakeLdap:
    lookup_ok = True

    def authenticate(self, username, password):
        entry = DIRECTORY.get(username)
        if not entry or entry[0] != password:
            raise SignInFailed("invalid credentials")
        return username, entry[1], username.title()

    def can_look_up(self):
        return True

    def lookup(self, username):
        from ldap_auth import LookupFailed
        if not FakeLdap.lookup_ok:
            raise LookupFailed("directory unavailable: timed out")
        key = username.lower()
        if key not in LOOKUP:
            return None
        groups, nested, disabled = LOOKUP[key]
        return {"username": key, "display_name": key.title(), "groups": groups, "nested_groups": nested,
                "disabled": disabled}

    def describe(self):
        return "fake directory"


class Client:
    def __init__(self, port):
        self.port = port
        self.cookie = None

    def request(self, method, path, body=None, headers=None, csrf=True):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"Host": f"127.0.0.1:{self.port}"}
        if csrf and method != "GET":
            h["X-Pelican-Admin"] = "1"
        if self.cookie:
            h["Cookie"] = self.cookie
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        h.update(headers or {})
        conn.request(method, path, body=data, headers=h)
        res = conn.getresponse()
        raw = res.read()
        set_cookie = res.getheader("Set-Cookie")
        if set_cookie:
            self.cookie = set_cookie.split(";")[0]
        conn.close()
        try:
            payload = json.loads(raw) if raw else None
        except ValueError:
            payload = raw
        return res.status, payload, res

    def login(self, user, password):
        return self.request("POST", "/api/login", {"username": user, "password": password})


class ServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.st = S.Store(os.path.join(TMP, "admin.db"), ["Pelican Admins"])
        cls.st.on_change = lambda: admin_server.write_exports(cls.st)
        admin_server.Handler.app = admin_server.App(cls.st, FakeLdap())
        cls.server = admin_server.http.server.ThreadingHTTPServer(("127.0.0.1", 0), admin_server.Handler)
        cls.server.daemon_threads = True
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        admin = cls.st.user("root", ["Pelican Admins"])
        cls.scope = cls.st.save_scope(admin, {
            "name": "Finance", "groups": ["Finance IT"], "kinds": ["smb"], "smb_servers": ["files1.example.local"],
            "credentials": ["default"]})
        cls.secret = cls.st.save_source(admin, {"kind": "smb", "name": "hr-secret", "crawl_minutes": 0,
                                                "acl_minutes": 0,
                                                "config": {"server": "files9.example.local", "share": "hr"}})

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.st.db.close()

    def clear_queue(self):
        """Worker tests take the next queued job; make sure it's theirs."""
        with self.st.lock:
            self.st.db.execute("UPDATE jobs SET status='cancelled' WHERE status='queued'")
            self.st.db.commit()

    def client(self, user=None):
        c = Client(self.port)
        if user:
            status, _, _ = c.login(user, DIRECTORY[user][0])
            self.assertEqual(status, 200)
        return c

    # ---------------------------------------------------------- sign-in

    def test_sign_in_rules(self):
        c = Client(self.port)
        self.assertEqual(c.request("GET", "/api/me")[0], 401)
        self.assertEqual(c.login("alice", "wrong")[0], 401)
        self.assertEqual(c.login("dave", "dave-pw")[0], 401)   # in the directory, no admin access
        status, me, res = c.login("alice", "alice-pw")
        self.assertEqual(status, 200)
        self.assertFalse(me["super_admin"])
        self.assertEqual(me["kinds"], ["smb"])
        cookie = res.getheader("Set-Cookie")
        for flag in ("HttpOnly", "SameSite=Strict", "Path=/"):
            self.assertIn(flag, cookie)
        self.assertEqual(c.request("GET", "/api/me")[1]["username"], "alice")
        self.assertEqual(c.request("POST", "/api/logout")[0], 200)
        self.assertEqual(c.request("GET", "/api/me")[0], 401)

    def test_break_glass_account(self):
        c = Client(self.port)
        self.assertEqual(c.login("pelican-admin", "nope")[0], 401)
        status, me, _ = c.login("pelican-admin", "Break-Glass-Test-Pw-1")
        self.assertEqual(status, 200)
        self.assertTrue(me["super_admin"])

    def test_mutations_need_csrf_header_and_same_origin(self):
        c = self.client("root")
        body = {"kind": "smb", "name": "x1", "config": {"server": "a.example", "share": "s"}}
        self.assertEqual(c.request("POST", "/api/sources", body, csrf=False)[0], 403)
        self.assertEqual(c.request("POST", "/api/sources", body, headers={"Origin": "https://evil.example"})[0], 403)
        self.assertEqual(c.request("POST", "/api/login", {"username": "root", "password": "root-pw"},
                                   csrf=False)[0], 403)
        status, src, _ = c.request("POST", "/api/sources", body, headers={"Origin": f"http://127.0.0.1:{self.port}"})
        self.assertEqual(status, 200, src)
        self.assertEqual(c.request("DELETE", f"/api/sources/{src['id']}", {"confirm": "x1"})[0], 200)

    # --------------------------------------------------------- delegation

    def test_scoped_admin_sees_and_changes_only_their_sources(self):
        c = self.client("alice")
        names = [s["name"] for s in c.request("GET", "/api/sources")[1]]
        self.assertNotIn("hr-secret", names)
        for method, path, body in (("GET", f"/api/sources/{self.secret['id']}", None),
                                   ("PUT", f"/api/sources/{self.secret['id']}", {"config": {}}),
                                   ("POST", f"/api/sources/{self.secret['id']}/jobs", {"type": "crawl"}),
                                   ("DELETE", f"/api/sources/{self.secret['id']}", {"confirm": "hr-secret"})):
            self.assertEqual(c.request(method, path, body)[0], 404, path)
        self.assertEqual(c.request("GET", "/api/credentials")[0], 403)
        self.assertEqual(c.request("GET", "/api/settings/smb")[0], 403)
        self.assertEqual(c.request("POST", "/api/scopes", {"name": "x", "groups": ["Finance IT"]})[0], 403)
        status, err, _ = c.request("POST", "/api/sources", {
            "kind": "smb", "name": "fin-x", "scope_id": self.scope["id"],
            "config": {"server": "files9.example.local", "share": "hr"}})
        self.assertEqual(status, 400)
        self.assertIn("can't crawl server", err["error"])
        status, src, _ = c.request("POST", "/api/sources", {
            "kind": "smb", "name": "fin-ok", "scope_id": self.scope["id"], "crawl_minutes": 0, "acl_minutes": 0,
            "config": {"server": "files1.example.local", "share": "data", "path": "Finance"}})
        self.assertEqual(status, 200, src)
        detail = c.request("GET", f"/api/sources/{src['id']}")[1]
        self.assertIn("name: fin-ok", detail["rendered"])

    def test_exports_written(self):
        with open(os.path.join(TMP, "export", "shares.yaml")) as f:
            text = f.read()
        self.assertIn("hr-secret", text)
        self.assertTrue(text.startswith("# Written by the Pelican admin portal"))
        self.assertEqual(os.stat(os.path.join(TMP, "export", "shares.yaml")).st_mode & 0o777, 0o644)

    # ----------------------------------------------------------- storage

    def test_storage_figures_by_who_is_asking(self):
        root = self.client("root")
        src = root.request("POST", "/api/sources", {
            "kind": "smb", "name": "fin-storage", "scope_id": self.scope["id"], "crawl_minutes": 0, "acl_minutes": 0,
            "config": {"server": "files1.example.local", "share": "data", "path": "Storage"}})[1]

        def row(name, host, docs):
            return {"name": name, "host": host, "docs": docs, "raw_bytes": 1, "measured_pct": 100,
                    "avg_doc_bytes": 1, "est_index_bytes": docs * 10, "pct": 1.0}

        class FakeStorage:
            refreshed = 0

            def snapshot(self):
                return {"updated": time.time(), "error": "RuntimeError: OpenSearch 503 on /_nodes/stats/fs", "data": {
                    "index": "documents", "index_bytes": 999, "docs": 60, "deleted_docs": 0, "disk_total": 10,
                    "disk_free": 5, "sample_docs": 100,
                    "growth": {"window_days": 2, "index_bytes_per_day": 1, "docs_per_day_by_source": {"fin-storage": 4}},
                    "sources": [row("hr-secret", "smb-share", 30), row("fin-storage", "smb-share", 20),
                                row("fin-storage", "exchange-online", 5),   # same name, other type: not this source
                                row("leftover", "smb-share", 5)]}}

            def refresh_soon(self):
                FakeStorage.refreshed += 1

        app = admin_server.Handler.app
        app.storage, app.storage_refreshed = FakeStorage(), 0
        try:
            full = root.request("GET", "/api/storage")[1]
            self.assertEqual(full["index_bytes"], 999)
            self.assertIn("503", full["error"])
            by = {(r["name"], r["host"]): r for r in full["sources"]}
            self.assertEqual(by[("fin-storage", "smb-share")]["source_id"], src["id"])
            self.assertEqual(by[("fin-storage", "smb-share")]["docs_per_day"], 4)
            self.assertIsNone(by[("fin-storage", "exchange-online")]["source_id"])
            self.assertIsNone(by[("leftover", "smb-share")]["source_id"])

            alice = self.client("alice")
            scoped = alice.request("GET", "/api/storage")[1]
            self.assertEqual([r["name"] for r in scoped["sources"]], ["fin-storage"])
            self.assertEqual(scoped["sources"][0]["host"], "smb-share")
            for key in ("index_bytes", "disk_free", "growth", "docs"):
                self.assertNotIn(key, scoped)
            self.assertNotIn("503", scoped["error"])   # no cluster details

            detail = alice.request("GET", f"/api/sources/{src['id']}")[1]
            self.assertEqual(detail["storage"]["docs"], 20)
            self.assertTrue(detail["storage_available"])

            self.assertEqual(alice.request("POST", "/api/storage/refresh")[0], 403)
            self.assertEqual(root.request("POST", "/api/storage/refresh")[0], 200)
            self.assertEqual(root.request("POST", "/api/storage/refresh")[0], 400)   # once a minute
            self.assertEqual(FakeStorage.refreshed, 1)
        finally:
            app.storage = None
        self.assertEqual(root.request("GET", "/api/storage")[1], {"available": False})

    # ------------------------------------------------------------ static

    def test_access_check(self):
        root = self.client("root")
        fin = root.request("POST", "/api/sources", {
            "kind": "smb", "name": "fin-access", "scope_id": self.scope["id"], "crawl_minutes": 0, "acl_minutes": 0,
            "config": {"server": "files1.example.local", "share": "data", "path": "Access"}})[1]
        asked = []

        def fake_search(path, body):
            asked.append(body)
            roles = next((f["terms"]["role"] for f in body["query"].get("bool", {}).get("filter", [])), None)

            def bucket(share, host, n, granted=None):
                hb = {"key": host, "doc_count": n}
                if granted is not None:
                    hb["granted"] = {"buckets": [{"key": k, "doc_count": v} for k, v in granted.items()]}
                return {"key": share, "doc_count": n, "host": {"buckets": [hb]}}
            if roles is None:
                buckets = [bucket("fin-access", "smb-share", 10), bucket("hr-secret", "smb-share", 7),
                           bucket("legacy", "smb-share", 4)]
            else:
                buckets = [bucket("fin-access", "smb-share", 6, {"2Finance": 5, "1erin": 2}),
                           bucket("legacy", "smb-share", 1, {"Rguest": 1})]
            return {"aggregations": {"by_share": {"buckets": buckets}}}

        app = admin_server.Handler.app
        app.os_search = fake_search
        try:
            self.assertEqual(root.request("GET", "/api/access")[1], {"lookup": True, "counts": True})
            d = root.request("GET", "/api/access?user=Erin")[1]
            self.assertTrue(d["found"])
            self.assertEqual([r["role"] for r in d["roles"]], ["Rguest", "1erin", "2Finance", "2Domain Users"])
            self.assertEqual(d["nested_groups"], ["All Staff"])
            by = {r["name"]: r for r in d["sources"]}
            self.assertEqual((by["fin-access"]["visible"], by["fin-access"]["total"]), (6, 10))
            self.assertEqual(by["fin-access"]["by_role"], {"2Finance": 5, "1erin": 2})
            self.assertEqual((by["hr-secret"]["visible"], by["hr-secret"]["total"]), (0, 7))
            self.assertEqual(d["outside"], {"sources": 1, "total": 4, "visible": 1})
            self.assertEqual(asked[-1]["query"]["bool"]["filter"][0]["terms"]["role"],
                             ["Rguest", "1erin", "2Finance", "2Domain Users"])

            # A scoped admin: only their scope's sources, nothing about the rest of the index.
            alice = self.client("alice")
            scoped = alice.request("GET", "/api/access?user=erin")[1]
            self.assertEqual([r["name"] for r in scoped["sources"]], ["fin-access"])
            self.assertIsNone(scoped["outside"])

            self.assertTrue(root.request("GET", "/api/access?user=olduser")[1]["disabled"])
            self.assertEqual(root.request("GET", "/api/access?user=nobody")[1]["found"], False)
            audit = [e for e in root.request("GET", "/api/audit")[1] if e["action"] == "check access"]
            self.assertEqual([e["target"] for e in audit[:4]], ["nobody", "olduser", "erin", "Erin"])

            FakeLdap.lookup_ok = False
            status, err, _ = root.request("GET", "/api/access?user=erin")
            self.assertEqual(status, 400)
            self.assertIn("directory", err["error"])
            FakeLdap.lookup_ok = True

            app.os_search = None
            d = root.request("GET", "/api/access?user=erin")[1]
            self.assertFalse(d["counts"])
            self.assertEqual(d["sources"], [])
            self.assertEqual(Client(self.port).request("GET", "/api/access?user=erin")[0], 401)
        finally:
            FakeLdap.lookup_ok = True
            app.os_search = None
            root.request("DELETE", f"/api/sources/{fin['id']}", {"confirm": "fin-access"})

    def test_access_check_without_lookup_account(self):
        app = admin_server.Handler.app
        saved = app.ldap
        app.ldap = type("NoLookup", (), {"authenticate": FakeLdap.authenticate, "can_look_up": lambda self: False,
                                         "describe": lambda self: "x"})()
        try:
            root = self.client("root")
            self.assertEqual(root.request("GET", "/api/access")[1]["lookup"], False)
            status, err, _ = root.request("GET", "/api/access?user=erin")
            self.assertEqual(status, 400)
            self.assertIn("LDAP_LOOKUP_USER", err["error"])
        finally:
            app.ldap = saved

    def test_static_and_headers(self):
        c = Client(self.port)
        status, body, res = c.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"Pelican Admin", body)
        csp = res.getheader("Content-Security-Policy")
        self.assertIn("default-src 'self'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertEqual(res.getheader("X-Content-Type-Options"), "nosniff")
        self.assertEqual(c.request("GET", "/static/app.js")[2].getheader("Content-Type"),
                         "text/javascript; charset=utf-8")
        for path in ("/static/../store.py", "/static/%2e%2e/store.py", "/static/..%2fstore.py"):
            status, body, _ = c.request("GET", path)
            self.assertNotIn(b"Store", body if isinstance(body, bytes) else b"", path)
        self.assertEqual(c.request("GET", "/healthz")[0], 200)

    def test_help_page(self):
        import re as _re
        status, body, res = Client(self.port).request("GET", "/static/help.html")
        self.assertEqual(status, 200)
        text = body.decode()
        targets = _re.findall(r'data-target="([^"]+)"', text)
        sections = _re.findall(r'<section id="([^"]+)"', text)
        self.assertEqual(targets, sections)   # every contents entry has its section, in order
        for page in ("Sources", "Activity", "Storage", "Scopes", "Credentials", "Settings", "Audit log"):
            self.assertIn(page, text)   # each page of the portal is covered
        self.assertNotIn("<script", text)

    # ------------------------------------------------------------ worker

    def test_jobs_at_once_set_in_the_portal(self):
        root, alice = self.client("root"), self.client("alice")
        self.assertEqual(alice.request("PUT", "/api/workers/default", {"slots": 3})[0], 403)
        self.assertEqual(root.request("PUT", "/api/workers/default", {"slots": 99})[0], 400)
        self.assertEqual(root.request("PUT", "/api/workers/default", {"slots": 3})[0], 200)
        token = {"Authorization": "Bearer " + "w" * 40}
        c = Client(self.port)
        reply = c.request("POST", "/api/worker/claim", {"worker": "lab-worker-7", "running": 3}, csrf=False,
                          headers=token)[1]
        self.assertEqual((reply["job"], reply["slots"]), (None, 3))
        self.assertEqual(root.request("PUT", "/api/workers/lab-worker-7", {"slots": 5})[1], {"slots": 5})
        reply = c.request("POST", "/api/worker/claim", {"worker": "lab-worker-7", "running": 3}, csrf=False,
                          headers=token)[1]
        self.assertEqual(reply["slots"], 5)
        workers = {w["name"]: w for w in root.request("GET", "/api/activity")[1]["workers"]}
        self.assertTrue(workers["lab-worker-7"]["own_slots"])
        self.assertEqual(root.request("PUT", "/api/workers/lab-worker-7", {"slots": None})[1], {"slots": 3})
        self.assertEqual(alice.request("GET", "/api/activity")[1]["workers"], [])
        root.request("PUT", "/api/workers/default", {"slots": 2})

    def test_worker_api_needs_token(self):
        c = Client(self.port)
        self.assertEqual(c.request("POST", "/api/worker/claim", {"worker": "w"}, csrf=False)[0], 401)
        self.assertEqual(c.request("POST", "/api/worker/claim", {"worker": "w"}, csrf=False,
                                   headers={"Authorization": "Bearer " + "x" * 40})[0], 401)

    def test_worker_runs_jobs_end_to_end(self):
        os.environ["ADMIN_URL"] = f"http://127.0.0.1:{self.port}"
        import importlib
        import run_worker
        importlib.reload(run_worker)
        self.clear_queue()
        root = self.client("root")
        status, src, _ = root.request("POST", "/api/sources", {
            "kind": "smb", "name": "worker-e2e", "crawl_minutes": 0, "acl_minutes": 0,
            "config": {"server": "files1.example.local", "share": "data"}})
        self.assertEqual(status, 200, src)
        root.request("POST", f"/api/sources/{src['id']}/jobs", {"type": "test"})
        # The stub prints what a job gets, instead of running check_source.py.
        stub = ("import os,sys; print('names', os.environ['SHARE_NAMES']); "
                "print('config has', open(os.environ['SHARES_CONFIG']).read().count('worker-e2e'));"
                "print('token' if 'WORKER_TOKEN' in os.environ else 'no token'); print('OK: stub done')")
        run_worker.Job.command = lambda self: [sys.executable, "-c", stub]
        w = run_worker.Worker()
        self.assertTrue(w._claim())
        for _ in range(100):
            w._reap()
            if not w.jobs:
                break
            time.sleep(0.05)
        w._report()
        job = root.request("GET", f"/api/sources/{src['id']}")[1]["jobs"][0]
        self.assertEqual(job["status"], "done", job)
        self.assertEqual(job["summary"], "OK: stub done")
        self.assertIn("names worker-e2e", job["log"])
        self.assertIn("config has 1", job["log"])
        self.assertIn("no token", job["log"])

    def test_running_job_shows_totals_before_it_ends(self):
        os.environ["ADMIN_URL"] = f"http://127.0.0.1:{self.port}"
        import importlib
        import run_worker
        importlib.reload(run_worker)
        status_dir = tempfile.mkdtemp(prefix="pelican-status-live-")
        run_worker.STATUS_DIR = status_dir
        run_worker.HEARTBEAT_SECONDS = 0
        self.clear_queue()
        root = self.client("root")
        src = root.request("POST", "/api/sources", {
            "kind": "smb", "name": "worker-live", "crawl_minutes": 0, "acl_minutes": 0,
            "config": {"server": "files1.example.local", "share": "data"}})[1]
        job = root.request("POST", f"/api/sources/{src['id']}/jobs", {"type": "crawl"})[1]
        # Writes progress as a crawler does, then keeps running.
        stub = ("import json, os, time; p = os.path.join(%r, 'status-' + os.environ['JOB_NAME'] + '.json'); "
                "json.dump({'shares': {'worker-live': {'indexed': 7, 'skipped_unchanged': 3, 'discovered': 40}}}, open(p, 'w')); "
                "print('crawling', flush=True); time.sleep(30)") % status_dir
        run_worker.Job.command = lambda self: [sys.executable, "-c", stub]
        w = run_worker.Worker()
        self.assertTrue(w._claim())
        deadline = time.time() + 10
        seen = None
        while time.time() < deadline:
            w._heartbeats()
            seen = root.request("GET", f"/api/jobs/{job['id']}")[1]
            if seen.get("summary"):
                break
            time.sleep(0.2)
        self.assertEqual(seen["status"], "running")
        self.assertEqual(seen["summary"], "7 indexed · 3 unchanged · 40 found")
        self.assertIn("crawling", seen["log"])
        for j in w.jobs.values():
            os.killpg(j.proc.pid, 9)
        while w.jobs:
            w._reap()
            time.sleep(0.1)

    def test_worker_stops_cancelled_job(self):
        os.environ["ADMIN_URL"] = f"http://127.0.0.1:{self.port}"
        import importlib
        import run_worker
        importlib.reload(run_worker)
        run_worker.HEARTBEAT_SECONDS = 0
        self.clear_queue()
        root = self.client("root")
        src = root.request("POST", "/api/sources", {
            "kind": "smb", "name": "worker-cancel", "crawl_minutes": 0, "acl_minutes": 0,
            "config": {"server": "files1.example.local", "share": "data"}})[1]
        job = root.request("POST", f"/api/sources/{src['id']}/jobs", {"type": "crawl"})[1]
        run_worker.Job.command = lambda self: [sys.executable, "-c", "import time; print('working', flush=True); time.sleep(60)"]
        w = run_worker.Worker()
        self.assertTrue(w._claim())
        time.sleep(0.3)
        root.request("POST", f"/api/jobs/{job['id']}/cancel")
        deadline = time.time() + 10
        while w.jobs and time.time() < deadline:
            w._heartbeats()
            w._reap()
            time.sleep(0.1)
        w._report()
        self.assertFalse(w.jobs)
        done = root.request("GET", f"/api/jobs/{job['id']}")[1]
        self.assertEqual(done["status"], "cancelled")
        self.assertIn("working", done["log"])


    # ------------------------------------------------------------ index

    def clear_index_jobs(self):
        with self.st.lock:
            self.st.db.execute("UPDATE index_jobs SET status='cancelled' WHERE status IN ('queued','running')")
            self.st.db.commit()

    def test_index_page_is_super_admin_only(self):
        alice = self.client("alice")
        self.assertEqual(alice.request("GET", "/api/index")[0], 403)
        self.assertEqual(alice.request("PUT", "/api/index/settings", {"enabled": True})[0], 403)
        self.assertEqual(alice.request("POST", "/api/index/jobs", {"action": "check"})[0], 403)

    def test_index_page_without_opensearch(self):
        self.clear_index_jobs()
        root = self.client("root")
        status, d, _ = root.request("GET", "/api/index")
        self.assertEqual(status, 200, d)
        self.assertIn("OS_HOST", d["state_error"])
        self.assertEqual(d["settings"]["model"], "BAAI/bge-base-en-v1.5")
        status, err, _ = root.request("POST", "/api/index/jobs", {"action": "rebuild"})
        self.assertEqual(status, 400)
        self.assertIn("OS_HOST", err["error"])
        status, saved, _ = root.request("PUT", "/api/index/settings", {"enabled": True, "chunk_words": 120})
        self.assertEqual((status, saved["chunk_words"]), (200, 120))
        self.assertEqual(root.request("PUT", "/api/index/settings", {"embeddings_url": "ftp://x"})[0], 400)
        status, job, _ = root.request("POST", "/api/index/jobs", {"action": "check"})   # needs no OpenSearch here
        self.assertEqual((status, job["op"]["vectors"]["chunk_words"]), (200, 120))
        self.assertEqual(root.request("POST", f"/api/index/jobs/{job['id']}/cancel")[1]["status"], "cancelled")

    def test_index_state_and_choices(self):
        def fake(responses):
            def get(path):
                for prefix, reply in responses.items():
                    if path.startswith(prefix):
                        return reply
                return None
            return get
        vec = {"properties": {"content": {"type": "text"},
                              "content_embedding": {"type": "nested", "properties": {"knn": {"dimension": 768}}}}}
        plain = admin_server.index_state(fake({
            "/documents/_alias": {"documents": {"aliases": {}}},
            "/documents,documents-*/_mapping": {"documents": {"mappings": vec}},
            "/documents,documents-*/_stats": {"indices": {"documents": {
                "total": {"store": {"size_in_bytes": 999}}}}},
        }), lambda path, body: {"count": 8 if "nested" in json.dumps(body) else 10})
        self.assertEqual((plain["live"], plain["plain"], plain["with_vectors"]), ("documents", True, 8))
        self.assertEqual((plain["indexes"][0]["docs"], plain["indexes"][0]["bytes"]), (10, 999))
        self.assertEqual(plain["indexes"][0]["dimension"], 768)
        app = admin_server.Handler.app
        self.assertFalse(app._index_choices(plain)["switch_back"])

        meta = {**vec, "_meta": {"pelican": {"generation": 2, "model": "m"}}}
        both = admin_server.index_state(fake({
            "/documents/_alias": {"documents-2": {"aliases": {"documents": {}}}},
            "/documents,documents-*/_mapping": {"documents-1": {"mappings": vec}, "documents-2": {"mappings": meta}},
            "/documents,documents-*/_stats": {"indices": {}},
        }), lambda path, body: {"count": 5})
        self.assertEqual([(i["name"], i["live"], i["built"]) for i in both["indexes"]],
                         [("documents-2", True, True), ("documents-1", False, False)])
        self.assertEqual((both["leftovers"], both["blocked"]), ([], False))
        unfinished = {**vec, "_meta": {"pelican": {"generation": 3}}}   # never switched to
        stuck = admin_server.index_state(fake({
            "/documents/_alias": {"documents": {"aliases": {}}},
            "/documents/_settings": {"documents": {"settings": {"index": {"blocks": {"write": "true"}}}}},
            "/documents,documents-*/_mapping": {"documents": {"mappings": vec}, "documents-1": {"mappings": vec},
                                                "documents-2": {"mappings": unfinished}},
            "/documents,documents-*/_stats": {"indices": {}},
        }), lambda path, body: {"count": 1})
        self.assertEqual((stuck["leftovers"], stuck["blocked"]), (["documents-1", "documents-2"], True))
        self.assertIsNone(admin_server.Handler.app._index_choices(stuck)["previous"])
        self.clear_index_jobs()
        with self.st.lock:
            self.st.db.execute("DELETE FROM index_jobs")
            self.st.db.commit()
        choices = app._index_choices(both)
        self.assertEqual(choices["previous"], "documents-1")
        self.assertFalse(choices["switch_back"])   # no switch recorded by this portal
        root_user = self.st.user("root", ["Pelican Admins"])
        job = self.st.request_index_job(root_user, "rebuild")
        self.st.claim("w-index", 0)
        self.st.index_finish("w-index", job["id"], True, 0)
        self.assertTrue(app._index_choices(both)["switch_back"])
        # A crawl after the switch rules switching back out.
        with self.st.lock:
            self.st.db.execute("INSERT INTO jobs (source_id, type, status, created_at, started_at) VALUES (?, 'crawl', 'done', ?, ?)",
                               (self.secret["id"], time.time() + 1, time.time() + 1))
            self.st.db.commit()
        choices = app._index_choices(both)
        self.assertFalse(choices["switch_back"])
        self.assertIn("1 job", choices["switch_back_why"])

    def test_worker_runs_index_job(self):
        os.environ["ADMIN_URL"] = f"http://127.0.0.1:{self.port}"
        os.environ["OS_MAINT_PASSWORD"] = "maint-secret"
        os.environ["OS_PASSWORD"] = "crawler-secret"
        self.addCleanup(os.environ.pop, "OS_MAINT_PASSWORD")
        self.addCleanup(os.environ.pop, "OS_PASSWORD")
        import importlib
        import run_worker
        importlib.reload(run_worker)
        run_worker.STATUS_DIR = tempfile.mkdtemp(prefix="pelican-status-index-")
        self.clear_queue()
        self.clear_index_jobs()
        root = self.client("root")
        job = root.request("POST", "/api/index/jobs", {"action": "check"})[1]
        progress_file = os.path.join(run_worker.STATUS_DIR, "status-index.json")
        stub = ("import json, os; op = json.loads(os.environ['INDEX_OP']); print('action', op['action']); "
                f"json.dump({{'progress': 'asking the server'}}, open({progress_file!r}, 'w')); "
                "print('maint' if os.environ.get('OS_MAINT_PASSWORD') else 'no maint'); "
                "print('crawler' if os.environ.get('OS_PASSWORD') else 'no crawler'); print('checked')")
        run_worker.Job.command = lambda self: [sys.executable, "-c", stub]
        w = run_worker.Worker()
        self.assertTrue(w._claim())
        for _ in range(100):
            w._reap()
            if not w.jobs:
                break
            time.sleep(0.05)
        w._report()
        done = root.request("GET", f"/api/index/jobs/{job['id']}")[1]
        self.assertEqual((done["status"], done["summary"]), ("done", "checked"), done)
        self.assertIn("action check", done["log"])
        self.assertIn("maint", done["log"])
        self.assertIn("no crawler", done["log"])   # index jobs get only the maintainer account

    def test_source_jobs_dont_get_the_maintainer_password(self):
        os.environ["OS_MAINT_PASSWORD"] = "maint-secret"
        self.addCleanup(os.environ.pop, "OS_MAINT_PASSWORD")
        import run_worker
        job = run_worker.Job({"id": 1, "type": "test", "source": {"kind": "smb", "name": "x"}, "config_yaml": "",
                              "config_env": "SHARES_CONFIG", "names_env": "SHARE_NAMES"})
        self.addCleanup(job.cleanup)
        seen = {}
        real = run_worker.subprocess.Popen
        def fake(cmd, env=None, **kw):
            seen.update(env)
            return real([sys.executable, "-c", "pass"], **kw)
        run_worker.subprocess.Popen = fake
        self.addCleanup(setattr, run_worker.subprocess, "Popen", real)
        job.start()
        job.proc.wait()
        job.reader.join()
        self.assertNotIn("OS_MAINT_PASSWORD", seen)


class WorkerProgressTest(unittest.TestCase):
    """Running totals, read from the status file a crawler writes."""

    def setUp(self):
        import run_worker
        self.rw = run_worker
        self.dir = tempfile.mkdtemp(prefix="pelican-status-test-")
        self.old_dir = run_worker.STATUS_DIR
        run_worker.STATUS_DIR = self.dir

    def tearDown(self):
        self.rw.STATUS_DIR = self.old_dir

    def job(self, job_type):
        spec = {"id": 1, "type": job_type, "source": {"kind": "smb", "name": "fin"}, "config_yaml": "",
                "config_env": "SHARES_CONFIG", "names_env": "SHARE_NAMES"}
        job = self.rw.Job(spec)
        self.addCleanup(job.cleanup)
        return job

    def write(self, job_name, share):
        with open(os.path.join(self.dir, f"status-{job_name}.json"), "w") as f:
            json.dump({"shares": {"fin": share}}, f)

    def test_crawl_totals(self):
        job = self.job("crawl")
        self.assertEqual(job.progress(), "")   # nothing written yet
        self.write("smb-fin", {"indexed": 1204, "skipped_unchanged": 18330, "skipped_excluded": 0, "discovered": 19601})
        self.assertEqual(job.progress(), "1,204 indexed · 18,330 unchanged · 19,601 found")
        self.write("smb-fin", {"indexed": 1, "skipped_unchanged": 2, "skipped_excluded": 3, "discovered": 6})
        self.assertEqual(job.progress(), "1 indexed · 2 unchanged · 3 excluded · 6 found")

    def test_index_job_progress(self):
        job = self.rw.Job({"id": 2, "type": "index", "op": {"action": "rebuild"}})
        self.addCleanup(job.cleanup)
        self.assertEqual(job.progress(), "")
        with open(os.path.join(self.dir, "status-index.json"), "w") as f:
            json.dump({"progress": "12,000 of 91,598 documents copied (13%)"}, f)
        self.assertEqual(job.progress(), "12,000 of 91,598 documents copied (13%)")

    def test_acl_totals_and_stale_files(self):
        job = self.job("acl")
        self.write("acl-fin", {"acl_docs_updated": 340, "acl_groups_changed": 12})
        self.assertEqual(job.progress(), "340 documents updated · 12 folders changed")
        path = os.path.join(self.dir, "status-acl-fin.json")
        os.utime(path, (job.started_at - 3600, job.started_at - 3600))   # from an earlier run
        self.assertEqual(job.progress(), "")
        self.assertEqual(self.job("test").progress(), "")


class WorkerNameTest(unittest.TestCase):
    """A worker names itself from Docker's DNS (a reverse lookup of its own address)."""

    def serve_once(self, answer_name):
        import socket
        import struct
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        self.addCleanup(sock.close)

        def reply():
            query, addr = sock.recvfrom(512)
            header = query[:2] + struct.pack(">HHHHH", 0x8180, 1, 1 if answer_name else 0, 0, 0)
            answer = b""
            if answer_name:
                rdata = b"".join(bytes([len(p)]) + p.encode() for p in answer_name.split(".")) + b"\0"
                answer = b"\xc0\x0c" + struct.pack(">HHIH", 12, 1, 600, len(rdata)) + rdata
            sock.sendto(header + query[12:] + answer, addr)
        threading.Thread(target=reply, daemon=True).start()
        return sock.getsockname()

    def test_compose_name(self):
        import run_worker
        self.assertEqual(run_worker._container_name(self.serve_once("lab-worker-2.lab_search")), "lab-worker-2")

    def test_no_answer_or_no_server(self):
        import run_worker
        self.assertIsNone(run_worker._container_name(self.serve_once(None)))
        self.assertIsNone(run_worker._container_name(("127.0.0.1", 9)))   # nothing listening


class LdapHelpersTest(unittest.TestCase):
    def test_cn_from_dn(self):
        self.assertEqual(cn_from_dn("CN=Domain Admins,CN=Users,DC=example,DC=local"), "Domain Admins")
        self.assertEqual(cn_from_dn("CN=Smith\\, John,OU=People,DC=x"), "Smith, John")

    def test_refused_bind_is_a_wrong_password_not_an_outage(self):
        from unittest import mock
        from ldap3.core.exceptions import LDAPInvalidCredentialsResult, LDAPSocketOpenError
        from ldap_auth import LdapAuth, LookupFailed
        auth = LdapAuth("ldap://dc.example.local", "{username}@example.local", "DC=example,DC=local",
                        lookup_user="svc-lookup", lookup_password="pw")
        with mock.patch.object(LdapAuth, "_connect", side_effect=LDAPInvalidCredentialsResult(result=49)):
            with self.assertRaisesRegex(SignInFailed, "invalid credentials"):
                auth.authenticate("alice", "wrong")
            with self.assertRaisesRegex(LookupFailed, "refused"):
                auth.lookup("alice")
        with mock.patch.object(LdapAuth, "_connect", side_effect=LDAPSocketOpenError("no route")):
            with self.assertRaisesRegex(LookupFailed, "unavailable"):
                auth.lookup("alice")

    def test_primary_group_sid(self):
        # S-1-5-21-1-2-3-1104 as AD stores it.
        sid = bytes([1, 5, 0, 0, 0, 0, 0, 5]) + b"".join(n.to_bytes(4, "little") for n in (21, 1, 2, 3, 1104))
        self.assertEqual(primary_group_sid(sid, 513), "S-1-5-21-1-2-3-513")
        self.assertIsNone(primary_group_sid(b"\x01\x05", 513))


if __name__ == "__main__":
    unittest.main()
