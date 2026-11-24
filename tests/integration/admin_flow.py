"""
Integration test of the admin portal and a worker, from the host: imported
sources, a connection test, a crawl, adding a source, and removing it with
its documents. Prints one "ok"/"FAIL" line per check; exit status is the
number of failures.

    python3 admin_flow.py <portal URL> <break-glass password>
"""

import http.cookiejar
import json
import sys
import time
import urllib.error
import urllib.request

BASE, PASSWORD = sys.argv[1].rstrip("/"), sys.argv[2]
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
failures = 0


def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    if method != "GET":
        req.add_header("X-Pelican-Admin", "1")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with opener.open(req, timeout=30) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"null")


def check(label, ok, detail=""):
    global failures
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + (f"\n     {detail}" if detail and not ok else ""))
    failures += 0 if ok else 1
    return ok


def wait_job(source_id, job_id, seconds=300):
    deadline = time.time() + seconds
    while time.time() < deadline:
        _, job = call("GET", f"/api/jobs/{job_id}")
        if job and job.get("status") in ("done", "failed", "cancelled"):
            return job
        time.sleep(2)
    return call("GET", f"/api/jobs/{job_id}")[1]


def run(source, job_type):
    status, job = call("POST", f"/api/sources/{source['id']}/jobs", {"type": job_type})
    if status != 200:
        return {"status": "not queued", "summary": str(job)}
    return wait_job(source["id"], job["id"])


status, _ = call("GET", "/api/sources")
check("portal refuses the API before sign-in", status == 401)
status, me = call("POST", "/api/login", {"username": "pelican-admin", "password": PASSWORD})
check("break-glass sign-in", status == 200 and me.get("super_admin"), me)

_, sources = call("GET", "/api/sources")
by_name = {s["name"]: s for s in sources}
check("shares.yaml imported on first start", {"test-finance", "test-encrypted"} <= set(by_name), sorted(by_name))
enc = by_name.get("test-encrypted", {})
check("imported settings kept (encrypt: true)", enc.get("config", {}).get("encrypt") is True, enc)

fin = by_name["test-finance"]
# Turn off its schedule, so only the jobs this test asks for run.
for s in sources:
    call("PUT", f"/api/sources/{s['id']}", {"config": s["config"], "credential": s["credential"],
                                            "crawl_minutes": 0, "acl_minutes": 0})
job = run(fin, "test")
check("test connection to an imported share", job.get("status") == "done" and job.get("summary", "").startswith("OK"),
      f"{job.get('status')}: {job.get('summary')}\n{(job.get('log') or '')[-800:]}")
job = run(fin, "crawl")
check("crawl run by the worker", job.get("status") == "done", f"{job.get('summary')}\n{(job.get('log') or '')[-1500:]}")
check("crawl used the existing state (nothing re-indexed)", "0 documents indexed" in (job.get("log") or ""),
      (job.get("log") or "")[-600:])
job = run(fin, "acl")
check("ACL sync run by the worker", job.get("status") == "done", f"{job.get('summary')}\n{(job.get('log') or '')[-800:]}")

status, added = call("POST", "/api/sources", {
    "kind": "smb", "name": "test-admin-added", "crawl_minutes": 0, "acl_minutes": 0,
    "config": {"server": "samba", "share": "Shared", "path": "Admin"}})
check("add a source", status == 200, added)
if status == 200:
    job = run(added, "crawl")
    check("new source crawled", job.get("status") == "done" and "2 documents indexed" in (job.get("log") or ""),
          f"{job.get('summary')}\n{(job.get('log') or '')[-800:]}")
    _, count = call("GET", f"/api/sources/{added['id']}/count")
    check("document count for the new source (read-only account)", count.get("count") == 2, count)
    status, err = call("DELETE", f"/api/sources/{added['id']}", {"confirm": "wrong"})
    check("removal needs the name typed", status == 400, err)
    status, _ = call("DELETE", f"/api/sources/{added['id']}", {"confirm": "test-admin-added"})
    check("removal accepted", status == 200)
    deadline = time.time() + 300
    gone = False
    while time.time() < deadline and not gone:
        time.sleep(2)
        _, sources = call("GET", "/api/sources")
        gone = "test-admin-added" not in {s["name"] for s in sources}
    check("removed source disappears once its documents are deleted", gone)
    _, audit = call("GET", "/api/audit")
    actions = [e["action"] for e in audit]
    check("audit log records the add and the removal",
          "source added" in actions and "source removed" in actions, actions[:10])

deadline = time.time() + 120
storage = {}
while time.time() < deadline:
    _, storage = call("GET", "/api/storage")
    if storage.get("updated"):
        break
    time.sleep(2)
fin_row = next((r for r in storage.get("sources", []) if r["name"] == "test-finance"), {})
check("storage figures read with the read-only account", storage.get("available") and not storage.get("error")
      and storage.get("index_bytes", 0) > 0 and fin_row.get("docs", 0) > 0 and fin_row.get("source_id") == fin["id"],
      {k: storage.get(k) for k in ("available", "error", "index_bytes", "updated")})

_, activity = call("GET", "/api/activity")
check("worker listed", any(w["name"] == "itest-worker" for w in activity.get("workers", [])), activity.get("workers"))
sys.exit(failures)
