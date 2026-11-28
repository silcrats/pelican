"""
Integration test of the admin portal and a worker, from the host: imported
sources, a connection test, a crawl, adding a source, removing it with
its documents, and index rebuilds (with VECTOR=1: turning vectors off and
on again with other passage settings). Prints one "ok"/"FAIL" line per check; exit status is the
number of failures.

    python3 admin_flow.py <portal URL> <break-glass password>
"""

import http.cookiejar
import json
import os
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

if sys.argv[3:] == ["tidy"]:
    # run.sh has left an index as a rebuild whose worker stopped would.
    def wait(job_id, seconds=300):
        deadline = time.time() + seconds
        while time.time() < deadline:
            job = call("GET", f"/api/index/jobs/{job_id}")[1]
            if job.get("status") in ("done", "failed", "cancelled"):
                return job
            time.sleep(2)
        return job
    _, idx = call("GET", "/api/index")
    state = idx.get("state") or {}
    check("index page spots what an unfinished rebuild left", state.get("leftovers") == ["documents-9"]
          and idx.get("previous") != "documents-9", state.get("leftovers"))
    _, job = call("POST", "/api/index/jobs", {"action": "tidy"})
    job = wait(job["id"]) if job and "id" in job else {"status": str(job)}
    _, idx = call("GET", "/api/index")
    names = sorted(i["name"] for i in idx.get("state", {}).get("indexes", []))
    live_name = next((i["name"] for i in idx.get("state", {}).get("indexes", []) if i["live"]), None)
    check("tidy up removes it and leaves search alone", job.get("status") == "done" and names == ["documents-3"]
          and live_name == "documents-3", f"{names} {job.get('status')}: {(job.get('log') or '')[-800:]}")
    sys.exit(failures)

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
# No directory here: the Access page says it needs a lookup account rather than failing.
_, access = call("GET", "/api/access")
status, err = call("GET", "/api/access?user=pelican-test")
check("access page asks for a lookup account when none is set",
      access == {"lookup": False, "counts": True} and status == 400 and "LDAP_LOOKUP_USER" in (err or {}).get("error", ""),
      f"{access} {status} {err}")

# ------------------------------------------------------------------ index

def wait_index_job(job_id, seconds=900):
    deadline = time.time() + seconds
    while time.time() < deadline:
        _, job = call("GET", f"/api/index/jobs/{job_id}")
        if job and job.get("status") in ("done", "failed", "cancelled"):
            return job
        time.sleep(2)
    return call("GET", f"/api/index/jobs/{job_id}")[1]


def index_job(action):
    status, job = call("POST", "/api/index/jobs", {"action": action})
    if status != 200:
        return {"status": "not queued", "summary": str(job)}
    return wait_index_job(job["id"])


def live(d):
    return next((i for i in d.get("state", {}).get("indexes", []) if i["live"]), {})


def described(job):
    return f"{job.get('status')}: {job.get('summary')}\n{(job.get('log') or '')[-1500:]}"


vector = os.environ.get("VECTOR") == "1"
_, idx = call("GET", "/api/index")
start = live(idx)
check("index page reads the plain index", idx.get("state", {}).get("plain") and start.get("name") == "documents"
      and start.get("docs", 0) > 0 and start.get("vectors") == vector, idx.get("state") or idx)
docs = start.get("docs") or -1

if vector:
    call("PUT", "/api/index/settings", {"enabled": True, "embeddings_url": "http://embeddings/embed"})
    job = index_job("check")
    check("check server embeds through OpenSearch", job.get("status") == "done"
          and "768-dimension" in (job.get("summary") or ""), described(job))

# 1: rebuild without vectors (with VECTOR=1, that turns them off). A crawl
# asked for meanwhile waits for it.
call("PUT", "/api/index/settings", {"enabled": False})
status, rebuild = call("POST", "/api/index/jobs", {"action": "rebuild"})
status2, crawl = call("POST", f"/api/sources/{fin['id']}/jobs", {"type": "crawl"})
rebuild = wait_index_job(rebuild["id"]) if status == 200 else {"status": str(rebuild)}
check("rebuild of a plain index", rebuild.get("status") == "done", described(rebuild))
crawl = wait_job(fin["id"], crawl["id"]) if status2 == 200 else {"status": str(crawl)}
check("a crawl asked for during the rebuild waits for it, then works through the alias",
      crawl.get("status") == "done" and (crawl.get("started_at") or 0) >= (rebuild.get("finished_at") or 1e12)
      and "0 documents indexed" in (crawl.get("log") or ""), f"{crawl.get('status')} {crawl.get('started_at')} "
      f"{rebuild.get('finished_at')}\n{(crawl.get('log') or '')[-600:]}")
_, idx = call("GET", "/api/index")
now = live(idx)
check("search uses documents-2, the plain index is kept as documents-1",
      not idx.get("state", {}).get("plain", True) and now.get("name") == "documents-2" and now.get("docs") == docs
      and not now.get("vectors") and idx.get("previous") == "documents-1", idx.get("state"))
check("no switching back once a crawl has written to the new index",
      not idx.get("switch_back") and call("POST", "/api/index/jobs", {"action": "switch_back"})[0] == 400,
      idx.get("switch_back_why"))

# 2: rebuild again (with VECTOR=1: vectors back on, with shorter passages).
if vector:
    call("PUT", "/api/index/settings", {"enabled": True, "chunk_words": 150, "chunk_overlap": 0.2, "max_chunks": 40})
job = index_job("rebuild")
check("second rebuild" + (", with vectors" if vector else ""), job.get("status") == "done", described(job))
_, idx = call("GET", "/api/index")
now = live(idx)
names = sorted(i["name"] for i in idx.get("state", {}).get("indexes", []))
check("documents-3 is live, documents-2 kept, the older documents-1 deleted",
      now.get("name") == "documents-3" and now.get("docs") == docs and names == ["documents-2", "documents-3"],
      names)
if vector:
    meta = now.get("meta") or {}
    check("vectors made with the portal's settings",
          now.get("vectors") and now.get("dimension") == 768 and meta.get("chunk_words") == 150
          and meta.get("max_chunks") == 40 and 0 < (idx.get("state", {}).get("with_vectors") or 0) <= docs, now)

job = index_job("switch_back")
_, idx = call("GET", "/api/index")
check("switch back to the previous index", job.get("status") == "done" and live(idx).get("name") == "documents-2"
      and idx.get("previous") == "documents-3", described(job))
job = index_job("switch_back")
_, idx = call("GET", "/api/index")
check("and forward again", job.get("status") == "done" and live(idx).get("name") == "documents-3", described(job))
job = index_job("drop_previous")
_, idx = call("GET", "/api/index")
names = sorted(i["name"] for i in idx.get("state", {}).get("indexes", []))
check("delete the previous index", job.get("status") == "done" and names == ["documents-3"]
      and not idx.get("previous"), f"{names}\n{described(job)}")
job = run(fin, "crawl")
check("crawl after the rebuilds", job.get("status") == "done" and "0 documents indexed" in (job.get("log") or ""),
      f"{job.get('summary')}\n{(job.get('log') or '')[-800:]}")

_, activity = call("GET", "/api/activity")
check("worker listed", any(w["name"] == "itest-worker" for w in activity.get("workers", [])), activity.get("workers"))
sys.exit(failures)
