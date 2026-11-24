"""
Removes a source from the index: deletes every document it wrote and
forgets its crawl state, so adding a source with the same name later
starts from scratch. Run by a worker when someone removes a source in the
admin portal.

    python purge_source.py <smb|exchange|sharepoint> <name>

The source must be in the config file the worker passes (as for its
crawler), so the state can be found by server/share, mailbox or site.
Exit status 0 means the source is gone from the index.
"""

import sys
import time

from pelican import settings, state
from pelican.index import SEARCH_INDEX, client

HOSTS = {"smb": settings.HOST_SMB, "exchange": settings.HOST_EXCHANGE, "sharepoint": settings.HOST_SHAREPOINT}


def delete_documents(kind: str, name: str) -> int:
    query = {"query": {"bool": {"filter": [{"term": {"share": name}}, {"term": {"host": HOSTS[kind]}}]}}}
    if not client.indices.exists(index=SEARCH_INDEX):
        return 0
    task = client.delete_by_query(index=SEARCH_INDEX, body=query, conflicts="proceed", refresh=True,
                                  slices="auto", wait_for_completion=False)["task"]
    deadline = time.time() + 6 * 3600
    while time.time() < deadline:
        resp = client.tasks.get(task_id=task, request_timeout=60)
        if resp.get("completed"):
            if resp.get("error"):
                raise RuntimeError(f"delete failed: {resp['error']}")
            result = resp.get("response") or {}
            if result.get("failures"):
                raise RuntimeError(f"delete had failures: {result['failures'][:3]}")
            deleted = int(result.get("deleted", 0))
            break
        status = (resp.get("task") or {}).get("status") or {}
        print(f"  deleted {status.get('deleted', 0)} of {status.get('total', '?')} so far")
        time.sleep(5)
    else:
        raise RuntimeError("delete still running after 6 hours")
    remaining = client.count(index=SEARCH_INDEX, body=query)["count"]
    if remaining:
        raise RuntimeError(f"{remaining} documents remain; try again")
    return deleted


def _table_exists(db, table: str) -> bool:
    return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is not None


def forget_state(kind: str, name: str) -> int:
    db = state.init_state_db()
    keys: set[str] = set()
    if kind == "smb":
        from pelican import smb_shares
        from pelican.smb_acl import ACL_ROLES_TABLE
        share = next((s for s in smb_shares.config().get("shares") or [] if s["name"] == name), None)
        if share is not None:
            # As crawl_smb.previously_known_urls. A sibling entry for a folder
            # inside this one loses its state too, and re-crawls once in full.
            root = share.get("path", "").replace("\\", "/").strip("/")
            keys |= state.keys_with_prefix(db, smb_shares.smb_url(share, root + "/" if root else ""))
        if _table_exists(db, ACL_ROLES_TABLE):
            db.execute(f"DELETE FROM {ACL_ROLES_TABLE} WHERE source LIKE ? ESCAPE '\\'",
                       (name.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "\x1f%",))
    elif kind == "exchange":
        cfg = settings.load_yaml(settings.config_path("EXCHANGE_CONFIG", "exchange.yaml"))
        mb = next((m for m in cfg.get("mailboxes") or [] if m["name"] == name), None)
        if mb is not None:
            keys |= state.keys_with_prefix(db, f"exchange://{mb['user']}/")
        for table, column in (("exchange_delta", "mailbox"), ("exchange_roles", "mailbox")):
            if _table_exists(db, table):
                db.execute(f"DELETE FROM {table} WHERE {column} = ?", (name,))
    else:
        if _table_exists(db, "sharepoint_delta"):
            for (drive_id,) in db.execute("SELECT drive_id FROM sharepoint_delta WHERE site = ?", (name,)).fetchall():
                keys |= state.keys_with_prefix(db, f"sharepoint://{drive_id}/")
            db.execute("DELETE FROM sharepoint_delta WHERE site = ?", (name,))
        if _table_exists(db, "sharepoint_roles"):
            db.execute("DELETE FROM sharepoint_roles WHERE source = ?", (name,))
    state.forget(db, keys)   # commits the deletes above too
    db.close()
    return len(keys)


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in HOSTS:
        print(__doc__)
        return 2
    kind, name = sys.argv[1:]
    try:
        deleted = delete_documents(kind, name)
        forgotten = forget_state(kind, name)
        print(f"OK: deleted {deleted} documents and forgot {forgotten} crawl state entries")
        return 0
    except Exception as exc:
        print(f"FAILED: {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
