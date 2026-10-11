"""
Access roles: how they're encoded into each document's `role` field, and
keeping that field in step with who should have access.

Encoding (prefixes from config/pelican.yaml) must match what the search UI
builds for a signed-in user -- see the `roles:` block there. User names are
lower-cased: `role` is a case-sensitive keyword field, and the UI lower-cases
the signed-in username the same way.

Crawlers remember the roles they last wrote for each source; when the
computed roles change, every existing document of that source is rewritten
in place (no re-download -- permissions changing doesn't change any content).
"""

import json
import re
import sqlite3
import time

from . import settings

EVERYONE = settings.EVERYONE_ROLE
RESTRICTED = settings.RESTRICTED_ROLE


def user_role(username: str) -> str:
    return f"{settings.PREFIX_USER}{str(username).lower()}"


def group_role(group_name: str) -> str:
    return f"{settings.PREFIX_GROUP}{group_name}"


def named_role(role_name: str) -> str:
    return f"{settings.PREFIX_ROLE}{role_name}"


def cn_from_dn(dn: str | None) -> str | None:
    """'CN=Domain Admins,CN=Users,DC=...' -> 'Domain Admins' -- the same CN
    extraction the search UI applies to a user's AD memberOf."""
    match = re.match(r"CN=([^,]+)", dn or "", re.IGNORECASE)
    return match.group(1) if match else None


def static_roles(entry: dict) -> list[str]:
    """Roles written by hand under a source entry's `permissions:`
    (users / groups / roles lists) in its YAML config."""
    perms = entry.get("permissions") or {}
    roles = [user_role(u) for u in perms.get("users", [])]
    roles += [group_role(g) for g in perms.get("groups", [])]
    roles += [named_role(r) for r in perms.get("roles", [])]
    return roles


def summarize(roles: list[str], limit: int = 10) -> str:
    return ", ".join(roles[:limit]) + (f", ... (+{len(roles) - limit} more)" if len(roles) > limit else "")


# ------------------------------------------------------- last-applied roles

def init_roles_table(db: sqlite3.Connection, table: str) -> None:
    db.execute(f"""
        CREATE TABLE IF NOT EXISTS {table} (
            source TEXT PRIMARY KEY,
            roles TEXT,
            updated_at REAL
        )
    """)
    db.commit()


def get_stored_roles(db: sqlite3.Connection, table: str, source: str) -> list[str] | None:
    row = db.execute(f"SELECT roles FROM {table} WHERE source = ?", (source,)).fetchone()
    return json.loads(row[0]) if row else None


def get_stored_roles_with_age(db: sqlite3.Connection, table: str, source: str) -> tuple[list[str] | None, float | None]:
    """Like get_stored_roles, but also returns updated_at -- how long ago this
    source's roles were last *verified* (see save_stored_roles: every call
    refreshes updated_at, whether or not the roles it saved actually changed).
    Callers doing an expensive live lookup (e.g. an smbcacls call per
    directory, every run) can use the age to skip re-verifying a source
    that was checked recently, rather than always paying that cost."""
    row = db.execute(f"SELECT roles, updated_at FROM {table} WHERE source = ?", (source,)).fetchone()
    return (json.loads(row[0]), row[1]) if row else (None, None)


def list_sources(db: sqlite3.Connection, table: str, prefix: str) -> list[str]:
    """Every stored source key starting with `prefix` (LIKE wildcards escaped)."""
    escaped = prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    rows = db.execute(f"SELECT source FROM {table} WHERE source LIKE ? ESCAPE '\\'", (escaped + "%",)).fetchall()
    return [row[0] for row in rows]


def delete_sources(db: sqlite3.Connection, table: str, sources: list[str]) -> None:
    db.executemany(f"DELETE FROM {table} WHERE source = ?", [(s,) for s in sources])
    db.commit()


def save_stored_roles(db: sqlite3.Connection, table: str, source: str, roles: list[str]) -> None:
    db.execute(
        f"INSERT OR REPLACE INTO {table} (source, roles, updated_at) VALUES (?, ?, ?)",
        (source, json.dumps(roles), time.time()),
    )
    db.commit()


# ------------------------------------------------- rewrite indexed documents

def apply_roles_to_indexed_docs(client, index: str, share_name: str, host: str, roles: list[str],
                                 extra_filters: list[dict] | None = None, on_progress=None) -> int:
    """Rewrite `role` on every already-indexed document of this source (optionally
    narrowed further by extra_filters, e.g. to one directory within an SMB share).

    Runs as a background task inside OpenSearch and is polled, rather than as one
    long HTTP request: a large source takes minutes, and a single request held
    open that long fails.

    A client.tasks.get() call can block indefinitely against a connection that's
    gone silent, past its own timeout. request_timeout below is one layer of
    defense; on_progress is the one that matters -- an optional callback (e.g.
    the process watchdog's heartbeat) invoked on every poll attempt, BEFORE
    calling tasks.get(), so external stall detection has something to measure
    even when that call is the one that's stuck."""
    filters = [{"term": {"share": share_name}}, {"term": {"host": host}}]
    if extra_filters:
        filters += extra_filters
    resp = client.update_by_query(
        index=index,
        body={
            "query": {"bool": {"filter": filters}},
            "script": {"source": "ctx._source.role = params.roles", "lang": "painless", "params": {"roles": roles}},
        },
        conflicts="proceed",
        refresh=True,
        slices="auto",
        wait_for_completion=False,
    )
    task_id = resp["task"]
    deadline = time.time() + 4 * 3600
    last_report = time.time()
    while True:
        if on_progress:
            on_progress(f"polling role update task {task_id} for '{share_name}'")
        task = client.tasks.get(task_id=task_id, request_timeout=30)
        if task.get("completed"):
            break
        if time.time() > deadline:
            raise RuntimeError(f"role update task {task_id} still running after 4h")
        if time.time() - last_report > 30:
            progress = (task.get("task") or {}).get("status") or {}
            print(f"  ... updating roles: {progress.get('updated', 0)}/{progress.get('total', '?')} documents")
            last_report = time.time()
        time.sleep(5)
    if task.get("error"):
        raise RuntimeError(f"role update task failed: {task['error']}")
    result = task.get("response") or {}
    failures = result.get("failures") or []
    if failures:
        raise RuntimeError(f"updating roles failed for {len(failures)} document(s): {failures[0]}")
    return result.get("updated", 0)
