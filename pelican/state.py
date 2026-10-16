"""
Incremental-crawl state, shared by every crawler: a small SQLite file
(persisted on a Docker volume) recording each item's last-modified time, so
unchanged items are skipped entirely on repeat runs -- no download, no
extraction, no OpenSearch write.

The table/column names (file_state.smb_url) predate the non-SMB crawlers and
are kept as-is so existing state databases carry over; for mail and
SharePoint the "url" is their stable ID-based key.
"""

import os
import sqlite3
import time

from . import settings


def init_state_db(path: str | None = None) -> sqlite3.Connection:
    path = path or settings.STATE_DB_PATH
    os.makedirs(os.path.dirname(path), exist_ok=True)
    # An SMB crawler's ACL-sync container opens this same file from a second
    # process: WAL lets readers proceed during a write, and the timeout makes a
    # brief writer collision wait instead of raising "database is locked".
    db = sqlite3.connect(path, timeout=30)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("""
        CREATE TABLE IF NOT EXISTS file_state (
            smb_url TEXT PRIMARY KEY,
            last_modified REAL,
            indexed_at REAL
        )
    """)
    # When this database first saw each extraction revision (see
    # extraction_cutoffs).
    db.execute("CREATE TABLE IF NOT EXISTS extraction_revisions (revision TEXT PRIMARY KEY, first_seen REAL)")
    db.commit()
    return db


def extraction_cutoffs(db: sqlite3.Connection, revisions: dict[str, set[str]]) -> tuple[dict[str, float], bool]:
    """For each extension an extraction revision covers, the time this
    database first saw that revision: an item of that type indexed earlier
    was extracted by the old code and is re-extracted once (pass the cutoff
    to is_unchanged). Also returns whether any revision is new this run.
    `revisions` maps a revision name to its extensions; see
    extract_text.EXTRACTION_REVISIONS."""
    now = time.time()
    cutoffs: dict[str, float] = {}
    new = False
    for revision, extensions in revisions.items():
        row = db.execute("SELECT first_seen FROM extraction_revisions WHERE revision = ?", (revision,)).fetchone()
        if row is None:
            db.execute("INSERT INTO extraction_revisions (revision, first_seen) VALUES (?, ?)", (revision, now))
            first_seen, new = now, True
        else:
            first_seen = row[0]
        for ext in extensions:
            cutoffs[ext] = max(cutoffs.get(ext, 0.0), first_seen)
    db.commit()
    return cutoffs, new


def is_unchanged(db: sqlite3.Connection, key: str, mtime: float, reextract_before: float | None = None) -> bool:
    """Same modification time as when last indexed -- and, given
    reextract_before (an extraction cutoff), indexed no earlier than that."""
    row = db.execute("SELECT last_modified, indexed_at FROM file_state WHERE smb_url = ?", (key,)).fetchone()
    if row is None or row[0] != mtime:
        return False
    return reextract_before is None or (row[1] or 0) >= reextract_before


def record_indexed(db: sqlite3.Connection, key: str, mtime: float) -> None:
    db.execute(
        "INSERT OR REPLACE INTO file_state (smb_url, last_modified, indexed_at) VALUES (?, ?, ?)",
        (key, mtime, time.time()),
    )


def forget(db: sqlite3.Connection, keys) -> None:
    db.executemany("DELETE FROM file_state WHERE smb_url = ?", [(k,) for k in keys])
    db.commit()


def keys_with_prefix(db: sqlite3.Connection, prefix: str) -> set[str]:
    """Every recorded key starting with `prefix` (LIKE wildcards escaped)."""
    escaped = prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    rows = db.execute(
        "SELECT smb_url FROM file_state WHERE smb_url LIKE ? ESCAPE '\\'", (escaped + "%",)
    ).fetchall()
    return {row[0] for row in rows}
