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
    db.commit()
    return db


def is_unchanged(db: sqlite3.Connection, key: str, mtime: float) -> bool:
    row = db.execute("SELECT last_modified FROM file_state WHERE smb_url = ?", (key,)).fetchone()
    return row is not None and row[0] == mtime


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
