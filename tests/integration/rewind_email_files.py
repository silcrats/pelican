"""
Makes the state DB look as if emails had been indexed by an older Pelican,
from before thread fields: their indexed_at is moved to before the revision
was first seen. Run in a crawler container with its state volume. Prints how
many rows it changed.
"""

import sqlite3

from pelican import settings

db = sqlite3.connect(settings.STATE_DB_PATH)
(first_seen,) = db.execute(
    "SELECT first_seen FROM extraction_revisions WHERE revision = '2026-10-email-threads'").fetchone()
changed = db.execute(
    "UPDATE file_state SET indexed_at = ? WHERE smb_url LIKE '%.eml'", (first_seen - 86400,)).rowcount
db.commit()
print(changed)
