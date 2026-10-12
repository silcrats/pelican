"""
Writes progress to a JSON file on a shared status directory, read by the
separate always-on status-page service (see status-page/status_server.py).
Writes are atomic (write to a temp file, then os.replace) so the reader never
sees a partially-written file.

status.job_name (JOB_NAME) identifies this crawler instance (e.g.
"fileserver01", "mail") so multiple crawler containers can each write
their own file into the same shared status directory without clashing, and
the status page can show all of them.
"""

import json
import os
import tempfile
from datetime import datetime, timedelta, timezone

from . import settings

JOB_NAME = settings.JOB_NAME
STATUS_PATH = os.environ.get("STATUS_PATH", os.path.join(settings.STATUS_DIR, f"status-{JOB_NAME}.json"))
_TZ = (timezone(timedelta(hours=settings.STATUS_UTC_OFFSET_HOURS))
       if settings.STATUS_UTC_OFFSET_HOURS is not None else None)


def _now() -> str:
    now = datetime.now(_TZ) if _TZ else datetime.now().astimezone()
    return now.isoformat(timespec="seconds")


_status = {
    "job_name": JOB_NAME,
    "job_type": "smb",
    "status": "idle",
    "started_at": None,
    "finished_at": None,
    "current_share": None,
    "shares": {},
    "grand_total_indexed": 0,
    "last_updated": None,
    "config": {},
}


def _write() -> None:
    _status["last_updated"] = _now()
    status_dir = os.path.dirname(STATUS_PATH)
    os.makedirs(status_dir, exist_ok=True)
    # A fixed ".tmp" name here would race if the same JOB_NAME is ever
    # running twice at once (e.g. a scheduled run overlapping a manual one)
    # -- whichever process finishes first renames the shared tmp file away,
    # and the second's os.replace() then fails with "no such file" because
    # its tmp file is already gone. mkstemp gives each call its own unique
    # file, so two concurrent writers never collide; whoever replaces() last
    # simply wins, same as any other last-write-wins file.
    fd, tmp_path = tempfile.mkstemp(dir=status_dir, prefix=os.path.basename(STATUS_PATH) + ".")
    try:
        # mkstemp creates the file 0600; the status page may run as another
        # user, so keep it world-readable like a plain open() would have.
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "w") as f:
            json.dump(_status, f, indent=2)
        os.replace(tmp_path, STATUS_PATH)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def job_started(share_names: list[str], smb_workers: int = None,
                 exclude_extensions: list[str] = None, exclude_no_extension: bool = None,
                 job_type: str = "smb") -> None:
    # job_type lets the status page group jobs by crawler kind ("smb", "exchange",
    # "sharepoint", "acl") instead of just sorting job names alphabetically.
    _status["status"] = "running"
    _status["job_type"] = job_type
    _status["started_at"] = _now()
    _status["finished_at"] = None
    _status["grand_total_indexed"] = 0
    _status["config"] = {
        "smb_workers": smb_workers,
        "exclude_extensions": sorted(exclude_extensions) if exclude_extensions else [],
        "exclude_no_extension": exclude_no_extension,
    }
    _status["shares"] = {name: {"status": "pending", "discovered": 0, "indexed": 0,
                                 "skipped_excluded": 0, "skipped_unchanged": 0,
                                 "skipped_oversized": 0, "extraction_timeouts": 0,
                                 "acl_groups_changed": 0, "acl_docs_updated": 0, "error": None}
                          for name in share_names}
    _write()


def share_started(name: str) -> None:
    _status["current_share"] = name
    _status["shares"][name]["status"] = "running"
    _write()


def share_progress(name: str, discovered: int, indexed: int,
                    skipped_excluded: int = 0, skipped_unchanged: int = 0,
                    extraction_timeouts: int = 0, skipped_oversized: int = 0) -> None:
    s = _status["shares"][name]
    s["discovered"] = discovered
    s["indexed"] = indexed
    s["skipped_excluded"] = skipped_excluded
    s["skipped_unchanged"] = skipped_unchanged
    s["extraction_timeouts"] = extraction_timeouts
    s["skipped_oversized"] = skipped_oversized
    _status["grand_total_indexed"] = sum(sh["indexed"] for sh in _status["shares"].values())
    _write()


def acl_progress(name: str, acl_groups_changed: int, acl_docs_updated: int) -> None:
    """Separate from share_progress: an access-change pass can itself take a
    long time on a source with many directories, with nothing else to report
    meanwhile -- this lets its own progress show up live rather than only in
    a final summary line."""
    s = _status["shares"][name]
    s["acl_groups_changed"] = acl_groups_changed
    s["acl_docs_updated"] = acl_docs_updated
    _write()


def share_finished(name: str, indexed: int) -> None:
    s = _status["shares"][name]
    s["status"] = "done"
    s["indexed"] = indexed
    _status["grand_total_indexed"] = sum(sh["indexed"] for sh in _status["shares"].values())
    _write()


def share_failed(name: str, error: str) -> None:
    s = _status["shares"][name]
    s["status"] = "failed"
    s["error"] = error
    _write()


def failed_sources() -> list[str]:
    """Names of this run's shares/mailboxes/sites that failed."""
    return [name for name, s in _status["shares"].items() if s["status"] == "failed"]


def job_finished() -> None:
    _status["status"] = "idle"
    _status["current_share"] = None
    _status["finished_at"] = _now()
    _status["grand_total_indexed"] = sum(sh["indexed"] for sh in _status["shares"].values())
    _write()
