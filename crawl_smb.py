"""
SMB -> OpenSearch crawler. Crawls the shares in config/shares.yaml into the
shared index (see pelican/index.py for the document schema).

Two things needed to scale from ~600K files to millions:
  1. Concurrency: files are fetched in parallel via a thread pool, one
     persistent SMB connection per worker thread (see pelican/smb_client.py;
     a connection isn't shared across threads).
  2. Incremental runs: the state DB (pelican/state.py) tracks each file's
     last-modified time. On repeat runs, unchanged files are skipped
     entirely -- no download, no extraction, no OpenSearch write.

A permission (ACL) change on a folder does NOT change any file's modified
time, so it would never trigger the per-file re-fetch above. That is caught
by a separate container (sync_smb_acl.py), which re-checks each known
directory's ACL on its own schedule and updates already-indexed documents'
access without re-downloading them. This crawler's only part in it is
record_new_acl_groups(): registering each directory it walks (and forgetting
ones that are gone) so that container knows what to check.

A file deleted from the share is also never reported as such by a
directory listing -- it just stops appearing. See remove_deleted_files(): unlike the
Exchange/SharePoint crawlers (which get told about deletions via a Graph delta
feed), this diffs each run's complete listing against everything the state DB
previously knew about that share, so it needs a full, uninterrupted walk to be
trustworthy -- see that function's docstring for how a partial/failed walk is
kept from causing a wrong mass deletion.
"""

import os
import queue
import sqlite3
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, FIRST_COMPLETED, wait, as_completed
from pathlib import Path

from pelican import roles as role_store
from pelican import settings, smb_shares, state, status
from pelican.extract_text import extract_text
from pelican.index import build_doc, bulk_index, delete_docs, ensure_index_exists
from pelican.smb_acl import ACL_ROLES_TABLE, AclLookupProblem, acl_group_key, roles_for_acl_group, roles_for_path
from pelican.smb_client import SmbShareClient
from pelican.watchdog import heartbeat, start_watchdog

BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "50"))
SMB_WORKERS = int(os.environ.get("SMB_WORKERS", "8"))
EMPTY_LISTING_RETRY_DELAY_SECONDS = int(os.environ.get("EMPTY_LISTING_RETRY_DELAY_SECONDS", "5"))
# How long to wait for the server's answer to each SMB request, rather than
# relying on library defaults -- a NAS that accepts the TCP connection but then
# never answers a specific request (a silent network drop, not a clean error)
# has been observed hanging a crawl indefinitely with no exception and no way to
# notice. (Connect timeout: SMB_CONNECT_TIMEOUT_SECONDS, see pelican/smb_shares.py.)
SMB_LIST_TIMEOUT_SECONDS = int(os.environ.get("SMB_LIST_TIMEOUT_SECONDS", "60"))
# Generous compared to listing. Applies to each 1 MiB read request, so a large
# file on a slow link isn't mistaken for a hang.
SMB_FETCH_TIMEOUT_SECONDS = int(os.environ.get("SMB_FETCH_TIMEOUT_SECONDS", "300"))
# Belt-and-braces on top of SMB_LIST_TIMEOUT_SECONDS: observed in practice
# (with the earlier SMB library), a listing passed an explicit timeout can still
# block indefinitely against an unresponsive NAS (CPU pinned at 0%, no
# progress, no exception, for many minutes) -- so per-request timeouts aren't
# trusted alone here. This is the actual backstop: how long with NO new item at
# all from the listing before giving up on it outright. See
# walk_smb_files_watchdog().
SMB_LIST_STALL_SECONDS = int(os.environ.get("SMB_LIST_STALL_SECONDS", "120"))

_config = smb_shares.config()
SHARES = smb_shares.selected_shares()
DEFAULT_EXCLUDE_EXTENSIONS = {e.lower().lstrip(".") for e in _config.get("exclude_extensions", [])}
DEFAULT_EXCLUDE_NO_EXTENSION = _config.get("exclude_no_extension", False)
# Remove documents from the index once their file is gone from the share. See
# remove_deleted_files(). Global only (no per-share override), matching how
# Exchange/SharePoint's own propagate_deletes setting works.
PROPAGATE_DELETES = bool(_config.get("propagate_deletes", True))

_thread_local = threading.local()
# Every worker connection opened for the current share, closed when it's done.
_worker_connections: list[SmbShareClient] = []
_worker_connections_lock = threading.Lock()


def get_worker_connection(share: dict) -> SmbShareClient:
    """One persistent connection per worker thread, created lazily and reused.
    Worker threads live for one share (process_share's executor), so each
    connection is to that share."""
    if not hasattr(_thread_local, "conn"):
        _thread_local.conn = smb_shares.connect(share)
        with _worker_connections_lock:
            _worker_connections.append(_thread_local.conn)
    return _thread_local.conn


def close_worker_connections() -> None:
    with _worker_connections_lock:
        for conn in _worker_connections:
            conn.close()
        _worker_connections.clear()


def walk_smb_files(conn: SmbShareClient, smb_path: str):
    """Lazily yield (share-relative SMB path, last_write_time) for every
    file under smb_path. Listing only -- nothing downloaded here."""
    for name, is_directory, last_write_time in conn.list_dir(smb_path, timeout=SMB_LIST_TIMEOUT_SECONDS):
        entry_smb_path = f"{smb_path}\\{name}" if smb_path else name
        if is_directory:
            yield from walk_smb_files(conn, entry_smb_path)
        else:
            yield entry_smb_path, last_write_time


def _walk_smb_files_producer(conn: SmbShareClient, root_path: str, out: queue.Queue) -> None:
    """Runs walk_smb_files to completion on a background thread, forwarding
    every item (or the terminal error/done marker) onto `out`. See
    walk_smb_files_watchdog for why this exists."""
    try:
        for item in walk_smb_files(conn, root_path):
            out.put(("item", item))
    except Exception as exc:
        out.put(("error", exc))
    else:
        out.put(("done", None))


def walk_smb_files_watchdog(conn: SmbShareClient, share_name: str, root_path: str, stall_seconds: float):
    """Like walk_smb_files, but gives up if NOTHING new arrives (not even one
    more file, or the listing finishing) within stall_seconds -- protection
    against a hang inside the SMB library or the underlying socket that
    per-request timeouts don't reliably catch.

    Does this by running the real walk on a background daemon thread and
    reading its results off a queue with a timeout on each read, rather than
    iterating it directly -- queue.Queue.get(timeout=...) is enforced by
    Python itself, not by whatever the SMB library/socket is doing, so it
    can't be defeated the same way.

    If it gives up, the background thread is simply abandoned, not joined --
    safe here because this is a one-shot process: once its job finishes (even
    having given up on this one share), the whole container exits and Python
    kills any daemon thread outright, stuck or not."""
    q: queue.Queue = queue.Queue(maxsize=1000)
    threading.Thread(target=_walk_smb_files_producer, args=(conn, root_path, q), daemon=True).start()
    while True:
        try:
            kind, payload = q.get(timeout=stall_seconds)
        except queue.Empty:
            raise TimeoutError(
                f"no progress listing '{share_name}' for {stall_seconds:.0f}s -- the SMB connection "
                f"appears to have hung (its per-request timeout apparently didn't catch this)"
            )
        if kind == "done":
            return
        if kind == "error":
            raise payload
        yield payload


def fetch_one(share: dict, smb_relative_path: str) -> tuple[str, str, list[str], int, dict, str]:
    """Runs in a worker thread. Returns (filename, extracted_text, roles, raw_size, meta, acl_group)."""
    conn = get_worker_connection(share)
    filename = smb_relative_path.split("\\")[-1]
    data = conn.read_file(smb_relative_path, timeout=SMB_FETCH_TIMEOUT_SECONDS)
    full_path = f"{share['server']}\\{share['share']}\\{smb_relative_path}"
    text, meta = extract_text(full_path, data)
    doc_roles = roles_for_path(share, smb_relative_path)
    group = acl_group_key(share, smb_relative_path)
    return filename, text, doc_roles, len(data), meta, group


def record_new_acl_groups(share: dict, acl_groups_seen: set[str], state_db: sqlite3.Connection) -> None:
    """Keeps ACL_ROLES_TABLE's set of directories for this share in step with
    what this run's walk actually found, for the separate ACL-sync container
    (sync_smb_acl.py) -- which doesn't walk the share itself and only ever
    re-checks directories listed here.

    A directory seen for the first time has its current roles recorded as the
    baseline, without touching any document (its documents were just indexed
    with those same roles by fetch_one, and there is nothing yet to compare
    against). A recorded directory this walk no longer found is forgotten, so
    the ACL container doesn't keep smbcacls-ing a deleted folder forever.

    The walk that produced acl_groups_seen completed without raising (an
    incomplete listing propagates out of process_share before this is
    reached), but an EMPTY set can still mean a NAS blip rather than a truly
    empty share -- so nothing is forgotten in that case, same as
    remove_deleted_files."""
    share_name = share["name"]
    prefix = f"{share_name}\x1f"
    known = set(role_store.list_sources(state_db, ACL_ROLES_TABLE, prefix))
    seen_keys = {f"{prefix}{g}" for g in acl_groups_seen}

    new_count = 0
    for source_key in sorted(seen_keys - known):
        group_key = source_key[len(prefix):]
        try:
            found = roles_for_acl_group(share, group_key)
        except AclLookupProblem as exc:
            print(f"  could not record ACL baseline for new directory '{group_key}': {exc} -- will retry next run")
            continue
        role_store.save_stored_roles(state_db, ACL_ROLES_TABLE, source_key, found)
        new_count += 1
    if new_count:
        print(f"  recorded ACL baseline for {new_count} newly-seen director{'y' if new_count == 1 else 'ies'}")

    gone = sorted(known - seen_keys)
    if gone and seen_keys:
        role_store.delete_sources(state_db, ACL_ROLES_TABLE, gone)
        print(f"  forgot {len(gone)} director{'y' if len(gone) == 1 else 'ies'} no longer on the share")


def previously_known_urls(share: dict, state_db: sqlite3.Connection) -> set[str]:
    """Every url the state DB currently has recorded for this share. Used both
    to decide whether an empty listing is suspicious (process_share's retry) and,
    later, to work out what's actually been deleted (remove_deleted_files) --
    computed once per run and passed to both, rather than queried twice.

    Scoped by this share's own `path`, not just its (server, share) pair: several
    shares.yaml entries commonly point at the same underlying SMB share with
    different `path`s. Matching on (server, share) alone treats a SIBLING entry's
    files as belonging to this one -- which is exactly what made two shares
    alternately "delete" each other's files (and force a full re-crawl of
    whichever got wiped) every run."""
    root = share.get("path", "").replace("\\", "/").strip("/")
    prefix = f"smb://{share['server']}/{share['share']}/" + (f"{root}/" if root else "")
    return state.keys_with_prefix(state_db, prefix)


def remove_deleted_files(share: dict, seen: set[str], previously_known: set[str],
                          state_db: sqlite3.Connection) -> int:
    """Removes documents from the index whose file no longer exists on the
    share. An SMB directory listing has no "tell me what changed" mode -- it's a full
    directory listing every run -- so this is detected by diffing this run's
    complete set of discovered files (`seen`, everything walk_smb_files
    yielded, regardless of extension exclusion or whether the content itself
    changed) against `previously_known` (see previously_known_urls).

    Only ever called after process_share's walk-and-fetch loop finished
    without raising: if the SMB listing fails or is interrupted partway
    (a dropped connection, a subfolder the crawl account can no longer read),
    walk_smb_files' exception propagates out of process_share uncaught, the
    whole share is reported failed by run()'s try/except, and this function is
    never reached for that run -- an incomplete listing must never be treated
    as "everything else was deleted".

    That guard isn't enough on its own, though: a listing can also come back
    completely EMPTY without raising anything -- a NAS blip, a permissions
    change, a mistyped path -- and that's indistinguishable, from here, from
    every file genuinely having been deleted in one run. process_share already
    retries a share that discovers nothing once before we ever get here, so
    reaching this function with seen still empty means that retry ALSO came
    back empty. Treating that as "delete everything" could empty the index of
    a still-populated share, so it's refused outright rather than acted on."""
    if not seen and previously_known:
        print(f"  WARNING: this run discovered 0 files under '{share['name']}' (even after a retry) but "
              f"{len(previously_known)} file(s) were previously indexed -- NOT deleting anything. Check the "
              f"share path/credentials/permissions are still correct, and that the folder is still really there.")
        return 0
    to_delete = previously_known - seen
    if not to_delete:
        return 0
    delete_docs(to_delete)
    state.forget(state_db, to_delete)
    return len(to_delete)


def process_share(share: dict, state_db: sqlite3.Connection) -> int:
    status.share_started(share["name"])
    heartbeat(f"started '{share['name']}'")
    known_before = previously_known_urls(share, state_db)

    exclude_extensions = {e.lower().lstrip(".") for e in share.get("exclude_extensions", DEFAULT_EXCLUDE_EXTENSIONS)}
    exclude_no_extension = share.get("exclude_no_extension", DEFAULT_EXCLUDE_NO_EXTENSION)

    actions: list[dict] = []
    total_indexed = 0
    skipped_excluded = 0
    skipped_unchanged = 0
    extraction_timeouts = 0
    batch_num = 0

    def flush_batch() -> None:
        nonlocal batch_num, total_indexed, actions
        if not actions:
            return
        batch_num += 1
        bulk_index(actions)
        total_indexed += len(actions)
        state_db.commit()
        heartbeat(f"indexed batch {batch_num} of '{share['name']}'")
        print(f"  batch {batch_num}: indexed {len(actions)} docs (running total {total_indexed})")
        actions = []

    def handle_result(future, smb_relative_path: str, mtime: float, url: str) -> None:
        nonlocal actions, extraction_timeouts
        try:
            filename, text, doc_roles, raw_size, meta, acl_group = future.result()
        except Exception as exc:
            print(f"  fetch failed for {smb_relative_path}: {exc}")
            return
        if meta.get("extraction_timeout"):
            extraction_timeouts += 1
        actions.append(build_doc(url, filename, text, doc_roles, raw_size, meta, share["name"], mtime,
                                 host=settings.HOST_SMB, acl_group=acl_group))
        state.record_indexed(state_db, url, mtime)
        if len(actions) >= BATCH_SIZE:
            flush_batch()

    # Retried once (fresh connection) if a share that previously had content
    # discovers nothing at all -- see remove_deleted_files' docstring for why:
    # a NAS blip or transient server-side issue can make a listing come back
    # completely empty without raising anything, indistinguishable up to this
    # point from every file genuinely being gone. A retry lets the crawl
    # self-heal within the same run instead of just avoiding the worse outcome
    # (silently deleting everything) and waiting for the next scheduled run.
    # Safe to retry from scratch: discovered == 0 means the loop below never
    # queued a single fetch, so nothing needs undoing between attempts.
    for attempt in (1, 2):
        lister_conn = smb_shares.connect(share)
        discovered = 0
        acl_groups_seen: set[str] = set()
        seen: set[str] = set()   # every file's url discovered this run, regardless of
                                  # exclusion/unchanged status -- see remove_deleted_files()

        try:
            with ThreadPoolExecutor(max_workers=SMB_WORKERS) as executor:
                in_flight: dict = {}
                max_in_flight = SMB_WORKERS * 4
                last_report = time.time()

                for smb_relative_path, mtime in walk_smb_files_watchdog(
                        lister_conn, share["share"], share.get("path", ""), SMB_LIST_STALL_SECONDS):
                    discovered += 1
                    if time.time() - last_report > 3:
                        heartbeat(f"discovering '{share['name']}' ({discovered} so far)")
                        print(f"  [diag] discovered {discovered} files so far, {len(in_flight)} in flight, {total_indexed} indexed")
                        status.share_progress(share["name"], discovered, total_indexed, skipped_excluded,
                                               skipped_unchanged, extraction_timeouts)
                        last_report = time.time()

                    # Both tracked for every file (even excluded/unchanged ones), computed
                    # before any `continue` below: acl_groups_seen is how
                    # record_new_acl_groups() finds every directory the ACL container should
                    # know about (a permission change never shows up as a "changed" file to
                    # skip past), and seen is how remove_deleted_files()
                    # tells "still on the share, just not re-indexed this run" apart from
                    # "gone" -- excluding a file by extension must not make it look deleted.
                    acl_groups_seen.add(acl_group_key(share, smb_relative_path))
                    url = smb_shares.smb_url(share, smb_relative_path)
                    seen.add(url)

                    filename = smb_relative_path.split("\\")[-1]
                    ext = Path(filename).suffix.lstrip(".").lower()
                    if (ext and ext in exclude_extensions) or (not ext and exclude_no_extension):
                        skipped_excluded += 1
                        continue

                    if state.is_unchanged(state_db, url, mtime):
                        skipped_unchanged += 1
                        continue

                    future = executor.submit(fetch_one, share, smb_relative_path)
                    in_flight[future] = (smb_relative_path, mtime, url)

                    if len(in_flight) >= max_in_flight:
                        done, _ = wait(in_flight.keys(), return_when=FIRST_COMPLETED)
                        for f in done:
                            handle_result(f, *in_flight.pop(f))

                for f in as_completed(in_flight):
                    handle_result(f, *in_flight[f])
        finally:
            # Also on an error, so a failed share doesn't leave connections open.
            lister_conn.close()
            close_worker_connections()

        if discovered > 0 or not known_before or attempt == 2:
            break
        print(f"  discovered 0 files under '{share['name']}' but {len(known_before)} were previously known -- "
              f"retrying the listing once with a fresh connection in {EMPTY_LISTING_RETRY_DELAY_SECONDS}s")
        time.sleep(EMPTY_LISTING_RETRY_DELAY_SECONDS)

    flush_batch()

    # Both run only after the walk-and-fetch loop above completed without raising
    # (see each function's docstring for why that matters).
    if PROPAGATE_DELETES:
        removed = remove_deleted_files(share, seen, known_before, state_db)
        if removed:
            print(f"  removed {removed} deleted files from the index")

    # Only registers new directories (and forgets gone ones); re-checking known
    # directories for permission changes is the ACL container's job.
    record_new_acl_groups(share, acl_groups_seen, state_db)

    status.share_progress(share["name"], discovered, total_indexed, skipped_excluded,
                           skipped_unchanged, extraction_timeouts)

    if skipped_excluded:
        print(f"  skipped {skipped_excluded} excluded files")
    if skipped_unchanged:
        print(f"  skipped {skipped_unchanged} unchanged files")
    if extraction_timeouts:
        print(f"  {extraction_timeouts} files hit the PDF extraction timeout ({os.environ.get('PDF_TIMEOUT_SECONDS', '30')}s)")
    return total_indexed


def run() -> None:
    start_watchdog()
    ensure_index_exists()
    state_db = state.init_state_db()
    role_store.init_roles_table(state_db, ACL_ROLES_TABLE)
    status.job_started(
        [s["name"] for s in SHARES],
        smb_workers=SMB_WORKERS,
        exclude_extensions=sorted(DEFAULT_EXCLUDE_EXTENSIONS),
        exclude_no_extension=DEFAULT_EXCLUDE_NO_EXTENSION,
    )
    grand_total = 0

    for share in SHARES:
        print(f"Processing share '{share['name']}' from {share['server']}/{share['share']}")
        try:
            count = process_share(share, state_db)
            grand_total += count
            status.share_finished(share["name"], count)
            print(f"  finished '{share['name']}': {count} documents indexed")
        except Exception as exc:
            status.share_failed(share["name"], str(exc))
            print(f"  failed on '{share['name']}': {exc}")

    state_db.close()
    print(f"Total indexed across all shares: {grand_total}")
    status.job_finished()
    # Non-zero exit so the scheduler and monitoring see the failure; the
    # status page shows which share and why.
    failed = status.failed_sources()
    if failed:
        sys.exit(f"{len(failed)} share(s) failed: {', '.join(failed)}")


if __name__ == "__main__":
    run()
