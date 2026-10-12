"""
Exchange Online -> OpenSearch crawler (Microsoft Graph). Crawls the mailboxes
in config/exchange.yaml into the shared index, with the same document schema
as the SMB crawler, so a search UI sees files and mail together.

  * Each message is downloaded as full MIME (GET /messages/{id}/$value) and
    passed to extract_text() as an ".eml" -- the same code path as .eml files
    on an SMB share, so email_from/email_to/email_subject/email_attachments
    and attachment text extraction come out identically.
  * Index bootstrap, document schema, state DB, roles and status are the
    shared pelican/ modules.

Incremental crawling: one Graph delta query per folder. The deltaLink is
stored in the state DB only after every message in that folder was handled
successfully, so a crash or a failed fetch just replays that folder next run
(unchanged messages are skipped via file_state).

A message's "mtime" in file_state is its receivedDateTime, not
lastModifiedDateTime -- otherwise every read/unread flip or flag change would
trigger a full re-download and re-index of the message.
"""

import json
import os
import re
import sqlite3
import sys
import time
from concurrent.futures import ThreadPoolExecutor, FIRST_COMPLETED, wait, as_completed
from datetime import datetime, timezone
from urllib.parse import quote

import requests

from pelican import roles as role_store
from pelican import settings, state, status
from pelican.extract_text import extract_text
from pelican.graph_client import GraphClient
from pelican.index import SEARCH_INDEX, build_doc, bulk_index, client, delete_docs, ensure_index_exists
from pelican.watchdog import heartbeat, start_watchdog

EXCHANGE_CONFIG_PATH = settings.config_path("EXCHANGE_CONFIG", "exchange.yaml")
# Graph allows ~4 concurrent requests per app per mailbox; going above that
# just produces 429s.
GRAPH_WORKERS = int(os.environ.get("GRAPH_WORKERS", "4"))
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "50"))

_config = settings.load_yaml(EXCHANGE_CONFIG_PATH)

MAILBOXES = _config.get("mailboxes") or []

# Optional: restrict this instance to some mailboxes by name (comma-separated),
# mirroring SHARE_NAMES in the SMB crawler.
_names_filter = os.environ.get("MAILBOX_NAMES", "").strip()
if _names_filter:
    _wanted = {n.strip() for n in _names_filter.split(",") if n.strip()}
    _unknown = _wanted - {m["name"] for m in MAILBOXES}
    if _unknown:
        raise ValueError(f"MAILBOX_NAMES references mailboxes not in {EXCHANGE_CONFIG_PATH}: {sorted(_unknown)}")
    MAILBOXES = [m for m in MAILBOXES if m["name"] in _wanted]

_auth = _config.get("auth") or {}
# ImmutableId: message IDs stay the same when a message is moved between
# folders, so document IDs (md5 of the ID-based key) don't change on a move.
graph = GraphClient(
    tenant_env=_auth.get("tenant_id_env", "GRAPH_TENANT_ID"),
    client_id_env=_auth.get("client_id_env", "GRAPH_CLIENT_ID"),
    secret_env=_auth.get("secret_env", "GRAPH_SECRET"),
    authority=_auth.get("authority", "https://login.microsoftonline.com"),
    endpoint=_auth.get("graph_endpoint", "https://graph.microsoft.com/v1.0"),
    scope=_auth.get("scope", "https://graph.microsoft.com/.default"),
    max_retries=int(os.environ.get("GRAPH_MAX_RETRIES", "8")),
    prefer='IdType="ImmutableId", odata.maxpagesize=100',
)

MAX_MESSAGE_BYTES = int(_config.get("max_message_mb", 100)) * 1024 * 1024
PROPAGATE_DELETES = bool(_config.get("propagate_deletes", True))
FULL_RECRAWL_SECONDS = float(_config.get("full_recrawl_days", 30)) * 86400

# Full Access holders per mailbox, exported from Exchange Online by the
# exo-permissions job (see exo-permissions/). Optional: when unset, only the
# hand-written `permissions:` in exchange.yaml are used.
PERMISSIONS_FILE = os.environ.get("EXCHANGE_PERMISSIONS_FILE") or _config.get("permissions_file") or ""
PERMISSIONS_MAX_AGE_SECONDS = float(_config.get("permissions_max_age_hours", 48)) * 3600


# --------------------------------------------------------------- state (delta)

def init_tables(db: sqlite3.Connection) -> None:
    db.execute("""
        CREATE TABLE IF NOT EXISTS exchange_delta (
            mailbox TEXT,
            folder_id TEXT,
            delta_link TEXT,
            updated_at REAL,
            full_crawl_at REAL,
            PRIMARY KEY (mailbox, folder_id)
        )
    """)
    # The roles last written onto each mailbox's documents, so a change in who
    # has access can be detected and applied to already-indexed documents.
    db.execute("""
        CREATE TABLE IF NOT EXISTS exchange_roles (
            mailbox TEXT PRIMARY KEY,
            roles TEXT,
            updated_at REAL
        )
    """)
    db.commit()


def get_delta(db: sqlite3.Connection, mailbox: str, folder_id: str):
    return db.execute(
        "SELECT delta_link, full_crawl_at FROM exchange_delta WHERE mailbox = ? AND folder_id = ?",
        (mailbox, folder_id),
    ).fetchone()


def save_delta(db: sqlite3.Connection, mailbox: str, folder_id: str, link: str, full_crawl_at: float) -> None:
    db.execute(
        "INSERT OR REPLACE INTO exchange_delta (mailbox, folder_id, delta_link, updated_at, full_crawl_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (mailbox, folder_id, link, time.time(), full_crawl_at),
    )


def get_stored_roles(db: sqlite3.Connection, mailbox: str) -> list[str] | None:
    row = db.execute("SELECT roles FROM exchange_roles WHERE mailbox = ?", (mailbox,)).fetchone()
    return json.loads(row[0]) if row else None


def save_stored_roles(db: sqlite3.Connection, mailbox: str, roles: list[str]) -> None:
    db.execute(
        "INSERT OR REPLACE INTO exchange_roles (mailbox, roles, updated_at) VALUES (?, ?, ?)",
        (mailbox, json.dumps(roles), time.time()),
    )
    db.commit()


# ------------------------------------------------------------------- helpers

def _user_path(user: str) -> str:
    return f"{graph.endpoint}/users/{quote(user, safe='@')}"


def _epoch(iso: str | None) -> float:
    if not iso:
        return 0.0
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone(timezone.utc).timestamp()


def _normalise_since(since) -> str | None:
    if not since:
        return None
    s = str(since)
    return s + "T00:00:00Z" if len(s) == 10 else s


def _safe_filename(subject: str | None) -> str:
    cleaned = re.sub(r'[\\/:*?"<>|\r\n\t]+', " ", subject or "").strip()[:150]
    return (cleaned or "(no subject)") + ".eml"


class DirectoryLookupProblem(Exception):
    """A lookup failed in a way that says nothing about the person (permission
    missing, throttling, outage) -- as opposed to them simply having no AD account."""


_ad_name_cache: dict[str, tuple[str | None, str | None]] = {}


def ad_name_for(principal: dict) -> tuple[str | None, str | None]:
    """Map an exported Full Access principal to the name the search UI puts in
    that person's role list, via Entra (Microsoft Graph). Exchange Online's own
    SamAccountName is a generated placeholder, so it can't be used.

      user  -> onPremisesSamAccountName  (the AD username they sign in with)
      group -> CN taken from onPremisesDistinguishedName (what the UI reads
               from AD `memberOf`, using the same CN extraction)

    Returns (name, note). name is None (with a note) for someone who simply has
    no AD account. Raises DirectoryLookupProblem for anything transient/permission."""
    object_id = principal.get("object_id")
    kind = principal.get("kind")
    label = principal.get("address") or principal.get("display") or object_id
    if not object_id or kind not in ("user", "group"):
        return None, f"{label}: not identifiable as a user or group"
    cached = _ad_name_cache.get(object_id)
    if cached is not None:
        return cached

    collection = "users" if kind == "user" else "groups"
    select = "onPremisesSamAccountName,onPremisesSyncEnabled" if kind == "user" else "onPremisesDistinguishedName,onPremisesSyncEnabled"
    perm = "User.Read.All" if kind == "user" else "Group.Read.All"
    try:
        resp = graph.request(f"{graph.endpoint}/{collection}/{quote(object_id, safe='')}", params={"$select": select})
    except requests.RequestException as exc:
        raise DirectoryLookupProblem(f"Graph lookup of {label} failed: {exc}") from None
    try:
        if resp.status_code == 404:
            result = (None, f"{label}: not found in Entra")
        elif resp.status_code in (401, 403):
            raise DirectoryLookupProblem(
                f"Graph refused the lookup of {label} (HTTP {resp.status_code}) -- the app needs the "
                f"{perm} application permission with admin consent")
        elif resp.status_code != 200:
            raise DirectoryLookupProblem(f"Graph lookup of {label} returned HTTP {resp.status_code}")
        else:
            body = resp.json()
            if kind == "user":
                name = body.get("onPremisesSamAccountName")
            else:
                name = role_store.cn_from_dn(body.get("onPremisesDistinguishedName"))
            result = (name, None) if name else (None, f"{label}: no AD account (not synced from AD)")
    finally:
        resp.close()
    _ad_name_cache[object_id] = result
    return result


def full_access_roles(mb: dict) -> tuple[list[str] | None, str | None]:
    """Roles for the mailbox owner and everyone with Full Access, from the
    exported permissions file. Returns (roles, problem): roles is None when the
    export can't be used, and problem says why (None if it's simply not in use)."""
    if not PERMISSIONS_FILE or mb.get("full_access", True) is False:
        return None, None
    try:
        with open(PERMISSIONS_FILE) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"can't read permissions file {PERMISSIONS_FILE}: {exc}"
    age = time.time() - float(data.get("generated_at_epoch") or 0)
    if age > PERMISSIONS_MAX_AGE_SECONDS:
        return None, f"permissions file is {age / 3600:.0f}h old (limit {PERMISSIONS_MAX_AGE_SECONDS / 3600:.0f}h)"
    entry = (data.get("mailboxes") or {}).get(mb["name"])
    if not entry:
        return None, f"no exported permissions for '{mb['name']}'"
    if entry.get("error"):
        return None, f"permission export failed for '{mb['name']}': {entry['error']}"

    principals = entry.get("principals") or []
    if isinstance(principals, dict):        # PowerShell can emit a lone item unwrapped
        principals = [principals]
    found = []
    notes = []
    for p in principals:
        try:
            name, note = ad_name_for(p)
        except DirectoryLookupProblem as exc:
            return None, str(exc)      # can't be sure who has access -> caller keeps last known roles
        if name is None:
            notes.append(note)
        elif p["kind"] == "user":
            found.append(role_store.user_role(name))
        else:
            found.append(role_store.group_role(name))
    unresolved = entry.get("unresolved") or []
    if isinstance(unresolved, str):
        unresolved = [unresolved]
    notes += [f"{u}: couldn't be identified in Exchange" for u in unresolved]
    if notes:
        print(f"  note: {len(notes)} Full Access grant(s) on '{mb['name']}' get no search access: " + "; ".join(notes))
    return found, None


def resolve_roles(mb: dict, state_db: sqlite3.Connection) -> list[str]:
    """The roles to stamp on this mailbox's documents: owner + Full Access holders
    (from Exchange) + anything written by hand in exchange.yaml. If access changed
    since the last run, already-indexed documents are updated too.

    Fails safe: if the Exchange export is missing, stale or errored, the last known
    roles are kept -- access is never widened or wiped because a lookup failed."""
    name = mb["name"]
    stored = get_stored_roles(state_db, name)
    exchange_roles, problem = full_access_roles(mb)

    if exchange_roles is not None:
        mb_roles = sorted(set(role_store.static_roles(mb)) | set(exchange_roles))
    elif problem and stored is not None:
        print(f"  {problem} -- keeping the last known roles for '{name}'")
        return stored
    else:
        if problem:
            print(f"  {problem} -- using only the roles from exchange.yaml")
        mb_roles = sorted(set(role_store.static_roles(mb)))
    mb_roles = mb_roles or [role_store.RESTRICTED]  # restrict rather than accidentally open up

    shown = role_store.summarize(mb_roles)
    if stored is None or sorted(stored) != mb_roles:
        print(f"  access for '{name}' {'set' if stored is None else 'changed'}: {shown}")
        updated = role_store.apply_roles_to_indexed_docs(
            client, SEARCH_INDEX, name, settings.HOST_EXCHANGE, mb_roles, on_progress=heartbeat
        )  # raises on failure -> mailbox reported failed, retried next run
        print(f"  updated roles on {updated} already-indexed document(s)")
        status.acl_progress(name, 1 if updated else 0, updated)
        save_stored_roles(state_db, name, mb_roles)
    else:
        print(f"  access for '{name}' unchanged: {shown}")
    return mb_roles


def list_folders(user: str, exclude: set[str]):
    """Yield (folder_id, folder_path) for every non-excluded folder, recursively."""
    select = {"$top": 100, "$select": "id,displayName,childFolderCount"}

    def walk(url: str, parent_path: str):
        for body in graph.pages(url, dict(select)):
            for folder in body.get("value", []):
                name = folder["displayName"]
                if name.lower() in exclude:
                    continue
                path = f"{parent_path}/{name}" if parent_path else name
                yield folder["id"], path
                if folder.get("childFolderCount", 0):
                    yield from walk(f"{_user_path(user)}/mailFolders/{quote(folder['id'], safe='')}/childFolders", path)

    yield from walk(f"{_user_path(user)}/mailFolders", "")


class MessageTooLarge(Exception):
    """A message is over max_message_mb -- expected/routine, not a fetch failure.
    Kept distinct from other exceptions so handle_result can count it separately
    (skipped_oversized) instead of as a folder failure: unlike a real error, an
    oversized message will be exactly as oversized on every future run, so
    treating it as a "failure" would keep that folder's delta token from ever
    advancing and retry the same doomed fetch forever (see handle_result)."""


def fetch_one(user: str, message_id: str) -> tuple[str, dict, int]:
    """Runs in a worker thread. Returns (extracted_text, meta, raw_size)."""
    url = f"{_user_path(user)}/messages/{quote(message_id, safe='')}/$value"
    resp = graph.request(url, stream=True)
    try:
        if not resp.ok:
            raise requests.HTTPError(f"{resp.status_code} {resp.reason} for url {resp.url}: {resp.text}", response=resp)
        declared = int(resp.headers.get("Content-Length") or 0)
        if declared > MAX_MESSAGE_BYTES:
            raise MessageTooLarge(f"message too large ({declared} bytes)")
        buf = bytearray()
        for chunk in resp.iter_content(1 << 20):
            buf.extend(chunk)
            if len(buf) > MAX_MESSAGE_BYTES:
                raise MessageTooLarge(f"message too large (>{MAX_MESSAGE_BYTES} bytes)")
    finally:
        resp.close()
    data = bytes(buf)
    text, meta = extract_text(f"exchange\\{user}\\{message_id}.eml", data)
    return text, meta, len(data)


# ------------------------------------------------------------------- crawling

def _mailbox_scoped_weblink(web_link: str, user: str) -> str:
    """Graph's webLink is always '.../owa/?ItemID=...', with no mailbox
    segment -- OWA resolves that ItemID against whichever mailbox the
    *viewer* is currently signed into. That's correct for a message in the
    viewer's own mailbox, but wrong for a shared/delegated mailbox the
    message actually lives in: confirmed directly against a real tenant, the
    viewer's own mailbox opens instead, showing "This message might have
    been moved or deleted" for an item that was never there to begin with.

    Inserting the mailbox's own address as a path segment -- the same
    convention as the classic /owa/<address>/ shared-mailbox URL -- fixes
    that for anyone with Full Access to it, and should be a no-op for
    someone opening their own mail (explicit self-reference vs. the
    default). Also confirmed directly: this does NOT reliably land on the
    specific item for a mailbox other than the viewer's own -- OWA opens
    that mailbox's inbox instead, not the message. That's a known,
    unresolved OWA limitation (see
    https://learn.microsoft.com/en-us/answers/questions/62f63756), not
    something fixable from this end -- but it's still strictly better than
    a link that opens the wrong mailbox entirely."""
    if "/owa/?" not in web_link:
        return web_link
    return web_link.replace("/owa/?", f"/owa/{quote(user, safe='@.')}/?", 1)


def process_mailbox(mb: dict, state_db: sqlite3.Connection) -> int:
    name, user = mb["name"], mb["user"]
    if mb.get("archive"):
        raise NotImplementedError(
            "Online Archive mailboxes aren't reachable through Graph yet -- "
            "leave `archive: true` entries disabled until Microsoft's Graph archive support is live in your tenant"
        )

    status.share_started(name)
    heartbeat(f"started '{name}'")
    exclude = {f.lower() for f in mb.get("exclude_folders", _config.get("exclude_folders", []))}
    since = _normalise_since(mb.get("since", _config.get("since")))
    mb_roles = resolve_roles(mb, state_db)

    actions: list[dict] = []
    seen: set[str] = set()              # every message key encountered this run (indexed or skipped)
    pending_deletes: set[str] = set()   # applied at the end, minus anything seen (i.e. moved, not deleted)
    discovered = total_indexed = skipped_unchanged = extraction_timeouts = skipped_oversized = 0
    folder_failures = 0
    batch_num = 0
    last_report = time.time()

    def flush_batch() -> None:
        nonlocal batch_num, total_indexed, actions
        if not actions:
            return
        batch_num += 1
        bulk_index(actions)
        total_indexed += len(actions)
        state_db.commit()
        heartbeat(f"indexed batch {batch_num} of '{name}'")
        print(f"  batch {batch_num}: indexed {len(actions)} docs (running total {total_indexed})")
        actions = []

    def handle_result(future, subject: str, mtime: float, state_key: str, web_link: str) -> None:
        nonlocal actions, extraction_timeouts, folder_failures, skipped_oversized
        try:
            text, meta, raw_size = future.result()
        except MessageTooLarge as exc:
            print(f"  skipping '{subject}' ({state_key}): {exc}")
            skipped_oversized += 1
            return
        except Exception as exc:
            print(f"  fetch failed for '{subject}' ({state_key}): {exc}")
            folder_failures += 1
            return
        if meta.get("extraction_timeout"):
            extraction_timeouts += 1
        # url = what a user clicks (the message in Outlook on the web), rewritten to
        # target this mailbox explicitly -- see _mailbox_scoped_weblink;
        # _id is derived from the stable ID-based key so moves/renames don't duplicate.
        scoped_link = _mailbox_scoped_weblink(web_link, user) if web_link else web_link
        actions.append(build_doc(scoped_link or state_key, _safe_filename(subject), text, mb_roles,
                                 raw_size, meta, name, mtime, host=settings.HOST_EXCHANGE, id_key=state_key))
        state.record_indexed(state_db, state_key, mtime)
        if len(actions) >= BATCH_SIZE:
            flush_batch()

    with ThreadPoolExecutor(max_workers=GRAPH_WORKERS) as executor:
        max_in_flight = GRAPH_WORKERS * 4

        for folder_id, folder_path in list_folders(user, exclude):
            print(f"  folder '{folder_path}'")
            row = get_delta(state_db, name, folder_id)
            now = time.time()
            if row and row[0] and (now - (row[1] or 0)) < FULL_RECRAWL_SECONDS:
                url, params, full_crawl_at = row[0], None, row[1]      # incremental
            else:
                url = f"{_user_path(user)}/mailFolders/{quote(folder_id, safe='')}/messages/delta"
                params = {"$select": "id,receivedDateTime,subject,webLink"}
                if since:
                    params["$filter"] = f"receivedDateTime ge {since}"
                full_crawl_at = now                                     # full (re)enumeration

            in_flight: dict = {}
            folder_failures = 0
            final_delta = None

            for body in graph.pages(url, params):
                for msg in body.get("value", []):
                    discovered += 1
                    state_key = f"exchange://{user}/{msg['id']}"

                    if "@removed" in msg:
                        pending_deletes.add(state_key)
                        continue
                    seen.add(state_key)

                    if time.time() - last_report > 3:
                        heartbeat(f"discovering '{name}' ({discovered} so far)")
                        print(f"  [diag] discovered {discovered} messages so far, {len(in_flight)} in flight, {total_indexed} indexed")
                        status.share_progress(name, discovered, total_indexed, 0, skipped_unchanged,
                                              extraction_timeouts, skipped_oversized)
                        last_report = time.time()

                    mtime = _epoch(msg.get("receivedDateTime"))
                    if state.is_unchanged(state_db, state_key, mtime):
                        skipped_unchanged += 1
                        continue

                    future = executor.submit(fetch_one, user, msg["id"])
                    in_flight[future] = (msg.get("subject") or "", mtime, state_key, msg.get("webLink") or "")

                    if len(in_flight) >= max_in_flight:
                        done, _ = wait(in_flight.keys(), return_when=FIRST_COMPLETED)
                        for f in done:
                            handle_result(f, *in_flight.pop(f))

                final_delta = body.get("@odata.deltaLink", final_delta)

            for f in as_completed(list(in_flight)):
                handle_result(f, *in_flight[f])
            flush_batch()

            if final_delta and folder_failures == 0:
                save_delta(state_db, name, folder_id, final_delta, full_crawl_at)
                state_db.commit()
            elif folder_failures:
                print(f"  {folder_failures} message(s) failed in '{folder_path}' -- delta token not advanced, will retry next run")

    if PROPAGATE_DELETES:
        to_delete = pending_deletes - seen   # a "removed" message that reappeared in another folder was just moved
        if to_delete:
            delete_docs(to_delete)
            state.forget(state_db, to_delete)
            print(f"  removed {len(to_delete)} deleted/moved-out messages from the index")

    status.share_progress(name, discovered, total_indexed, 0, skipped_unchanged, extraction_timeouts, skipped_oversized)
    if skipped_unchanged:
        print(f"  skipped {skipped_unchanged} unchanged messages")
    if skipped_oversized:
        print(f"  skipped {skipped_oversized} messages over the {MAX_MESSAGE_BYTES // (1024 * 1024)}MB size limit")
    if extraction_timeouts:
        print(f"  {extraction_timeouts} messages hit the extraction timeout")
    return total_indexed


def run() -> None:
    start_watchdog()
    ensure_index_exists()
    state_db = state.init_state_db()
    init_tables(state_db)
    status.job_started(
        [m["name"] for m in MAILBOXES],
        smb_workers=GRAPH_WORKERS,
        exclude_extensions=[],
        exclude_no_extension=False,
        job_type="exchange",
    )
    grand_total = 0

    for mb in MAILBOXES:
        print(f"Processing mailbox '{mb['name']}' ({mb['user']})")
        try:
            count = process_mailbox(mb, state_db)
            grand_total += count
            status.share_finished(mb["name"], count)
            print(f"  finished '{mb['name']}': {count} documents indexed")
        except Exception as exc:
            status.share_failed(mb["name"], str(exc))
            print(f"  failed on '{mb['name']}': {exc}")

    state_db.close()
    print(f"Total indexed across all mailboxes: {grand_total}")
    status.job_finished()
    # Non-zero exit so the scheduler and monitoring see the failure; the
    # status page shows which mailbox and why.
    failed = status.failed_sources()
    if failed:
        sys.exit(f"{len(failed)} mailbox(s) failed: {', '.join(failed)}")


if __name__ == "__main__":
    run()
