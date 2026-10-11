"""
SharePoint Online -> OpenSearch crawler (Microsoft Graph), companion to
crawl_smb.py (SMB) and crawl_exchange.py (mail). Writes into the shared index
with the same document schema, so a search UI sees files, mail and SharePoint
together.

  * Only the sites listed in config/sharepoint.yaml are crawled. The app is granted
    read access to each one individually (Graph "Sites.Selected"), so it can't
    read anything else.
  * Each document library is enumerated with a Graph delta query; the deltaLink is
    stored in the state DB only after every file in that library was handled, so a
    crash or failed download just replays the library next run (unchanged files are
    skipped by last-modified time).
  * Files are downloaded and passed to extract_text() by extension -- the same code
    path as the SMB crawler, so PDFs, .docx, .eml/.msg and plain text get body text
    and everything else is indexed by name.
  * Who can see a site's files: the members and owners of the site's Microsoft 365
    group (the site's "Members"/"Owners"), mapped to AD names via Entra, plus any
    hand-written `permissions:` in sharepoint.yaml. If the roles change, documents
    already indexed are updated in place. See resolve_roles().
"""

import os
import re
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor, FIRST_COMPLETED, wait, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlparse

import requests

from pelican import roles as role_store
from pelican import settings, state, status
from pelican.extract_text import extract_text
from pelican.graph_client import GraphClient
from pelican.index import SEARCH_INDEX, build_doc, bulk_index, client, delete_docs, ensure_index_exists
from pelican.watchdog import heartbeat, start_watchdog

SHAREPOINT_CONFIG_PATH = settings.config_path("SHAREPOINT_CONFIG", "sharepoint.yaml")
SP_WORKERS = int(os.environ.get("SP_WORKERS", "4"))
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "50"))
HOST_TYPE = settings.HOST_SHAREPOINT          # written to each document's `host` field
ROLES_TABLE = "sharepoint_roles"
GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")

_config = settings.load_yaml(SHAREPOINT_CONFIG_PATH)

SITES = _config.get("sites") or []

# Optional: restrict this instance to some sites by name (comma-separated),
# mirroring SHARE_NAMES / MAILBOX_NAMES in the other crawlers.
_names_filter = os.environ.get("SITE_NAMES", "").strip()
if _names_filter:
    _wanted = {n.strip() for n in _names_filter.split(",") if n.strip()}
    _unknown = _wanted - {s["name"] for s in SITES}
    if _unknown:
        raise ValueError(f"SITE_NAMES references sites not in {SHAREPOINT_CONFIG_PATH}: {sorted(_unknown)}")
    SITES = [s for s in SITES if s["name"] in _wanted]

_auth = _config.get("auth") or {}
graph = GraphClient(
    tenant_env=_auth.get("tenant_id_env", "GRAPH_TENANT_ID"),
    client_id_env=_auth.get("client_id_env", "GRAPH_CLIENT_ID"),
    secret_env=_auth.get("secret_env", "GRAPH_SECRET"),
    authority=_auth.get("authority", "https://login.microsoftonline.com"),
    endpoint=_auth.get("graph_endpoint", "https://graph.microsoft.com/v1.0"),
    scope=_auth.get("scope", "https://graph.microsoft.com/.default"),
    max_retries=int(os.environ.get("GRAPH_MAX_RETRIES", "8")),
)

DEFAULT_INCLUDE_EXTENSIONS = {e.lower().lstrip(".") for e in _config.get("include_extensions", [])}
DEFAULT_EXCLUDE_EXTENSIONS = {e.lower().lstrip(".") for e in _config.get("exclude_extensions", [])}
DEFAULT_EXCLUDE_NO_EXTENSION = _config.get("exclude_no_extension", False)
DEFAULT_EXCLUDE_LIBRARIES = {l.lower() for l in _config.get("exclude_libraries", [
    "Preservation Hold Library", "Style Library", "Form Templates"])}
MAX_FILE_BYTES = int(_config.get("max_file_mb", 200)) * 1024 * 1024
PROPAGATE_DELETES = bool(_config.get("propagate_deletes", True))
FULL_RECRAWL_SECONDS = float(_config.get("full_recrawl_days", 30)) * 86400


# --------------------------------------------------------------- state (delta)

def init_tables(db: sqlite3.Connection) -> None:
    db.execute("""
        CREATE TABLE IF NOT EXISTS sharepoint_delta (
            site TEXT,
            drive_id TEXT,
            delta_link TEXT,
            updated_at REAL,
            full_crawl_at REAL,
            PRIMARY KEY (site, drive_id)
        )
    """)
    db.commit()
    role_store.init_roles_table(db, ROLES_TABLE)


def get_delta(db: sqlite3.Connection, site: str, drive_id: str):
    return db.execute(
        "SELECT delta_link, full_crawl_at FROM sharepoint_delta WHERE site = ? AND drive_id = ?",
        (site, drive_id),
    ).fetchone()


def save_delta(db: sqlite3.Connection, site: str, drive_id: str, link: str, full_crawl_at: float) -> None:
    db.execute(
        "INSERT OR REPLACE INTO sharepoint_delta (site, drive_id, delta_link, updated_at, full_crawl_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (site, drive_id, link, time.time(), full_crawl_at),
    )


def delete_delta(db: sqlite3.Connection, site: str, drive_id: str) -> None:
    db.execute("DELETE FROM sharepoint_delta WHERE site = ? AND drive_id = ?", (site, drive_id))
    db.commit()


# ------------------------------------------------------------------- helpers

def _epoch(iso: str | None) -> float:
    if not iso:
        return 0.0
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone(timezone.utc).timestamp()


def _since_epoch(since) -> float:
    if not since:
        return 0.0
    s = str(since)
    return _epoch(s + "T00:00:00Z" if len(s) == 10 else s)


def resolve_site(url: str) -> dict:
    """Look up a site by its URL. Works only for sites the app has been granted."""
    parsed = urlparse(url)
    path = parsed.path.rstrip("/")
    api = f"{graph.endpoint}/sites/{parsed.hostname}" + (f":{quote(path, safe='/')}" if path else "")
    resp = graph.request(api, params={"$select": "id,displayName,webUrl"})
    try:
        if resp.status_code in (401, 403):
            raise RuntimeError(
                f"Graph refused access to {url} (HTTP {resp.status_code}) -- the app needs the Graph "
                "Sites.Selected permission AND a per-site 'read' grant on this site")
        if resp.status_code == 404:
            raise RuntimeError(f"Site not found (or not granted to the app): {url}")
        resp.raise_for_status()
        return resp.json()
    finally:
        resp.close()


def list_libraries(site_id: str, only: set[str], exclude: set[str]) -> list[dict]:
    libraries = []
    url = f"{graph.endpoint}/sites/{quote(site_id, safe=',')}/drives"
    for body in graph.pages(url, {"$select": "id,name,driveType,webUrl"}):
        for drive in body.get("value", []):
            lib_name = (drive.get("name") or "").lower()
            if drive.get("driveType") != "documentLibrary":
                continue
            if only and lib_name not in only:
                continue
            if lib_name in exclude:
                continue
            libraries.append(drive)
    missing = only - {(d.get("name") or "").lower() for d in libraries}
    if missing:
        print(f"  warning: librar{'y' if len(missing) == 1 else 'ies'} not found on this site: {sorted(missing)}")
    return libraries


# --------------------------------------------------------- who can see a site

class LookupProblem(Exception):
    """A lookup failed for a reason that says nothing about the people involved
    (permission missing, throttling, outage) -- so access must not be changed."""


def _lookup_problem(exc: Exception, doing: str, permission: str) -> LookupProblem:
    code = getattr(getattr(exc, "response", None), "status_code", None)
    if code in (401, 403):
        return LookupProblem(f"Graph refused {doing} (HTTP {code}) -- the app needs the {permission} "
                             "application permission with admin consent")
    return LookupProblem(f"{doing} failed: {exc}")


def find_group(cfg: dict, site: dict) -> tuple[str | None, str]:
    """(group id, label) of the Microsoft 365 group behind a team site, or (None, why).
    Uses `group:` from the config (an id or mail nickname) if given; otherwise the
    site URL name (/sites/Engineering -> nickname "Engineering")."""
    hint = cfg.get("group")
    if hint and GUID_RE.match(str(hint)):
        return str(hint), str(hint)
    nickname = str(hint) if hint else None
    if not nickname:
        parts = [p for p in urlparse(site.get("webUrl") or cfg["url"]).path.split("/") if p]
        if len(parts) >= 2 and parts[0].lower() in ("sites", "teams"):
            nickname = parts[1]
    if not nickname:
        return None, "the site URL doesn't identify a Microsoft 365 group (e.g. the root site)"

    escaped = nickname.replace("'", "''")
    found = []
    try:
        params = {"$filter": f"mailNickname eq '{escaped}'", "$select": "id,displayName,groupTypes,mailNickname"}
        for body in graph.pages(f"{graph.endpoint}/groups", params):
            found += [g for g in body.get("value", []) if "Unified" in (g.get("groupTypes") or [])]
    except requests.RequestException as exc:
        raise _lookup_problem(exc, f"looking up the group '{nickname}'", "Group.Read.All") from None
    if len(found) != 1:
        return None, f"no Microsoft 365 group with the name '{nickname}' (set `group:` if it differs from the site URL)"
    return found[0]["id"], found[0].get("displayName") or nickname


def mirrored_roles(cfg: dict, site: dict) -> list[str] | None:
    """Roles for the members and owners of the site's Microsoft 365 group, mapped
    to AD names through Entra. None if the site has no group (nothing to mirror).
    Raises LookupProblem if the lookup can't be trusted."""
    name = cfg["name"]
    group_id, label = find_group(cfg, site)
    if not group_id:
        print(f"  '{name}': no group to mirror -- {label}")
        return None

    found: set[str] = set()
    notes: list[str] = []
    kinds = (
        ("user", "microsoft.graph.user", "id,userPrincipalName,onPremisesSamAccountName"),
        ("group", "microsoft.graph.group", "id,displayName,onPremisesDistinguishedName"),
    )
    for relation in ("members", "owners"):
        for kind, cast, select in kinds:
            if relation == "owners" and kind == "group":
                continue   # a group's owners can only be users/service principals; asking for groups is a 400
            url = f"{graph.endpoint}/groups/{quote(group_id, safe='')}/{relation}/{cast}"
            try:
                for body in graph.pages(url, {"$select": select}):
                    for obj in body.get("value", []):
                        if kind == "user":
                            sam = obj.get("onPremisesSamAccountName")
                            if sam:
                                found.add(role_store.user_role(sam))
                            else:
                                notes.append(f"{obj.get('userPrincipalName') or obj.get('id')} (no AD account)")
                        else:
                            cn = role_store.cn_from_dn(obj.get("onPremisesDistinguishedName"))
                            if cn:
                                found.add(role_store.group_role(cn))
                            else:
                                notes.append(f"group {obj.get('displayName') or obj.get('id')} (not synced from AD)")
            except requests.RequestException as exc:
                raise _lookup_problem(exc, f"reading the {relation} of group '{label}'", "Group.Read.All") from None
    print(f"  '{name}': mirroring Microsoft 365 group '{label}'")
    if notes:
        print(f"  note: {len(notes)} member(s) of that group get no search access: " + "; ".join(sorted(set(notes))))
    return sorted(found)


def resolve_roles(cfg: dict, site: dict, state_db: sqlite3.Connection) -> list[str]:
    """The roles to stamp on this site's documents: the site group's members and
    owners (if mirroring) + anything written by hand in sharepoint.yaml. If access
    changed since the last run, already-indexed documents are updated too.

    Fails safe: if the group lookup errors, the last known roles are kept -- access
    is never widened or wiped because a lookup failed. A site with no way to tell who
    may see it is restricted."""
    name = cfg["name"]
    stored = role_store.get_stored_roles(state_db, ROLES_TABLE, name)
    mirrored, problem = None, None
    if cfg.get("mirror_members", True):
        try:
            mirrored = mirrored_roles(cfg, site)
        except LookupProblem as exc:
            problem = str(exc)

    if mirrored is not None:
        site_roles = sorted(set(role_store.static_roles(cfg)) | set(mirrored))
    elif problem and stored is not None:
        print(f"  {problem} -- keeping the last known roles for '{name}'")
        return stored
    else:
        if problem:
            print(f"  {problem} -- using only the roles from sharepoint.yaml")
        site_roles = sorted(set(role_store.static_roles(cfg)))
    if not site_roles:
        print(f"  nobody is granted access to '{name}' (no group members and no `permissions:`) -- "
              "restricted; set `group:` or `permissions:` in sharepoint.yaml")
    site_roles = site_roles or [role_store.RESTRICTED]  # restrict rather than accidentally open up

    shown = role_store.summarize(site_roles)
    if stored is None or sorted(stored) != site_roles:
        print(f"  access for '{name}' {'set' if stored is None else 'changed'}: {shown}")
        updated = role_store.apply_roles_to_indexed_docs(
            client, SEARCH_INDEX, name, HOST_TYPE, site_roles, on_progress=heartbeat
        )  # raises -> site reported failed, retried next run
        print(f"  updated roles on {updated} already-indexed document(s)")
        status.acl_progress(name, 1 if updated else 0, updated)
        role_store.save_stored_roles(state_db, ROLES_TABLE, name, site_roles)
    else:
        print(f"  access for '{name}' unchanged: {shown}")
    return site_roles


# ------------------------------------------------------------------- crawling

def fetch_one(drive_id: str, item_id: str, filename: str, site_name: str) -> tuple[str, dict, int]:
    """Runs in a worker thread. Returns (extracted_text, email_meta, raw_size).
    /content answers with a redirect to a short-lived download URL, which requests
    follows (and drops the Authorization header when the host changes)."""
    url = f"{graph.endpoint}/drives/{quote(drive_id, safe='')}/items/{quote(item_id, safe='')}/content"
    resp = graph.request(url, stream=True)
    try:
        resp.raise_for_status()
        buf = bytearray()
        for chunk in resp.iter_content(1 << 20):
            buf.extend(chunk)
            if len(buf) > MAX_FILE_BYTES:
                raise ValueError(f"file too large (>{MAX_FILE_BYTES} bytes)")
    finally:
        resp.close()
    data = bytes(buf)
    text, email_meta = extract_text(f"sharepoint\\{site_name}\\{filename}", data)
    return text, email_meta, len(data)


def process_site(cfg: dict, state_db: sqlite3.Connection) -> int:
    name = cfg["name"]
    status.share_started(name)
    heartbeat(f"started '{name}'")
    site = resolve_site(cfg["url"])
    print(f"  site: {site.get('displayName')} ({site.get('webUrl')})")
    site_roles = resolve_roles(cfg, site, state_db)

    # Whitelist mode (include_extensions set, global or per-site) takes over entirely
    # when present: only those extensions are crawled, and exclude_extensions /
    # exclude_no_extension are ignored -- a SharePoint document library can contain
    # an unbounded, ever-changing variety of "web" file types (a library holding a
    # web project's source, say), which a blacklist can never keep up with.
    include_ext = {e.lower().lstrip(".") for e in cfg.get("include_extensions", DEFAULT_INCLUDE_EXTENSIONS)}
    exclude_ext = {e.lower().lstrip(".") for e in cfg.get("exclude_extensions", DEFAULT_EXCLUDE_EXTENSIONS)}
    exclude_no_ext = cfg.get("exclude_no_extension", DEFAULT_EXCLUDE_NO_EXTENSION)
    only_libs = {l.lower() for l in cfg.get("libraries", [])}
    exclude_libs = {l.lower() for l in cfg.get("exclude_libraries", DEFAULT_EXCLUDE_LIBRARIES)}
    since_epoch = _since_epoch(cfg.get("since", _config.get("since")))

    libraries = list_libraries(site["id"], only_libs, exclude_libs)
    if not libraries:
        raise RuntimeError("no document libraries to crawl -- check `libraries:` / `exclude_libraries:`")

    actions: list[dict] = []
    seen: set[str] = set()              # every file key encountered this run (indexed or skipped)
    pending_deletes: set[str] = set()   # applied at the end, minus anything seen
    discovered = total_indexed = skipped_excluded = skipped_unchanged = extraction_timeouts = skipped_oversized = 0
    batch_num = 0
    last_report = time.time()
    lib_state = {"failures": 0}

    def flush_batch() -> None:
        nonlocal batch_num, total_indexed, actions
        if not actions:
            return
        batch_num += 1
        bulk_index(actions)
        total_indexed += len(actions)
        state_db.commit()
        heartbeat(f"indexed batch {batch_num} of '{cfg['name']}'")
        print(f"  batch {batch_num}: indexed {len(actions)} docs (running total {total_indexed})")
        actions = []

    def handle_result(future, filename: str, mtime: float, state_key: str, web_url: str) -> None:
        nonlocal actions, extraction_timeouts
        try:
            text, email_meta, raw_size = future.result()
        except Exception as exc:
            print(f"  fetch failed for '{filename}' ({state_key}): {exc}")
            lib_state["failures"] += 1
            return
        if email_meta.get("extraction_timeout"):
            extraction_timeouts += 1
        # url = what a user clicks (the file in SharePoint); _id comes from the stable
        # ID-based key so renames and moves don't create duplicates.
        actions.append(build_doc(web_url or state_key, filename, text, site_roles, raw_size, email_meta,
                                 name, mtime, host=HOST_TYPE, id_key=state_key))
        state.record_indexed(state_db, state_key, mtime)
        if len(actions) >= BATCH_SIZE:
            flush_batch()

    with ThreadPoolExecutor(max_workers=SP_WORKERS) as executor:
        max_in_flight = SP_WORKERS * 4

        for library in libraries:
            drive_id = library["id"]
            print(f"  library '{library.get('name')}'")
            in_flight: dict = {}

            for attempt in (1, 2):
                row = get_delta(state_db, name, drive_id)
                now = time.time()
                if attempt == 1 and row and row[0] and (now - (row[1] or 0)) < FULL_RECRAWL_SECONDS:
                    url, full_crawl_at = row[0], row[1]                     # incremental
                else:
                    url = f"{graph.endpoint}/drives/{quote(drive_id, safe='')}/root/delta"
                    full_crawl_at = now                                     # full (re)enumeration
                lib_state["failures"] = 0
                final_delta = None

                try:
                    for body in graph.pages(url):
                        for item in body.get("value", []):
                            state_key = f"sharepoint://{drive_id}/{item['id']}"
                            if "deleted" in item:
                                pending_deletes.add(state_key)
                                continue
                            if "file" not in item:          # folders, the library root
                                continue
                            seen.add(state_key)
                            discovered += 1

                            if time.time() - last_report > 3:
                                heartbeat(f"discovering '{name}' ({discovered} so far)")
                                print(f"  [diag] discovered {discovered} files so far, {len(in_flight)} in flight, {total_indexed} indexed")
                                status.share_progress(name, discovered, total_indexed, skipped_excluded,
                                                      skipped_unchanged, extraction_timeouts, skipped_oversized)
                                last_report = time.time()

                            filename = item.get("name") or item["id"]
                            ext = Path(filename).suffix.lstrip(".").lower()
                            if include_ext:
                                if ext not in include_ext:   # covers no-extension files too (ext == "")
                                    skipped_excluded += 1
                                    continue
                            elif (ext and ext in exclude_ext) or (not ext and exclude_no_ext):
                                skipped_excluded += 1
                                continue
                            size = int(item.get("size") or 0)
                            if size > MAX_FILE_BYTES:
                                print(f"  skipping '{filename}': {size / 1048576:.0f} MB is over max_file_mb")
                                skipped_oversized += 1
                                continue
                            mtime = _epoch(item.get("lastModifiedDateTime"))
                            if since_epoch and mtime < since_epoch:
                                skipped_excluded += 1
                                continue
                            if state.is_unchanged(state_db, state_key, mtime):
                                skipped_unchanged += 1
                                continue

                            future = executor.submit(fetch_one, drive_id, item["id"], filename, name)
                            in_flight[future] = (filename, mtime, state_key, item.get("webUrl") or "")

                            if len(in_flight) >= max_in_flight:
                                done, _ = wait(in_flight.keys(), return_when=FIRST_COMPLETED)
                                for f in done:
                                    handle_result(f, *in_flight.pop(f))

                        final_delta = body.get("@odata.deltaLink", final_delta)
                except requests.HTTPError as exc:
                    if attempt == 1 and exc.response is not None and exc.response.status_code == 410:
                        # The saved delta token expired: forget it and list the library afresh.
                        print("  delta token expired -- re-listing this library from scratch")
                        delete_delta(state_db, name, drive_id)
                        continue
                    raise
                break

            for f in as_completed(list(in_flight)):
                handle_result(f, *in_flight[f])
            flush_batch()

            if final_delta and lib_state["failures"] == 0:
                save_delta(state_db, name, drive_id, final_delta, full_crawl_at)
                state_db.commit()
            elif lib_state["failures"]:
                print(f"  {lib_state['failures']} file(s) failed in '{library.get('name')}' -- delta token not advanced, will retry next run")

    if PROPAGATE_DELETES:
        to_delete = pending_deletes - seen   # an id that was "deleted" in one place but seen elsewhere isn't gone
        if to_delete:
            delete_docs(to_delete)
            state.forget(state_db, to_delete)
            print(f"  removed {len(to_delete)} deleted files from the index")

    status.share_progress(name, discovered, total_indexed, skipped_excluded, skipped_unchanged,
                          extraction_timeouts, skipped_oversized)
    if skipped_excluded:
        print(f"  skipped {skipped_excluded} excluded files")
    if skipped_unchanged:
        print(f"  skipped {skipped_unchanged} unchanged files")
    if skipped_oversized:
        print(f"  skipped {skipped_oversized} files over the {MAX_FILE_BYTES // (1024 * 1024)}MB size limit")
    if extraction_timeouts:
        print(f"  {extraction_timeouts} files hit the PDF extraction timeout")
    return total_indexed


def run() -> None:
    start_watchdog()
    ensure_index_exists()
    state_db = state.init_state_db()
    init_tables(state_db)
    status.job_started(
        [s["name"] for s in SITES],
        smb_workers=SP_WORKERS,
        exclude_extensions=sorted(DEFAULT_EXCLUDE_EXTENSIONS),
        exclude_no_extension=DEFAULT_EXCLUDE_NO_EXTENSION,
        job_type="sharepoint",
    )
    grand_total = 0

    for cfg in SITES:
        print(f"Processing site '{cfg['name']}' ({cfg['url']})")
        try:
            count = process_site(cfg, state_db)
            grand_total += count
            status.share_finished(cfg["name"], count)
            print(f"  finished '{cfg['name']}': {count} documents indexed")
        except Exception as exc:
            status.share_failed(cfg["name"], str(exc))
            print(f"  failed on '{cfg['name']}': {exc}")

    state_db.close()
    print(f"Total indexed across all sites: {grand_total}")
    status.job_finished()


if __name__ == "__main__":
    run()
