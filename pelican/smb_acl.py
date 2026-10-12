"""
SMB access control: maps Windows/SMB ACL entries to search roles, querying
the server directly via smbcacls -- the same userspace auth path that has
proven reliable, sidestepping the kernel CIFS client entirely -- and keeps
already-indexed documents in step when a directory's ACL changes.

Mapping: a non-denied ACL entry for Everyone / Authenticated Users becomes
the `everyone` role; any other principal becomes a group role named after
it. An ACL with no usable grants (or a failed first lookup) becomes the
`restricted` role -- fail closed rather than open. See roles: in
config/pelican.yaml.

Cached per-directory rather than per-file: each smbcacls call spawns a new
process AND a new SMB session/auth handshake, which is expensive to pay for
every single file. Files usually inherit their folder's ACL, so this trades
strict per-file precision for a large speed win. A share that relies on
per-file ACL overrides should set acl_scope: file in shares.yaml.
"""

import os
import sqlite3
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import roles as role_store
from . import settings, smb_shares, status
from .watchdog import heartbeat

ACL_ROLES_TABLE = "smb_acl_group_roles"  # last-applied roles per (share, acl_group)

# A group verified within this window skips the live smbcacls call and its
# last-known roles are trusted; a real permission change is still caught within
# ACL_RECHECK_HOURS of happening. 0 disables the throttle (always check).
ACL_RECHECK_SECONDS = int(float(os.environ.get("ACL_RECHECK_HOURS", "24")) * 3600)

# Each group check spawns a fresh smbcacls process plus its own SMB auth
# handshake -- network-bound, so threads overlap well, but bounded by what the
# NAS will tolerate concurrently and the container's cpus limit.
ACL_SYNC_WORKERS = int(os.environ.get("ACL_SYNC_WORKERS", "8"))

_EVERYONE_PRINCIPALS = ("EVERYONE", "AUTHENTICATED USERS")

_acl_cache: dict[tuple, list[str]] = {}
_acl_cache_lock = threading.Lock()


class AclLookupProblem(Exception):
    """smbcacls itself failed (network blip, timeout, transient error) -- this
    says nothing about what the real ACL is. Raised by roles_for_acl_group so a
    caller that needs to tell "the real ACL is restricted" apart from "the
    check itself failed" can (see sync_acl_changes, which must not
    retroactively lock everyone out of content because of a transient error)."""


def _query_acl_raising(share: dict, smb_path: str) -> list[str]:
    user, password, domain = smb_shares.credentials(share)
    target = f"//{share['server']}/{share['share']}"
    auth = f"{domain}\\{user}%{password}" if domain else f"{user}%{password}"

    try:
        result = subprocess.run(
            ["smbcacls", target, smb_path, "-U", auth],
            capture_output=True, text=True, check=True, timeout=15,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise AclLookupProblem(f"smbcacls failed for {smb_path}: {exc}") from None

    found: list[str] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line.startswith("ACL:"):
            continue
        body = line[len("ACL:"):]
        principal = body.split(":", 1)[0]
        perm_part = body.split(":", 1)[1] if ":" in body else ""
        if perm_part.startswith("DENIED"):
            continue

        name = principal.split("\\")[-1]
        if name.upper() in _EVERYONE_PRINCIPALS:
            found.append(role_store.EVERYONE)
        else:
            found.append(role_store.group_role(name))

    # A principal with several entries (e.g. inherited and explicit) counts once.
    found = list(dict.fromkeys(found))
    return found or [role_store.RESTRICTED]  # a real ACL with no usable grants -- restrict rather than open up


def acl_group_key(share: dict, smb_relative_path: str) -> str:
    """The unit that shares one ACL lookup/result: the file's own path
    (acl_scope "file") or its immediate parent directory (acl_scope
    "directory", the default). Used to cache/query the ACL, and to tag each
    document with the group it belongs to, so a later permission change can be
    re-applied to every document in that group without re-downloading and
    re-extracting its content."""
    acl_scope = share.get("acl_scope", "directory")
    if acl_scope == "file":
        return smb_relative_path if smb_relative_path.startswith("\\") else "\\" + smb_relative_path
    parent_dir = smb_relative_path.rsplit("\\", 1)[0] if "\\" in smb_relative_path else ""
    return "\\" + parent_dir if parent_dir else "\\"


def roles_for_acl_group(share: dict, group_key: str) -> list[str]:
    """Roles for an ACL group, cached. RAISES AclLookupProblem on failure
    rather than falling back to restricted -- see AclLookupProblem."""
    cache_key = (share["server"], share["share"], group_key)
    with _acl_cache_lock:
        cached = _acl_cache.get(cache_key)
    if cached is not None:
        return cached
    found = _query_acl_raising(share, group_key)
    with _acl_cache_lock:
        _acl_cache[cache_key] = found
    return found


def roles_for_path(share: dict, smb_relative_path: str) -> list[str]:
    """Roles for a file being indexed for the first time (or re-fetched because
    it changed). Fail closed: a lookup failure restricts the document rather
    than leaving it world-visible. The restricted result is cached for the
    group too, so an unreachable server costs one smbcacls timeout per
    directory rather than per file; the ACL-sync job corrects it later."""
    group_key = acl_group_key(share, smb_relative_path)
    cache_key = (share["server"], share["share"], group_key)
    with _acl_cache_lock:
        cached = _acl_cache.get(cache_key)
    if cached is not None:
        return cached
    try:
        found = _query_acl_raising(share, group_key)
    except AclLookupProblem as exc:
        print(f"ACL lookup failed for {group_key}: {exc}")
        found = [role_store.RESTRICTED]
    with _acl_cache_lock:
        _acl_cache[cache_key] = found
    return found


# ------------------------------------------------------------- drift sync

def _check_and_apply_acl_group(client, index: str, share: dict, share_name: str, group_key: str,
                                stored: list[str] | None) -> tuple[str, list[str] | None, int, AclLookupProblem | None]:
    """Worker-thread body for one group: the live smbcacls check, plus the
    update_by_query apply if roles changed. Deliberately does NOT touch the
    state DB or status -- sqlite3 connections and status._write() aren't safe
    from multiple threads at once, so those stay serialized in
    sync_acl_changes' main thread. The ACL cache has its own lock."""
    try:
        found = roles_for_acl_group(share, group_key)
    except AclLookupProblem as exc:
        return group_key, None, 0, exc
    updated = 0
    if stored is not None and sorted(stored) != sorted(found):
        updated = role_store.apply_roles_to_indexed_docs(
            client, index, share_name, settings.HOST_SMB, found,
            # .keyword, not the bare field: an index whose acl_group was
            # dynamically mapped is text+keyword-subfield (the explicit mapping
            # in search_index_mapping.json only applies to a freshly-created
            # index), and a term query against the analyzed text field
            # silently matches nothing for a value with backslashes/spaces.
            extra_filters=[{"term": {"acl_group.keyword": group_key}}],
            on_progress=heartbeat,
        )
    return group_key, found, updated, None


def sync_acl_changes(client, index: str, share: dict, group_keys: list[str],
                      state_db: sqlite3.Connection) -> None:
    """Re-check `group_keys` (this share's known directories, or files for
    acl_scope: file) and re-apply roles to already-indexed documents where the
    live ACL differs from the last-applied roles. No re-download: a permission
    change doesn't change any file's content, only who may see it -- and
    doesn't touch a file's modified time, so the crawl's per-file path would
    never notice it.

    A group whose lookup fails keeps its last known roles rather than being
    restricted: a transient smbcacls error must not retroactively lock
    everyone out of content that was working fine.

    Groups verified within ACL_RECHECK_SECONDS are skipped; the rest run on an
    ACL_SYNC_WORKERS-thread pool, with all state DB and status updates done
    here in the main thread as each result comes back."""
    share_name = share["name"]
    changed_groups = 0
    docs_updated = 0
    skipped_recent = 0
    checked = 0

    to_check: dict[str, list[str] | None] = {}
    for group_key in sorted(group_keys):
        source_key = f"{share_name}\x1f{group_key}"
        stored, checked_at = role_store.get_stored_roles_with_age(state_db, ACL_ROLES_TABLE, source_key)
        if stored is not None and checked_at is not None and ACL_RECHECK_SECONDS \
                and time.time() - checked_at < ACL_RECHECK_SECONDS:
            skipped_recent += 1
            continue
        to_check[group_key] = stored

    with ThreadPoolExecutor(max_workers=ACL_SYNC_WORKERS) as executor:
        futures = {
            executor.submit(_check_and_apply_acl_group, client, index, share, share_name, group_key, stored): group_key
            for group_key, stored in to_check.items()
        }
        for future in as_completed(futures):
            group_key = futures[future]
            checked += 1
            heartbeat(f"ACL sync for '{share_name}' ({checked}/{len(to_check)}, {skipped_recent} skipped)")
            _, found, updated, exc = future.result()
            if exc is not None:
                if to_check[group_key] is not None:
                    print(f"  ACL check failed for '{group_key}': {exc} -- keeping last known roles")
                continue
            if updated:
                changed_groups += 1
                docs_updated += updated
                print(f"  ACL changed for '{group_key}': updated roles on {updated} already-indexed document(s)")
                status.acl_progress(share_name, changed_groups, docs_updated)
            # Saved unconditionally: this refreshes checked_at, which the
            # throttle above measures against next run.
            role_store.save_stored_roles(state_db, ACL_ROLES_TABLE, f"{share_name}\x1f{group_key}", found)

    skip_note = (f"; {skipped_recent} skipped (checked within the last "
                 f"{ACL_RECHECK_SECONDS // 3600}h)") if skipped_recent else ""
    print(f"  ACL sync: {changed_groups} director{'y' if changed_groups == 1 else 'ies'} "
          f"had role changes applied to {docs_updated} already-indexed document(s){skip_note}")
