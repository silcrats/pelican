"""
Test connection for one source, as the admin portal's "Test" button: signs
in the way its crawler would and reads a little, without indexing anything.

    python check_source.py <smb|exchange|sharepoint> <name>

Reads the source from the same config file and variables as its crawler
(the worker sets SHARES_CONFIG / EXCHANGE_CONFIG / SHAREPOINT_CONFIG and
SHARE_NAMES / MAILBOX_NAMES / SITE_NAMES). The last line printed is the
result; exit status 0 means it worked.
"""

import os
import sys


def check_smb(name: str) -> str:
    from pelican import smb_acl, smb_shares
    share = next((s for s in smb_shares.selected_shares() if s["name"] == name), None)
    if share is None:
        raise RuntimeError(f"no SMB share named {name} in the config")
    path = share.get("path", "")
    where = f"\\\\{share['server']}\\{share['share']}" + (f"\\{path}" if path else "")
    conn = smb_shares.connect(share)
    try:
        entries = conn.list_dir(path, timeout=float(os.environ.get("SMB_LIST_TIMEOUT_SECONDS", "120")))
    finally:
        conn.close()
    folders = sum(1 for _, is_dir, _ in entries if is_dir)
    print(f"listed {where}: {len(entries) - folders} files, {folders} folders at the top level")
    groups = smb_acl._query_acl_raising(share, "\\" + path.strip("\\"))
    print(f"permissions on the top folder: {', '.join(groups) if groups else 'none readable'}")
    return f"OK: signed in to {where}, listed {len(entries)} entries and read its permissions"


def check_exchange(name: str) -> str:
    import crawl_exchange as ex
    mb = next((m for m in ex.MAILBOXES if m["name"] == name), None)
    if mb is None:
        raise RuntimeError(f"no mailbox named {name} in the config")
    exclude = {f.lower() for f in mb.get("exclude_folders", ex._config.get("exclude_folders", []))}
    folders = list(ex.list_folders(mb["user"], exclude))
    print(f"mailbox {mb['user']}: {len(folders)} folders to crawl")
    if mb.get("full_access", True):
        roles, problem = ex.full_access_roles(mb)
        if problem:
            print(f"Full Access list: not available ({problem}); the crawler keeps the last known access")
        else:
            print(f"Full Access list: {len(roles or [])} people or groups")
    return f"OK: read {mb['user']}'s folder list through Graph"


def check_sharepoint(name: str) -> str:
    import crawl_sharepoint as sp
    cfg = next((s for s in sp.SITES if s["name"] == name), None)
    if cfg is None:
        raise RuntimeError(f"no site named {name} in the config")
    site = sp.resolve_site(cfg["url"])
    only = {l.lower() for l in cfg.get("libraries", [])}
    exclude = {l.lower() for l in cfg.get("exclude_libraries", sp.DEFAULT_EXCLUDE_LIBRARIES)}
    libraries = sp.list_libraries(site["id"], only, exclude)
    print(f"site {site.get('displayName')}: libraries {', '.join(d.get('name', '') for d in libraries) or 'none'}")
    if not libraries:
        raise RuntimeError("no document libraries to crawl -- check the library lists")
    return f"OK: found the site and {len(libraries)} document librar{'y' if len(libraries) == 1 else 'ies'}"


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in ("smb", "exchange", "sharepoint"):
        print(__doc__)
        return 2
    kind, name = sys.argv[1:]
    try:
        print({"smb": check_smb, "exchange": check_exchange, "sharepoint": check_sharepoint}[kind](name))
        return 0
    except Exception as exc:
        print(f"FAILED: {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
