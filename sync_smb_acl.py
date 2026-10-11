"""
Standalone ACL drift-detection job for SMB shares, run in its own container
on its own schedule, next to the crawl_smb.py container whose state volume it
shares.

Doesn't walk any share or fetch any file. The set of directories to check per
share comes straight from smb_acl_group_roles in that state DB -- the crawler
registers each directory the first time it walks it (record_new_acl_groups)
and forgets ones that have gone. So a brand-new directory is only picked up
after the next crawl of its share, the same point at which its documents
first exist anyway.

Set SHARE_NAMES to the same subset as the crawler sharing this state volume.
"""

from pelican import roles as role_store
from pelican import smb_acl, smb_shares, state, status
from pelican.index import SEARCH_INDEX, client
from pelican.watchdog import heartbeat, start_watchdog


def run() -> None:
    start_watchdog()
    shares = smb_shares.selected_shares()
    state_db = state.init_state_db()
    role_store.init_roles_table(state_db, smb_acl.ACL_ROLES_TABLE)
    status.job_started([s["name"] for s in shares], job_type="acl")

    for share in shares:
        name = share["name"]
        status.share_started(name)
        heartbeat(f"ACL sync started for '{name}'")
        prefix = f"{name}\x1f"
        group_keys = [s[len(prefix):] for s in role_store.list_sources(state_db, smb_acl.ACL_ROLES_TABLE, prefix)]
        print(f"Processing share '{name}': {len(group_keys)} known director{'y' if len(group_keys) == 1 else 'ies'}")
        try:
            smb_acl.sync_acl_changes(client, SEARCH_INDEX, share, group_keys, state_db)
            status.share_finished(name, 0)
        except Exception as exc:
            status.share_failed(name, str(exc))
            print(f"  failed on '{name}': {exc}")

    state_db.close()
    status.job_finished()


if __name__ == "__main__":
    run()
