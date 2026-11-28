"""Unit tests for SMB ACL -> role mapping (pelican/smb_acl.py).

    python -m unittest discover -s tests/unit

Needs pyyaml only: smbcacls and rpcclient are faked, and the modules that
need smbprotocol are stubbed.
"""

import os
import subprocess
import sys
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

# smb_acl's imports that pull in smbprotocol or write status files.
_smb_shares = types.ModuleType("pelican.smb_shares")
_smb_shares.credentials = lambda share: ("svc", "secret", "EXAMPLE")
_status = types.ModuleType("pelican.status")
_status.acl_progress = lambda *a, **k: None
_watchdog = types.ModuleType("pelican.watchdog")
_watchdog.heartbeat = lambda *a, **k: None
for name, module in (("pelican.smb_shares", _smb_shares), ("pelican.status", _status),
                     ("pelican.watchdog", _watchdog)):
    sys.modules[name] = module

import pelican  # noqa: E402
pelican.smb_shares, pelican.status, pelican.watchdog = _smb_shares, _status, _watchdog
from pelican import roles, smb_acl  # noqa: E402

DOM = "S-1-5-21-4114027263-3485176606-1447376589"
SIDS = {
    f"{DOM}-1105": ("EXAMPLE\\Alice", 1),
    f"{DOM}-1103": ("EXAMPLE\\Finance", 2),
    f"{DOM}-513": ("EXAMPLE\\Domain Users", 2),
    f"{DOM}-1200": ("EXAMPLE\\FILES1$", 9),
    "S-1-5-32-544": ("BUILTIN\\Administrators", 4),
    "S-1-3-0": ("\\CREATOR OWNER", 5),
    "S-1-1-0": ("\\Everyone", 5),
    "S-1-5-11": ("NT AUTHORITY\\Authenticated Users", 5),
}
SHARE = {"name": "files", "server": "files1.example.local", "share": "data"}


class FakeServer:
    """Answers smbcacls --numeric and rpcclient lookupsids like Samba does."""

    def __init__(self, aces, connect_ok=True):
        self.aces = aces
        self.connect_ok = connect_ok
        self.lookups: list[list[str]] = []

    def run(self, args, **kwargs):
        if args[0] == "smbcacls":
            assert "--numeric" in args
            out = "REVISION:1\nCONTROL:SR|DP\nOWNER:S-1-5-32-544\n" + \
                "".join(f"ACL:{sid}:{t}/0x3/0x001f01ff\n" for sid, t in self.aces)
            return subprocess.CompletedProcess(args, 0, out, "")
        assert args[0] == "rpcclient"
        if not self.connect_ok:
            return subprocess.CompletedProcess(
                args, 1, "Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE\n", "")
        sids = args[args.index("-c") + 1].split()[1:]
        self.lookups.append(sids)
        if any(s.startswith("S-1-22-") for s in sids):
            return subprocess.CompletedProcess(args, 1, "result was NT_STATUS_INVALID_SID\n", "")
        lines = []
        for sid in sids:
            name, sid_type = SIDS.get(sid, ("*unknown*\\*unknown*", 8))
            lines.append(f"{sid} {name} ({sid_type})")
        return subprocess.CompletedProcess(args, 0, "\n".join(lines) + "\n", "")


class AclRoleTests(unittest.TestCase):
    def setUp(self):
        smb_acl._sid_cache.clear()
        smb_acl._acl_cache.clear()

    def roles_for(self, aces, **kw):
        server = FakeServer(aces, **kw)
        with mock.patch.object(smb_acl.subprocess, "run", server.run):
            return smb_acl._query_acl_raising(SHARE, "\\Finance"), server

    def test_user_gets_user_prefix_and_group_gets_group_prefix(self):
        found, _ = self.roles_for([(f"{DOM}-1105", 0), (f"{DOM}-1103", 0)])
        self.assertEqual(found, [roles.user_role("alice"), roles.group_role("Finance")])
        self.assertEqual(found, ["1alice", "2Finance"])

    def test_builtin_well_known_and_computer_stay_groups(self):
        found, _ = self.roles_for([("S-1-5-32-544", 0), ("S-1-3-0", 0), (f"{DOM}-1200", 0),
                                   (f"{DOM}-513", 0)])
        self.assertEqual(found, ["2Administrators", "2CREATOR OWNER", "2FILES1$", "2Domain Users"])

    def test_everyone_and_authenticated_users(self):
        found, server = self.roles_for([("S-1-1-0", 0), ("S-1-5-11", 0)])
        self.assertEqual(found, [roles.EVERYONE])
        self.assertEqual(server.lookups, [])

    def test_denied_entries_are_skipped(self):
        found, _ = self.roles_for([(f"{DOM}-1105", 1), (f"{DOM}-1103", 6), (f"{DOM}-513", 0)])
        self.assertEqual(found, ["2Domain Users"])

    def test_only_denied_entries_restrict(self):
        found, _ = self.roles_for([(f"{DOM}-1105", 1)])
        self.assertEqual(found, [roles.RESTRICTED])

    def test_unix_sid_does_not_spoil_the_batch(self):
        found, server = self.roles_for([(f"{DOM}-1105", 0), ("S-1-22-2-0", 0)])
        self.assertEqual(found, ["1alice", "2S-1-22-2-0"])
        self.assertNotIn("S-1-22-2-0", sum(server.lookups, []))

    def test_unknown_sid_keeps_raw_sid_as_group(self):
        found, _ = self.roles_for([(f"{DOM}-9999", 0)])
        self.assertEqual(found, [f"2{DOM}-9999"])

    def test_one_bad_sid_falls_back_to_single_lookups(self):
        bad = "S-1-22-1-1000"
        server = FakeServer([])
        with mock.patch.object(smb_acl, "_UNRESOLVABLE_SID_PREFIX", "S-1-99-"), \
                mock.patch.object(smb_acl.subprocess, "run", server.run):
            names = smb_acl._resolve_sids(SHARE, [f"{DOM}-1105", bad])
        self.assertEqual(names[f"{DOM}-1105"], ("Alice", 1))
        self.assertEqual(names[bad], (bad, 8))
        self.assertEqual(server.lookups, [[f"{DOM}-1105", bad], [f"{DOM}-1105"], [bad]])

    def test_lookups_are_cached(self):
        server = FakeServer([(f"{DOM}-1105", 0), (f"{DOM}-1103", 0)])
        with mock.patch.object(smb_acl.subprocess, "run", server.run):
            smb_acl._query_acl_raising(SHARE, "\\Finance")
            smb_acl._query_acl_raising(SHARE, "\\Finance\\2001")
        self.assertEqual(len(server.lookups), 1)

    def test_lookup_connection_failure_is_a_lookup_problem(self):
        with self.assertRaises(smb_acl.AclLookupProblem):
            self.roles_for([(f"{DOM}-1105", 0)], connect_ok=False)
        self.assertEqual(smb_acl._sid_cache, {})

    def test_errors_never_carry_the_password(self):
        def failing(exc):
            def run(args, **kwargs):
                raise exc(args)
            return run
        cases = [
            ("smbcacls", lambda a: subprocess.CalledProcessError(1, a, "NT_STATUS_ACCESS_DENIED", "")),
            ("smbcacls", lambda a: subprocess.TimeoutExpired(a, 15)),
        ]
        for _, make in cases:
            with mock.patch.object(smb_acl.subprocess, "run", failing(make)), \
                    self.assertRaises(smb_acl.AclLookupProblem) as caught:
                smb_acl._query_acl_raising(SHARE, "\\Finance")
            self.assertNotIn("secret", str(caught.exception))
        with mock.patch.object(smb_acl.subprocess, "run", failing(lambda a: subprocess.TimeoutExpired(a, 15))), \
                self.assertRaises(smb_acl.AclLookupProblem) as caught:
            smb_acl._resolve_sids(SHARE, [f"{DOM}-1105"])
        self.assertNotIn("secret", str(caught.exception))

    def test_failed_lookup_restricts_new_documents(self):
        server = FakeServer([(f"{DOM}-1105", 0)], connect_ok=False)
        with mock.patch.object(smb_acl.subprocess, "run", server.run):
            self.assertEqual(smb_acl.roles_for_path(SHARE, "Finance\\a.txt"), [roles.RESTRICTED])


if __name__ == "__main__":
    unittest.main()
