"""Unit tests for the admin portal's rules and scheduler (admin/store.py).

    python -m unittest discover tests/admin

Needs pyyaml (and ldap3, requests for the other test files).
"""

import os
import sys
import tempfile
import time
import unittest

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "admin"))
import store as S  # noqa: E402

SHARES_YAML = """
exclude_extensions: [db, zip]
exclude_no_extension: true
default_credentials: {user_env: SMB_USER, pass_env: SMB_PASS, domain_env: SMB_DOMAIN}
shares:
  - name: finance
    server: files1.example.local
    share: data
    path: 'Finance'
  - name: engineering
    server: files2.example.local
    share: eng
    path: ""
    user_env: SMB_USER_ENG
    pass_env: SMB_PASS_ENG
    domain_env: SMB_DOMAIN_ENG
    acl_scope: file
"""

EXCHANGE_YAML = """
auth: {tenant_id_env: GRAPH_TENANT_ID, client_id_env: GRAPH_CLIENT_ID, secret_env: GRAPH_SECRET}
mailboxes:
  - name: accounts_exchange
    user: accounts@example.com
    permissions: {groups: [Finance]}
"""


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.st = S.Store(os.path.join(self.tmp.name, "admin.db"), admin_groups=["Pelican Admins"])
        self.changes = 0

        def changed():
            self.changes += 1
        self.st.on_change = changed
        self.admin = self.st.user("root", ["Pelican Admins"])
        self.alice = self.st.user("alice", ["Finance IT"])
        self.bob = self.st.user("bob", ["Engineering IT"])
        self.nobody = self.st.user("dave", ["Domain Users"])

    def tearDown(self):
        self.st.db.close()
        self.tmp.cleanup()

    def finance_scope(self, **extra):
        body = {"name": "Finance", "groups": ["Finance IT"], "kinds": ["smb", "exchange", "sharepoint"],
                "smb_servers": ["files1.example.local"], "credentials": ["default"],
                "grant_groups": ["Finance"], "grant_users": [], "grant_roles": [], "min_minutes": 60}
        body.update(extra)
        return self.st.save_scope(self.admin, body)

    def smb(self, name="fin-reports", server="files1.example.local", **extra):
        body = {"kind": "smb", "name": name, "config": {"server": server, "share": "data", "path": "Finance\\Reports"},
                "crawl_minutes": 360, "acl_minutes": 120}
        body.update(extra)
        return body

    # ------------------------------------------------------------ import

    def test_import_keeps_sources_settings_and_credentials(self):
        self.assertEqual(self.st.import_yaml("smb", SHARES_YAML), 2)
        self.assertEqual(self.st.import_yaml("exchange", EXCHANGE_YAML), 1)
        rendered = yaml.safe_load(self.st.render_all()["shares.yaml"])
        original = yaml.safe_load(SHARES_YAML)
        self.assertEqual(rendered, original)   # same file back, credentials included
        self.assertEqual([c["name"] for c in self.st.credentials()], ["smb_user_eng"])
        mail = yaml.safe_load(self.st.render_all()["exchange.yaml"])
        self.assertEqual(mail, yaml.safe_load(EXCHANGE_YAML))
        for s in self.st.all_sources():
            self.assertIsNone(s["scope_id"])
        self.assertEqual(self.st.all_sources("smb")[0]["acl_minutes"], 120)
        self.assertEqual(self.st.all_sources("exchange")[0]["acl_minutes"], 0)

    def test_import_skips_taken_names_and_commas(self):
        self.st.import_yaml("smb", SHARES_YAML)
        n = self.st.import_yaml("exchange", "mailboxes:\n  - {name: finance, user: a@b}\n  - {name: 'a,b', user: c@d}\n")
        self.assertEqual(n, 0)

    def test_imported_settings_edit_rejects_source_list(self):
        self.st.import_yaml("smb", SHARES_YAML)
        with self.assertRaises(S.Invalid):
            self.st.save_settings(self.admin, "smb", "shares: []\n")
        with self.assertRaises(S.Forbidden):
            self.st.save_settings(self.alice, "smb", "exclude_no_extension: false\n")
        self.st.save_settings(self.admin, "smb", "exclude_no_extension: false\n")
        self.assertEqual(self.st.settings("smb"), {"exclude_no_extension": False})

    # ------------------------------------------------------ delegation

    def test_sign_in_needs_admin_group_or_scope(self):
        self.assertTrue(self.st.may_sign_in(self.admin))
        self.assertFalse(self.st.may_sign_in(self.alice))
        self.finance_scope()
        self.assertTrue(self.st.may_sign_in(self.st.user("alice", ["finance it"])))   # case-insensitive
        self.assertFalse(self.st.may_sign_in(self.nobody))

    def test_only_super_admins_manage_scopes_and_credentials(self):
        with self.assertRaises(S.Forbidden):
            self.st.save_scope(self.alice, {"name": "x", "groups": ["Finance IT"]})
        with self.assertRaises(S.Forbidden):
            self.st.save_credential(self.alice, {"name": "p", "user_env": "A", "pass_env": "B"})
        with self.assertRaises(S.Invalid):
            self.st.save_credential(self.admin, {"name": "p", "user_env": "lower", "pass_env": "B"})
        with self.assertRaises(S.Invalid):
            self.st.save_scope(self.admin, {"name": "x", "groups": ["G"], "credentials": ["missing"]})

    def test_scoped_admin_adds_within_limits(self):
        scope = self.finance_scope()
        src = self.st.save_source(self.alice, self.smb(scope_id=scope["id"]))
        self.assertEqual(src["scope_id"], scope["id"])
        self.assertEqual(src["created_by"], "alice")

    def test_scoped_admin_cant_point_credentials_at_other_servers(self):
        scope = self.finance_scope()
        with self.assertRaisesRegex(S.Invalid, "can't crawl server"):
            self.st.save_source(self.alice, self.smb(server="evil.example.net", scope_id=scope["id"]))

    def test_scoped_admin_cant_use_other_credential_profiles(self):
        self.st.save_credential(self.admin, {"name": "eng", "user_env": "SMB_USER_ENG", "pass_env": "SMB_PASS_ENG"})
        scope = self.finance_scope()
        with self.assertRaisesRegex(S.Invalid, "credential profile"):
            self.st.save_source(self.alice, self.smb(scope_id=scope["id"], credential="eng"))
        src = self.st.save_source(self.admin, self.smb(scope_id=scope["id"], credential="eng"))
        self.assertEqual(src["credential"], "eng")
        entry = yaml.safe_load(self.st.render("smb", [src]))["shares"][0]
        self.assertEqual(entry["pass_env"], "SMB_PASS_ENG")

    def test_scoped_admin_needs_a_scope_and_one_of_theirs(self):
        self.finance_scope()
        other = self.st.save_scope(self.admin, {"name": "Eng", "groups": ["Engineering IT"], "kinds": ["smb"],
                                                "smb_servers": ["files1.example.local"], "credentials": ["default"]})
        with self.assertRaises(S.Invalid):
            self.st.save_source(self.alice, self.smb(scope_id=None))
        with self.assertRaises(S.Invalid):
            self.st.save_source(self.alice, self.smb(scope_id=other["id"]))

    def test_scoped_admin_kinds(self):
        scope = self.finance_scope(kinds=["smb"])
        with self.assertRaisesRegex(S.Invalid, "can't hold"):
            self.st.save_source(self.alice, {"kind": "exchange", "name": "mb", "scope_id": scope["id"],
                                             "config": {"user": "x@example.com"}})

    def test_grants_limited_to_scope_allowlist(self):
        scope = self.finance_scope()
        body = {"kind": "exchange", "name": "ap", "scope_id": scope["id"],
                "config": {"user": "ap@example.com", "permissions": {"groups": ["Domain Users"]}}}
        with self.assertRaisesRegex(S.Invalid, "can't grant"):
            self.st.save_source(self.alice, body)
        for roles in (["guest"],):
            body["config"]["permissions"] = {"roles": roles}
            with self.assertRaisesRegex(S.Invalid, "can't grant"):
                self.st.save_source(self.alice, body)
        body["config"]["permissions"] = {"groups": ["finance"]}   # case-insensitive match
        src = self.st.save_source(self.alice, body)
        self.assertEqual(src["config"]["permissions"], {"groups": ["finance"]})

    def test_grant_made_by_super_admin_survives_scoped_edit(self):
        scope = self.finance_scope()
        src = self.st.save_source(self.admin, {"kind": "exchange", "name": "ceo", "scope_id": scope["id"],
                                               "config": {"user": "ceo@example.com",
                                                          "permissions": {"users": ["Carol"]}}})
        self.assertEqual(src["config"]["permissions"], {"users": ["carol"]})
        edited = self.st.save_source(self.alice, {"config": {"user": "ceo@example.com", "since": "2020-01-01",
                                                             "permissions": {"users": ["carol"]}}}, src["id"])
        self.assertEqual(edited["config"]["since"], "2020-01-01")
        with self.assertRaises(S.Invalid):
            self.st.save_source(self.alice, {"config": {"user": "ceo@example.com",
                                                        "permissions": {"users": ["carol", "alice"]}}}, src["id"])

    def test_sharepoint_group_is_super_admin_only(self):
        scope = self.finance_scope()
        body = {"kind": "sharepoint", "name": "fin_sp", "scope_id": scope["id"],
                "config": {"url": "https://contoso.sharepoint.com/sites/Finance", "group": "AllStaff"}}
        with self.assertRaisesRegex(S.Invalid, "only a super admin"):
            self.st.save_source(self.alice, body)
        src = self.st.save_source(self.admin, body)
        # The scoped admin can edit other fields and leave the group as it is.
        self.st.save_source(self.alice, {"config": {**src["config"], "libraries": ["Documents"]}}, src["id"])

    def test_fixed_fields_and_name_cant_change(self):
        scope = self.finance_scope()
        src = self.st.save_source(self.alice, self.smb(scope_id=scope["id"]))
        with self.assertRaisesRegex(S.Invalid, "can't be changed"):
            self.st.save_source(self.alice, {"config": {**src["config"], "path": "Finance"}}, src["id"])
        with self.assertRaisesRegex(S.Invalid, "renamed"):
            self.st.save_source(self.alice, {"name": "other", "config": src["config"]}, src["id"])

    def test_unknown_fields_rejected_but_imported_ones_kept(self):
        self.st.import_yaml("smb", SHARES_YAML.replace("acl_scope: file", "acl_scope: file\n    legacy_flag: 3"))
        eng = next(s for s in self.st.all_sources() if s["name"] == "engineering")
        self.assertEqual(eng["config"]["legacy_flag"], 3)
        saved = self.st.save_source(self.admin, {"config": eng["config"], "credential": eng["credential"]}, eng["id"])
        self.assertEqual(saved["config"]["legacy_flag"], 3)
        with self.assertRaisesRegex(S.Invalid, "unknown setting"):
            self.st.save_source(self.admin, {"config": {**eng["config"], "rogue": 1}}, eng["id"])

    def test_names_unique_across_kinds(self):
        self.st.save_source(self.admin, self.smb(name="finance"))
        with self.assertRaisesRegex(S.Invalid, "already exists"):
            self.st.save_source(self.admin, {"kind": "exchange", "name": "Finance", "config": {"user": "a@b.c"}})
        with self.assertRaises(S.Invalid):
            self.st.save_source(self.admin, self.smb(name="bad name,1"))

    def test_scoped_admin_cant_see_other_scopes(self):
        scope = self.finance_scope()
        mine = self.st.save_source(self.alice, self.smb(scope_id=scope["id"]))
        unscoped = self.st.save_source(self.admin, self.smb(name="secret"))
        self.assertEqual([s["name"] for s in self.st.visible_sources(self.alice)], ["fin-reports"])
        with self.assertRaises(S.NotFound):
            self.st.request_job(self.alice, unscoped["id"], "crawl")
        with self.assertRaises(S.NotFound):
            self.st.remove_source(self.alice, unscoped["id"], "secret")
        self.assertEqual(len(self.st.visible_sources(self.admin)), 2)
        seen = self.st.audit_entries(self.alice)
        self.assertIn(mine["name"], [e["target"] for e in seen])
        self.assertNotIn("secret", [e["target"] for e in seen])
        self.assertTrue(all(e["scope_id"] == scope["id"] for e in self.st.audit_entries(self.alice)))

    def test_only_super_admin_moves_between_scopes(self):
        scope = self.finance_scope()
        src = self.st.save_source(self.alice, self.smb(scope_id=scope["id"]))
        with self.assertRaisesRegex(S.Invalid, "another scope"):
            self.st.save_source(self.alice, {"config": src["config"], "scope_id": None}, src["id"])
        moved = self.st.save_source(self.admin, {"config": src["config"], "scope_id": None}, src["id"])
        self.assertIsNone(moved["scope_id"])

    def test_schedule_limits(self):
        scope = self.finance_scope(min_minutes=120)
        with self.assertRaisesRegex(S.Invalid, "shortest schedule"):
            self.st.save_source(self.alice, self.smb(scope_id=scope["id"], crawl_minutes=60))
        with self.assertRaises(S.Invalid):
            self.st.save_source(self.admin, self.smb(crawl_minutes=2))
        src = self.st.save_source(self.alice, self.smb(scope_id=scope["id"], crawl_minutes=0, acl_minutes=0))
        self.assertEqual(src["crawl_minutes"], 0)

    def test_scope_and_credential_deletion_guarded(self):
        self.st.save_credential(self.admin, {"name": "eng", "user_env": "U", "pass_env": "P"})
        scope = self.finance_scope(credentials=["default", "eng"])
        cred_id = self.st.credentials()[0]["id"]
        with self.assertRaisesRegex(S.Invalid, "scope still allows"):
            self.st.delete_credential(self.admin, cred_id)
        self.st.save_source(self.alice, self.smb(scope_id=scope["id"]))
        with self.assertRaisesRegex(S.Invalid, "sources first"):
            self.st.delete_scope(self.admin, scope["id"])

    # ------------------------------------------------------ scheduler

    def test_schedule_queues_due_jobs(self):
        src = self.st.save_source(self.admin, self.smb(crawl_minutes=60, acl_minutes=30))
        t = 1_000_000.0
        job = self.st.claim("w1", 0, now=t)
        self.assertEqual((job["type"], job["source"]["name"]), ("crawl", src["name"]))
        self.assertEqual(job["names_env"], "SHARE_NAMES")
        self.assertEqual(yaml.safe_load(job["config_yaml"])["shares"][0]["name"], src["name"])
        job2 = self.st.claim("w1", 1, now=t)
        self.assertEqual(job2["type"], "acl")
        self.assertIsNone(self.st.claim("w1", 2, now=t + 1))   # both running
        self.st.finish("w1", job["id"], True, 0, "log", "done", now=t + 100)
        self.st.finish("w1", job2["id"], True, 0, "", "", now=t + 100)
        self.assertIsNone(self.st.claim("w1", 0, now=t + 1700))   # neither interval has passed
        self.assertEqual(self.st.claim("w1", 0, now=t + 1801)["type"], "acl")
        self.assertEqual(self.st.claim("w1", 1, now=t + 3601)["type"], "crawl")

    def test_old_workers_leave_the_list(self):
        t = 5_000_000.0
        self.st.claim("old-container", 0, now=t)
        self.st.claim("lab-worker-1", 0, now=t + S.WORKER_FORGET_SECONDS - 60)
        names = [w["name"] for w in self.st.workers(now=t + S.WORKER_FORGET_SECONDS - 30)]
        self.assertEqual(names, ["lab-worker-1", "old-container"])   # stopped recently: still shown
        names = [w["name"] for w in self.st.workers(now=t + S.WORKER_FORGET_SECONDS + 1)]
        self.assertEqual(names, ["lab-worker-1"])

    def test_full_worker_gets_nothing(self):
        self.st.save_source(self.admin, self.smb())
        self.assertIsNone(self.st.claim("w1", S.DEFAULT_WORKER_SLOTS))
        w = self.st.workers()[0]
        self.assertEqual((w["running"], w["slots"], w["own_slots"]), (S.DEFAULT_WORKER_SLOTS, S.DEFAULT_WORKER_SLOTS, False))

    def test_jobs_at_once_default_and_per_worker(self):
        self.st.save_source(self.admin, self.smb())
        with self.assertRaises(S.Forbidden):
            self.st.set_default_worker_slots(self.alice, 4)
        with self.assertRaises(S.Invalid):
            self.st.set_default_worker_slots(self.admin, 0)
        with self.assertRaises(S.Invalid):
            self.st.set_default_worker_slots(self.admin, S.MAX_WORKER_SLOTS + 1)
        self.st.set_default_worker_slots(self.admin, 1)
        self.assertIsNone(self.st.claim("w1", 1))            # the default now allows one
        self.assertEqual(self.st.set_worker_slots(self.admin, "w1", 3), 3)
        self.assertIsNotNone(self.st.claim("w1", 1))         # its own setting allows three
        self.assertEqual(self.st.worker_slots("w2"), 1)      # others keep the default
        self.assertTrue(self.st.workers()[0]["own_slots"])
        self.assertEqual(self.st.set_worker_slots(self.admin, "w1", None), 1)   # back to the default
        actions = [e["action"] for e in self.st.audit_entries(self.admin)]
        self.assertIn("worker default changed", actions)
        self.assertIn("worker changed", actions)

    def test_worker_setting_outlives_its_row(self):
        self.st.set_worker_slots(self.admin, "w1", 5)
        t = 6_000_000.0
        self.st.claim("w1", 0, now=t)
        self.st.workers(now=t + S.WORKER_FORGET_SECONDS + 1)   # forgotten from the list
        self.assertEqual(self.st.worker_slots("w1"), 5)

    def test_disabled_and_manual_sources(self):
        src = self.st.save_source(self.admin, self.smb(crawl_minutes=0, acl_minutes=0))
        self.assertIsNone(self.st.claim("w1", 0))
        self.st.request_job(self.admin, src["id"], "crawl")
        with self.assertRaisesRegex(S.Invalid, "already queued"):
            self.st.request_job(self.admin, src["id"], "crawl")
        self.st.save_source(self.admin, {"config": src["config"], "enabled": False}, src["id"])
        self.assertEqual(self.st.jobs_for(src["id"])[0]["status"], "cancelled")
        with self.assertRaisesRegex(S.Invalid, "disabled"):
            self.st.request_job(self.admin, src["id"], "crawl")
        self.st.request_job(self.admin, src["id"], "test")   # tests still allowed
        self.assertEqual(self.st.claim("w1", 0)["type"], "test")

    def test_acl_only_for_smb(self):
        src = self.st.save_source(self.admin, {"kind": "exchange", "name": "mb", "config": {"user": "a@b.c"},
                                               "acl_minutes": 30})
        self.assertEqual(src["acl_minutes"], 0)
        with self.assertRaises(S.Invalid):
            self.st.request_job(self.admin, src["id"], "acl")

    def test_lost_worker_lease_expires(self):
        self.st.save_source(self.admin, self.smb(acl_minutes=0))
        t = 2_000_000.0
        job = self.st.claim("w1", 0, now=t)
        self.st.heartbeat("w1", job["id"], "progress", now=t + 60)
        self.st.claim("w2", 0, now=t + 60 + S.LEASE_SECONDS - 1)
        self.assertEqual(self.st.job(job["id"])["status"], "running")
        self.st.claim("w2", 0, now=t + 60 + S.LEASE_SECONDS + 1)
        failed = self.st.job(job["id"])
        self.assertEqual(failed["status"], "failed")
        self.assertIn("w1", failed["summary"])
        with self.assertRaises(S.Invalid):
            self.st.finish("w1", job["id"], True, now=t + 500)

    def test_running_totals_show_as_result(self):
        src = self.st.save_source(self.admin, self.smb(acl_minutes=0))
        job = self.st.claim("w1", 0)
        self.st.heartbeat("w1", job["id"], "log", progress="20 indexed · 100 found")
        self.assertEqual(self.st.jobs_for(src["id"])[0]["summary"], "20 indexed · 100 found")
        self.st.heartbeat("w1", job["id"], "log", progress="")   # no totals yet: keep the last
        self.assertEqual(self.st.jobs_for(src["id"])[0]["summary"], "20 indexed · 100 found")
        self.st.finish("w1", job["id"], True, 0, "log", "120 indexed · 120 found")
        self.assertEqual(self.st.jobs_for(src["id"])[0]["summary"], "120 indexed · 120 found")

    def test_other_worker_cant_report(self):
        self.st.save_source(self.admin, self.smb(acl_minutes=0))
        job = self.st.claim("w1", 0)
        with self.assertRaises(S.Invalid):
            self.st.heartbeat("w2", job["id"])
        with self.assertRaises(S.Invalid):
            self.st.finish("w2", job["id"], True)

    def test_cancel_running_job(self):
        src = self.st.save_source(self.admin, self.smb(acl_minutes=0))
        job = self.st.claim("w1", 0)
        self.assertFalse(self.st.heartbeat("w1", job["id"])["cancel"])
        self.st.cancel_job(self.admin, job["id"])
        self.assertTrue(self.st.heartbeat("w1", job["id"])["cancel"])
        self.st.finish("w1", job["id"], False, -15, "", "stopped")
        self.assertEqual(self.st.jobs_for(src["id"])[0]["status"], "cancelled")

    def test_removal_waits_then_deletes_source(self):
        scope = self.finance_scope()
        src = self.st.save_source(self.alice, self.smb(scope_id=scope["id"], acl_minutes=0))
        t = 3_000_000.0
        t = time.time()   # remove_source queues the purge at the real time
        crawl = self.st.claim("w1", 0, now=t)
        with self.assertRaisesRegex(S.Invalid, "type the source's name"):
            self.st.remove_source(self.alice, src["id"], "wrong")
        self.st.remove_source(self.alice, src["id"], src["name"])
        self.assertTrue(self.st.heartbeat("w1", crawl["id"], now=t + 1)["cancel"])
        self.assertIsNone(self.st.claim("w1", 1, now=t + 2))   # purge waits for the crawl
        with self.assertRaises(S.Invalid):
            self.st.request_job(self.alice, src["id"], "test")
        self.st.finish("w1", crawl["id"], False, -15, now=t + 3)
        purge = self.st.claim("w1", 0, now=t + 4)
        self.assertEqual(purge["type"], "purge")
        self.assertIn(src["name"], purge["config_yaml"])   # the purge needs the source's location
        self.assertIn("fin-reports", self.st.render_all()["shares.yaml"])   # still in exports until gone
        self.st.finish("w1", purge["id"], False, 1, "", "FAILED", now=t + 5)
        self.assertIsNone(self.st.claim("w1", 0, now=t + 6))   # retry waits
        retry = self.st.claim("w1", 0, now=t + 5 + S.PURGE_RETRY_SECONDS + 1)
        self.assertEqual(retry["type"], "purge")
        changes = self.changes
        self.st.finish("w1", retry["id"], True, 0, "", "OK: deleted 3 documents", now=t + 900)
        self.assertEqual(self.st.all_sources(), [])
        self.assertGreater(self.changes, changes)
        self.assertNotIn("fin-reports", self.st.render_all()["shares.yaml"])
        actions = [e["action"] for e in self.st.audit_entries(self.alice)]
        self.assertIn("source removed", actions)
        self.assertIn("source removal started", actions)

    def test_removal_cant_be_cancelled(self):
        src = self.st.save_source(self.admin, self.smb(crawl_minutes=0, acl_minutes=0))
        self.st.remove_source(self.admin, src["id"], src["name"])
        purge = self.st.jobs_for(src["id"])[0]
        with self.assertRaises(S.Invalid):
            self.st.cancel_job(self.admin, purge["id"])

    # ------------------------------------------------------ index jobs

    def test_index_jobs_are_super_admin_only(self):
        for action in S.INDEX_ACTIONS:
            with self.assertRaises(S.Forbidden):
                self.st.request_index_job(self.alice, action)
        with self.assertRaises(S.Forbidden):
            self.st.save_vector_settings(self.alice, {"enabled": True})
        with self.assertRaises(S.Invalid):
            self.st.request_index_job(self.admin, "drop_everything")

    def test_vector_settings_defaults_and_checks(self):
        st = S.Store(os.path.join(self.tmp.name, "v.db"), ["Pelican Admins"],
                     vector_defaults={"embeddings_url": "http://tei:8080/embed"})
        self.addCleanup(st.db.close)
        admin = st.user("root", ["Pelican Admins"])
        v = st.vector_settings()
        self.assertEqual((v["enabled"], v["embeddings_url"], v["chunk_words"]), (False, "http://tei:8080/embed", 300))
        for bad, why in (({"embeddings_url": "file:///etc/passwd"}, "http"), ({"model": ""}, "model"),
                         ({"chunk_words": 10}, "passage size"), ({"chunk_overlap": 0.9}, "overlap"),
                         ({"max_chunks": "lots"}, "number")):
            with self.assertRaisesRegex(S.Invalid, why):
                st.save_vector_settings(admin, bad)
        saved = st.save_vector_settings(admin, {"enabled": True, "model": "BAAI/bge-small-en-v1.5", "chunk_words": "200"})
        self.assertEqual((saved["enabled"], saved["chunk_words"], saved["embeddings_url"]),
                         (True, 200, "http://tei:8080/embed"))
        self.assertEqual(st.vector_settings(), saved)
        self.assertEqual(st.audit_entries(admin)[0]["action"], "vector settings changed")

    def test_rebuild_job_carries_the_saved_settings(self):
        job = self.st.request_index_job(self.admin, "rebuild")
        self.assertIsNone(job["op"]["vectors"])   # vectors off: rebuild without them
        self.st.cancel_index_job(self.admin, job["id"])
        self.st.save_vector_settings(self.admin, {"enabled": True, "chunk_words": 250})
        job = self.st.request_index_job(self.admin, "rebuild")
        self.assertEqual(job["op"]["vectors"]["chunk_words"], 250)
        self.assertNotIn("enabled", job["op"]["vectors"])
        self.assertEqual(job["op"]["requested_by"], "root")
        with self.assertRaisesRegex(S.Invalid, "another index job"):
            self.st.request_index_job(self.admin, "check")

    def test_rebuild_waits_for_crawls_and_holds_new_ones(self):
        a = self.st.save_source(self.admin, self.smb(crawl_minutes=0, acl_minutes=0))
        b = self.st.save_source(self.admin, self.smb(name="fin-two", crawl_minutes=0, acl_minutes=0))
        self.st.request_job(self.admin, a["id"], "crawl")
        t = time.time() + 1
        crawl = self.st.claim("w1", 0, now=t)
        self.assertEqual(crawl["type"], "crawl")
        rebuild = self.st.request_index_job(self.admin, "rebuild")
        self.assertTrue(self.st.holding())
        self.st.request_job(self.admin, b["id"], "crawl")
        self.st.request_job(self.admin, b["id"], "test")
        t = time.time() + 1
        # The rebuild waits for the running crawl; the queued crawl waits for the rebuild; tests still run.
        test = self.st.claim("w1", 1, now=t + 1)
        self.assertEqual(test["type"], "test")
        self.assertIsNone(self.st.claim("w1", 0, now=t + 2))
        self.st.finish("w1", crawl["id"], True, 0, now=t + 3)
        self.st.finish("w1", test["id"], True, 0, now=t + 3)
        job = self.st.claim("w2", 0, now=t + 4)
        self.assertEqual((job["type"], job["id"], job["op"]["action"]), ("index", rebuild["id"], "rebuild"))
        self.assertIsNone(self.st.claim("w1", 0, now=t + 5))   # still held while it runs
        self.assertEqual(self.st.index_heartbeat("w2", job["id"], "log", progress="10 of 20 copied", now=t + 6),
                         {"cancel": False})
        self.assertEqual(self.st.index_job(job["id"])["summary"], "10 of 20 copied")
        with self.assertRaises(S.Invalid):
            self.st.index_finish("w1", job["id"], True)   # not w1's
        self.st.index_finish("w2", job["id"], True, 0, "log", "done", now=t + 7)
        self.assertFalse(self.st.holding())
        self.assertEqual(self.st.claim("w1", 0, now=t + 8)["source"]["name"], "fin-two")
        self.assertEqual([j["source_id"] for j in self.st.writes_since(t + 7)], [b["id"]])
        self.assertEqual(self.st.audit_entries(self.admin)[0]["action"], "index rebuild done")

    def test_check_and_drop_dont_hold_crawls(self):
        a = self.st.save_source(self.admin, self.smb(crawl_minutes=0, acl_minutes=0))
        self.st.request_job(self.admin, a["id"], "crawl")
        t = time.time() + 1
        crawl = self.st.claim("w1", 0, now=t)
        self.assertEqual(crawl["type"], "crawl")
        self.st.request_index_job(self.admin, "check")
        self.assertFalse(self.st.holding())
        self.assertEqual(self.st.claim("w1", 1, now=t + 1)["op"]["action"], "check")   # doesn't wait

    def test_index_job_cancel_and_lost_lease(self):
        job = self.st.request_index_job(self.admin, "switch_back")
        self.assertEqual(self.st.cancel_index_job(self.admin, job["id"])["status"], "cancelled")
        with self.assertRaises(S.Invalid):
            self.st.cancel_index_job(self.admin, job["id"])
        job = self.st.request_index_job(self.admin, "rebuild")
        t = time.time()
        self.st.claim("w1", 0, now=t)
        self.st.cancel_index_job(self.admin, job["id"])
        self.assertTrue(self.st.index_heartbeat("w1", job["id"], now=t + 1)["cancel"])
        self.st.index_finish("w1", job["id"], False, 1, now=t + 2)
        self.assertEqual(self.st.index_job(job["id"])["status"], "cancelled")
        job = self.st.request_index_job(self.admin, "rebuild")
        self.st.claim("w1", 0, now=t + 3)
        self.st.claim("w2", 0, now=t + 3 + S.LEASE_SECONDS + 1)
        self.assertEqual(self.st.index_job(job["id"])["status"], "failed")
        self.assertFalse(self.st.holding())

    def test_changes_trigger_exports(self):
        before = self.changes
        self.st.save_source(self.admin, self.smb())
        self.assertGreater(self.changes, before)


if __name__ == "__main__":
    unittest.main()
