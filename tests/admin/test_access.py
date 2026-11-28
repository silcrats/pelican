"""Unit tests for the Access page's role rules and counts (admin/access.py).

    python -m unittest discover tests/admin
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "admin"))
from access import RoleRules, visible_counts  # noqa: E402


class RoleRulesTest(unittest.TestCase):
    def test_same_roles_as_frogmouth(self):
        # Frogmouth's computeRoles: defaults, then the user, then each group.
        roles = RoleRules().roles("Alice", ["Finance", "Domain Users"])
        self.assertEqual([r["role"] for r in roles], ["Rguest", "1alice", "2Finance", "2Domain Users"])
        self.assertEqual([r["from"] for r in roles], ["default", "user", "group", "group"])

    def test_group_names_keep_their_case_and_duplicates_go(self):
        roles = RoleRules().roles("bob", ["Engineering", "Engineering"])
        self.assertEqual([r["role"] for r in roles], ["Rguest", "1bob", "2Engineering"])

    def test_from_env(self):
        env = {"ROLE_PREFIX_USER": "u:", "ROLE_PREFIX_GROUP": "g:", "ROLE_PREFIX_ROLE": "r:",
               "DEFAULT_ROLES": "guest, staff", "ROLE_LOWERCASE_USERNAME": "false"}
        with mock.patch.dict(os.environ, env):
            roles = RoleRules.from_env().roles("Bob", ["Eng"])
        self.assertEqual([r["role"] for r in roles], ["r:guest", "r:staff", "u:Bob", "g:Eng"])


class VisibleCountsTest(unittest.TestCase):
    def test_totals_visible_and_granting_roles(self):
        calls = []

        def search(path, body):
            calls.append((path, body))
            filtered = "bool" in body["query"]
            if not filtered:
                buckets = [{"key": "fin", "host": {"buckets": [{"key": "smb-share", "doc_count": 10},
                                                                 {"key": "exchange-online", "doc_count": 3}]}}]
            else:
                buckets = [{"key": "fin", "host": {"buckets": [
                    {"key": "smb-share", "doc_count": 4, "granted": {"buckets": [{"key": "1alice", "doc_count": 4}]}}]}}]
            return {"aggregations": {"by_share": {"buckets": buckets}}}

        out = visible_counts(search, "documents", ["Rguest", "1alice"])
        self.assertEqual(out[("fin", "smb-share")], {"total": 10, "visible": 4, "by_role": {"1alice": 4}})
        self.assertEqual(out[("fin", "exchange-online")], {"total": 3, "visible": 0, "by_role": {}})
        self.assertEqual(calls[1][0], "/documents/_search")
        self.assertEqual(calls[1][1]["query"], {"bool": {"filter": [{"terms": {"role": ["Rguest", "1alice"]}}]}})
        granted = calls[1][1]["aggs"]["by_share"]["aggs"]["host"]["aggs"]["granted"]["terms"]
        self.assertEqual(granted["include"], ["Rguest", "1alice"])


if __name__ == "__main__":
    unittest.main()
