"""Unit tests for the admin portal's storage figures (admin/storage.py), with
OpenSearch replaced by canned replies.

    python -m unittest discover -s tests/admin
"""

import json
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "admin"))
import storage as S  # noqa: E402

GB = 1024 ** 3


def replies(index_bytes=10 * GB, docs=300, buckets=None):
    buckets = buckets if buckets is not None else [
        # fully sized: 3 GB of document bytes
        {"key": "govdocs", "doc_count": 200, "raw": {"value": 5 * GB}, "host": {"buckets": [{"key": "smb-share"}]},
         "measured": {"doc_count": 200, "bytes": {"value": 3 * GB}}},
        # half sized: 50 measured at 1 GB, 50 estimated from a sample
        {"key": "mail", "doc_count": 100, "raw": {"value": GB}, "host": {"buckets": [{"key": "exchange-online"}]},
         "measured": {"doc_count": 50, "bytes": {"value": GB}}},
    ]
    return {
        ("GET", "/documents/_stats/store,docs"): {"_all": {"total": {"store": {"size_in_bytes": index_bytes}},
                                                          "primaries": {"docs": {"count": docs * 9, "deleted": 7}}}},
        ("GET", "/documents/_count"): {"count": docs},
        ("GET", "/_nodes/stats/fs"): {"nodes": {"n1": {"fs": {"total": {"total_in_bytes": 100 * GB,
                                                                       "available_in_bytes": 40 * GB}}}}},
        "aggs": {"aggregations": {"by_share": {"buckets": buckets}}},
        # The sample for "mail": each stored doc ~20 MB.
        "sample": {"hits": {"hits": [{"_source": {"content": "x" * (20 * 1024 * 1024)}}]}},
    }


class FakeStorage(S.Storage):
    def __init__(self, canned, **kw):
        super().__init__("https://opensearch:9200", "documents", **kw)
        self.canned = canned
        self.calls = []

    def _os(self, method, path, body=None):
        self.calls.append((method, path))
        if (method, path) in self.canned:
            return self.canned[(method, path)]
        if body and "aggs" in body:
            return self.canned["aggs"]
        return self.canned["sample"]


class StorageTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.history = os.path.join(self.tmp.name, "history.jsonl")

    def tearDown(self):
        self.tmp.cleanup()

    def test_index_split_by_document_bytes(self):
        st = FakeStorage(replies(), history_path=self.history)
        d = st.collect()
        self.assertEqual((d["index_bytes"], d["docs"], d["deleted_docs"]), (10 * GB, 300, 7))
        self.assertEqual((d["disk_total"], d["disk_free"]), (100 * GB, 40 * GB))
        by = {s["name"]: s for s in d["sources"]}
        mail_weight = GB + 50 * len(json.dumps({"content": "x" * (20 * 1024 * 1024)}).encode())
        total = 3 * GB + mail_weight
        self.assertAlmostEqual(by["govdocs"]["est_index_bytes"], 10 * GB * 3 * GB / total)
        self.assertAlmostEqual(by["govdocs"]["pct"] + by["mail"]["pct"], 100)
        self.assertEqual(by["mail"]["measured_pct"], 50)
        self.assertEqual(by["mail"]["host"], "exchange-online")
        self.assertEqual([s["name"] for s in d["sources"]], ["govdocs", "mail"])   # largest first
        self.assertIsNone(d["growth"])   # less than a day of history

    def test_sample_is_cached(self):
        st = FakeStorage(replies(), history_path=self.history)
        st.collect()
        st.collect()
        samples = [c for c in st.calls if c == ("POST", "/documents/_search")]
        self.assertEqual(len(samples), 3)   # aggs twice, the sample once

    def test_growth_from_history(self):
        old = {"ts": time.time() - 2 * 86400, "index_bytes": 8 * GB, "docs": 250, "disk_total": 100 * GB,
               "disk_free": 42 * GB, "sources": {"govdocs": 180, "mail": 70}}
        with open(self.history, "w") as f:
            f.write(json.dumps(old) + "\n")
        d = FakeStorage(replies(), history_path=self.history).collect()
        g = d["growth"]
        self.assertAlmostEqual(g["index_bytes_per_day"], GB, delta=GB * 0.01)
        self.assertAlmostEqual(g["days_until_full"], 40, delta=0.5)
        self.assertAlmostEqual(g["docs_per_day_by_source"]["govdocs"], 10, delta=0.1)
        with open(self.history) as f:
            self.assertEqual(len(f.read().splitlines()), 2)   # a new snapshot saved

    def test_snapshot_keeps_last_good_figures(self):
        st = FakeStorage(replies(), history_path="", refresh_seconds=3600)
        st.start()
        deadline = time.time() + 5
        while not st.snapshot()["updated"] and time.time() < deadline:
            time.sleep(0.05)
        good = st.snapshot()
        self.assertEqual(good["data"]["docs"], 300)
        st.canned = {}   # every query now fails
        st.refresh_soon()
        while not st.snapshot()["error"] and time.time() < deadline + 5:
            time.sleep(0.05)
        after = st.snapshot()
        self.assertIsNotNone(after["error"])
        self.assertEqual(after["data"]["docs"], 300)


if __name__ == "__main__":
    unittest.main()
