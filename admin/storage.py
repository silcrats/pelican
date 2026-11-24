"""
OpenSearch storage figures for the admin portal's Storage page: the
index's real size and document count, disk space, an estimate of each
source's share of the index, and growth from saved snapshots.

Collected in a background thread and cached, so a page never waits on
OpenSearch and a slow or failed query only leaves the last good figures.
Needs an account that can search the index and read index and node stats
(pelican-status in the compose example).
"""

import base64
import json
import os
import ssl
import threading
import time
import urllib.error
import urllib.request

HISTORY_MIN_INTERVAL_SECONDS = 6 * 3600   # at most one history snapshot per 6h
HISTORY_MAX_SNAPSHOTS = 500               # ~4 months at 4/day
GROWTH_WINDOW_DAYS = 7


class Storage:
    def __init__(self, os_host: str, index: str, username: str = "", password: str = "", ca_certs: str = "",
                 history_path: str = "", refresh_seconds: int = 900, sample_docs: int = 100,
                 sample_ttl_seconds: int = 3600):
        self.os_host = os_host.rstrip("/")
        self.index = index
        self.history_path = history_path
        self.refresh_seconds = refresh_seconds
        self.sample_docs = sample_docs
        self.sample_ttl_seconds = sample_ttl_seconds
        self._ssl = ssl.create_default_context(cafile=ca_certs or None)
        self._auth = ({"Authorization": "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()}
                      if username else {})
        self._lock = threading.Lock()
        self._state = {"data": None, "error": None, "updated": None}
        self._avg_doc_cache: dict = {}   # source name -> (sampled_at, avg stored doc bytes)
        self._wake = threading.Event()

    @classmethod
    def from_env(cls, history_path: str) -> "Storage":
        """Configured from OS_HOST, SEARCH_INDEX, OS_USERNAME, OS_PASSWORD,
        OS_CA_CERTS and the STORAGE_* tuning variables."""
        return cls(os.environ.get("OS_HOST", "http://opensearch:9200"), os.environ.get("SEARCH_INDEX", "documents"),
                   os.environ.get("OS_USERNAME", ""), os.environ.get("OS_PASSWORD", ""),
                   os.environ.get("OS_CA_CERTS", ""),
                   os.environ.get("STORAGE_HISTORY_PATH", history_path),
                   int(os.environ.get("STORAGE_REFRESH_SECONDS", "900")),       # how often to re-query OpenSearch
                   int(os.environ.get("STORAGE_SAMPLE_DOCS", "100")),           # random docs fetched per source
                   int(os.environ.get("STORAGE_SAMPLE_TTL_SECONDS", "3600")))   # re-sample a source's avg doc size this often

    # ---------------------------------------------------------- running

    def start(self) -> None:
        threading.Thread(target=self._loop, daemon=True).start()

    def refresh_soon(self) -> None:
        """Collect again now instead of at the next interval."""
        self._wake.set()

    def snapshot(self) -> dict:
        with self._lock:
            return dict(self._state)

    def _loop(self) -> None:
        while True:
            try:
                data = self.collect()
                with self._lock:
                    self._state.update(data=data, error=None, updated=time.time())
            except Exception as exc:  # keep the last good data; surface the error on the page
                with self._lock:
                    self._state["error"] = f"{type(exc).__name__}: {exc}"
            self._wake.wait(self.refresh_seconds)
            self._wake.clear()

    # ----------------------------------------------------------- queries

    def _os(self, method: str, path: str, body=None):
        payload = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.os_host + path, data=payload, method=method,
                                     headers={"Content-Type": "application/json", **self._auth})
        try:
            with urllib.request.urlopen(req, timeout=60,
                                        context=self._ssl if self.os_host.startswith("https") else None) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:300]
            raise RuntimeError(f"OpenSearch {exc.code} on {path}: {detail}") from None

    def _avg_unmeasured_doc_bytes(self, source: str) -> float:
        """Average stored (_source) size of a random sample of this source's docs
        that have no measured doc_bytes (indexed before sizing was added), cached
        so the (relatively heavy) sample isn't repeated every refresh."""
        cached = self._avg_doc_cache.get(source)
        if cached and time.time() - cached[0] < self.sample_ttl_seconds:
            return cached[1]
        body = {
            "size": self.sample_docs,
            "track_total_hits": False,
            "query": {"function_score": {
                "query": {"bool": {
                    "filter": [{"term": {"share": source}}],
                    "must_not": [{"exists": {"field": "doc_bytes"}}],
                }},
                "random_score": {},
            }},
        }
        hits = self._os("POST", f"/{self.index}/_search", body)["hits"]["hits"]
        sizes = [len(json.dumps(h["_source"], ensure_ascii=False).encode("utf-8")) for h in hits]
        avg = sum(sizes) / len(sizes) if sizes else 0.0
        self._avg_doc_cache[source] = (time.time(), avg)
        return avg

    # ----------------------------------------------------------- history

    def _read_history(self) -> list:
        snaps = []
        try:
            with open(self.history_path) as f:
                for line in f:
                    try:
                        snaps.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except OSError:
            pass
        return snaps

    def _record_history(self, data: dict) -> None:
        if not self.history_path:
            return
        snaps = self._read_history()
        if snaps and time.time() - snaps[-1]["ts"] < HISTORY_MIN_INTERVAL_SECONDS:
            return
        snaps.append({
            "ts": time.time(),
            "index_bytes": data["index_bytes"],
            "docs": data["docs"],
            "disk_total": data["disk_total"],
            "disk_free": data["disk_free"],
            "sources": {s["name"]: s["docs"] for s in data["sources"]},
        })
        snaps = snaps[-HISTORY_MAX_SNAPSHOTS:]
        tmp = self.history_path + ".tmp"
        with open(tmp, "w") as f:
            for snap in snaps:
                f.write(json.dumps(snap) + "\n")
        os.replace(tmp, self.history_path)

    def _growth(self, current: dict):
        """Growth rate over the last GROWTH_WINDOW_DAYS from saved snapshots, or
        None until there is at least a day of history."""
        cutoff = time.time() - GROWTH_WINDOW_DAYS * 86400
        window = [s for s in self._read_history() if s["ts"] >= cutoff]
        if not window:
            return None
        first = window[0]
        days = (time.time() - first["ts"]) / 86400
        if days < 1:
            return None
        per_day = (current["index_bytes"] - first["index_bytes"]) / days
        out = {
            "window_days": round(days, 1),
            "index_bytes_per_day": per_day,
            "docs_per_day_by_source": {
                s["name"]: (s["docs"] - first.get("sources", {}).get(s["name"], 0)) / days
                for s in current["sources"]
            },
        }
        if per_day > 0:
            out["days_until_full"] = current["disk_free"] / per_day
        return out

    # ------------------------------------------------------------ collect

    def collect(self) -> dict:
        stats = self._os("GET", f"/{self.index}/_stats/store,docs")["_all"]
        index_bytes = stats["total"]["store"]["size_in_bytes"]   # all shard copies = real disk footprint
        # Index stats count Lucene entries, and with vector search each passage
        # is one too; _count gives the documents themselves.
        docs = self._os("GET", f"/{self.index}/_count")["count"]
        deleted = stats["primaries"]["docs"].get("deleted", 0)   # entries, freed on merge

        nodes = list(self._os("GET", "/_nodes/stats/fs")["nodes"].values())
        disk_total = sum(n["fs"]["total"]["total_in_bytes"] for n in nodes)
        disk_free = sum(n["fs"]["total"]["available_in_bytes"] for n in nodes)

        agg = self._os("POST", f"/{self.index}/_search", {
            "size": 0,
            "track_total_hits": False,
            "aggs": {"by_share": {
                "terms": {"field": "share", "size": 1000},
                "aggs": {
                    "raw": {"sum": {"field": "content_length"}},
                    "host": {"terms": {"field": "host", "size": 1}},
                    # docs that carry a measured doc_bytes (added at index time)
                    "measured": {
                        "filter": {"exists": {"field": "doc_bytes"}},
                        "aggs": {"bytes": {"sum": {"field": "doc_bytes"}}},
                    },
                },
            }},
        })
        sources = []
        for b in agg["aggregations"]["by_share"]["buckets"]:
            host_buckets = b["host"]["buckets"]
            docs_in_source = b["doc_count"]
            measured_docs = b["measured"]["doc_count"]
            measured_bytes = int(b["measured"]["bytes"]["value"] or 0)
            legacy_docs = docs_in_source - measured_docs
            # Measured docs contribute their exact size; older docs (no doc_bytes)
            # are estimated from a sample, and only sampled if any exist.
            legacy_bytes = legacy_docs * self._avg_unmeasured_doc_bytes(b["key"]) if legacy_docs > 0 else 0.0
            weight = measured_bytes + legacy_bytes
            sources.append({
                "name": b["key"],
                "host": host_buckets[0]["key"] if host_buckets else "",
                "docs": docs_in_source,
                "raw_bytes": int(b["raw"]["value"] or 0),
                "measured_pct": 100 * measured_docs / docs_in_source if docs_in_source else 0,
                "weight": weight,
                "avg_doc_bytes": weight / docs_in_source if docs_in_source else 0,
            })

        # Apportion the real index size by each source's measured/estimated document bytes.
        total_weight = sum(s["weight"] for s in sources)
        for s in sources:
            s["est_index_bytes"] = index_bytes * s["weight"] / total_weight if total_weight else 0
            s["pct"] = 100 * s["weight"] / total_weight if total_weight else 0
            del s["weight"]
        sources.sort(key=lambda s: s["est_index_bytes"], reverse=True)

        data = {
            "index": self.index,
            "index_bytes": index_bytes,
            "docs": docs,
            "deleted_docs": deleted,
            "disk_total": disk_total,
            "disk_free": disk_free,
            "sample_docs": self.sample_docs,
            "sources": sources,
        }
        self._record_history(data)
        data["growth"] = self._growth(data)
        return data
