import glob
import http.server
import json
import os
import threading
import time
import urllib.error
import urllib.request

STATUS_DIR = os.environ.get("STATUS_DIR", "/status")
PORT = int(os.environ.get("PORT", "8090"))

# --- OpenSearch storage view -------------------------------------------------
OS_HOST = os.environ.get("OS_HOST", "http://opensearch:9200").rstrip("/")
SEARCH_INDEX = os.environ.get("SEARCH_INDEX", "documents")
STORAGE_REFRESH_SECONDS = int(os.environ.get("STORAGE_REFRESH_SECONDS", "900"))   # how often to re-query OpenSearch
SAMPLE_DOCS = int(os.environ.get("STORAGE_SAMPLE_DOCS", "100"))                   # random docs fetched per source
SAMPLE_TTL_SECONDS = int(os.environ.get("STORAGE_SAMPLE_TTL_SECONDS", "3600"))    # re-sample a source's avg doc size this often
HISTORY_PATH = os.environ.get("STORAGE_HISTORY_PATH", os.path.join(STATUS_DIR, "storage-history.jsonl"))
HISTORY_MIN_INTERVAL_SECONDS = 6 * 3600   # at most one history snapshot per 6h
HISTORY_MAX_SNAPSHOTS = 500               # ~4 months at 4/day
GROWTH_WINDOW_DAYS = 7

PAGE = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Pelican Status</title>
<style>
  body { font-family: system-ui, sans-serif; background: #111; color: #eee; padding: 2rem; }
  h1 { font-size: 1.3rem; margin-bottom: 1.5rem; }
  h2 { font-size: 1.05rem; margin: 0 0 0.4rem; }
  .job { background: #191919; border: 1px solid #2a2a2a; border-radius: 8px; padding: 1.2rem 1.4rem; margin-bottom: 1.5rem; }
  table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
  th, td { text-align: left; padding: 0.4rem 0.8rem; border-bottom: 1px solid #333; word-break: break-word; }
  th { color: #888; font-weight: normal; font-size: 0.85rem; }
  td.num, th.num { text-align: right; }
  /* Fixed, shared column widths so every job's table lines up with every
     other's -- otherwise each table auto-sizes its own Share/Status columns
     to its own content (a longer mailbox name shifts everything after it),
     and the numeric columns end up at different x-positions job to job. */
  .crawl-table { table-layout: fixed; }
  .crawl-table th:nth-child(1), .crawl-table td:nth-child(1) { width: 15%; }
  .crawl-table th:nth-child(2), .crawl-table td:nth-child(2) { width: 15%; }
  .crawl-table th:nth-child(n+3), .crawl-table td:nth-child(n+3) { width: 10%; }
  .acl-count { color: #6cb6ff; }
  .status-running { color: #4caf50; }
  .status-done { color: #888; }
  .status-idle { color: #888; }
  .status-failed { color: #e05252; }
  .status-pending { color: #666; }
  .meta { color: #888; font-size: 0.9rem; margin-bottom: 0.3rem; }
  .config { color: #888; font-size: 0.85rem; margin-bottom: 0.5rem; }
  .hint { color: #777; font-size: 0.8rem; margin-top: 0.8rem; }
  .timeout-count { color: #e0a252; }
  .warn { color: #e0a252; }
  #err { color: #e05252; }
  #empty { color: #888; }
  .tabs { display: flex; gap: 0.4rem; margin-bottom: 1.5rem; border-bottom: 1px solid #2a2a2a; }
  .tab { background: none; border: none; border-bottom: 2px solid transparent; color: #888; font: inherit;
         padding: 0.5rem 1rem; cursor: pointer; margin-bottom: -1px; }
  .tab:hover { color: #ccc; }
  .tab.active { color: #eee; border-bottom-color: #4caf50; }
  .c-smb { color: #f5e58a; }
  .c-exchange { color: #2b88d8; }
  .c-sharepoint { color: #2fa84f; }
  .c-acl { color: #f0932b; }
  /* Sub-tabs (crawl type, under the top-level Crawling tab) always show their
     type colour, active or not -- consistent with job names/headings
     elsewhere already being colour-coded by type. The combined selectors
     are needed because plain .tab.active (2 classes) otherwise outranks a
     single .c-* class and forces the generic white/green active style. */
  .subtabs { margin-bottom: 1.2rem; }
  .subtabs .tab.active { border-bottom-color: currentColor; }
  .subtabs .tab.active.c-smb { color: #f5e58a; }
  .subtabs .tab.active.c-exchange { color: #2b88d8; }
  .subtabs .tab.active.c-sharepoint { color: #2fa84f; }
  .subtabs .tab.active.c-acl { color: #f0932b; }
</style>
</head>
<body>
<h1>Pelican Status</h1>
<div class="tabs" id="top-tabs">
  <button type="button" class="tab active" data-tab="crawling">Crawling</button>
  <button type="button" class="tab" data-tab="storage">Storage</button>
</div>
<div id="tab-crawling">
  <div class="tabs subtabs" id="crawl-subtabs"></div>
  <div id="root">loading...</div>
</div>
<div id="tab-storage" hidden><div id="storage"></div></div>

<script>
let consecutiveFailures = 0;
const FAILURE_THRESHOLD = 3;  // only show the error after this many misses in a row

function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
}

function fmtBytes(n) {
  if (n === null || n === undefined || isNaN(n)) return '-';
  const sign = n < 0 ? '-' : '';
  let v = Math.abs(Number(n));
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return sign + v.toFixed(i === 0 ? 0 : 1) + ' ' + units[i];
}

function renderJob(data) {
  const cfg = data.config || {};
  let cfgHtml = '';
  if (cfg.smb_workers !== undefined) {
    const exts = esc((cfg.exclude_extensions || []).join(', ') || 'none');
    cfgHtml =
      `Workers: <b>${esc(cfg.smb_workers)}</b> &middot; ` +
      `Excluded extensions: <b>${exts}</b> &middot; ` +
      `Excluded (no extension): <b>${esc(cfg.exclude_no_extension)}</b>`;
  }

  const metaHtml =
    `Status: <b class="status-${esc(data.status)}">${esc(data.status)}</b> &middot; ` +
    `Started: ${esc(data.started_at || '-')} &middot; ` +
    `Finished: ${esc(data.finished_at || '-')} &middot; ` +
    `Total indexed: <b>${esc(data.grand_total_indexed)}</b> &middot; ` +
    `Last updated: ${esc(data.last_updated || '-')}`;

  const rows = Object.entries(data.shares || {}).map(([name, s]) => `
    <tr>
      <td>${esc(name)}</td>
      <td class="status-${esc(s.status)}">${esc(s.status)}${s.error ? ' - ' + esc(s.error) : ''}</td>
      <td class="num">${esc(s.discovered)}</td><td class="num">${esc(s.indexed)}</td>
      <td class="num">${esc(s.skipped_excluded)}</td><td class="num">${esc(s.skipped_unchanged)}</td>
      <td class="num ${s.skipped_oversized ? 'timeout-count' : ''}">${s.skipped_oversized || 0}</td>
      <td class="num ${s.extraction_timeouts ? 'timeout-count' : ''}">${s.extraction_timeouts || 0}</td>
      <td class="num ${s.acl_docs_updated ? 'acl-count' : ''}" title="${s.acl_groups_changed || 0} director${s.acl_groups_changed === 1 ? 'y' : 'ies'} with a permission change this run">${s.acl_docs_updated || 0}</td>
    </tr>`).join('');

  const div = document.createElement('div');
  div.className = 'job';
  div.innerHTML = `
    <h2 class="c-${['smb', 'exchange', 'sharepoint', 'acl'].includes(data.job_type) ? data.job_type : 'smb'}">${esc(data.job_name || 'unnamed job')}</h2>
    <div class="config">${cfgHtml}</div>
    <div class="meta">${metaHtml}</div>
    <table class="crawl-table"><thead>
      <tr><th>Share</th><th>Status</th><th class="num">Discovered</th><th class="num">Indexed</th>
      <th class="num">Skipped (excluded)</th><th class="num">Skipped (unchanged)</th>
      <th class="num">Over size limit</th><th class="num">Timed out</th>
      <th class="num" title="Documents whose role changed because a folder's permissions changed, not their content">ACL updates</th></tr>
    </thead><tbody>${rows}</tbody></table>
  `;
  return div;
}

// A source's `host` field is smb-share / exchange-online / sharepoint-online.
function hostColorClass(host) {
  const h = String(host || '');
  return h.startsWith('exchange') ? 'c-exchange' : h.startsWith('sharepoint') ? 'c-sharepoint' : 'c-smb';
}

function renderStorage(s) {
  const d = s.data;
  const g = d.growth;
  const usedPct = d.disk_total ? (100 * (d.disk_total - d.disk_free) / d.disk_total) : 0;
  const perDoc = d.docs ? d.index_bytes / d.docs : 0;

  const diskHtml =
    `Disk: <b class="${usedPct >= 85 ? 'warn' : ''}">${fmtBytes(d.disk_total - d.disk_free)}</b> used of ` +
    `${fmtBytes(d.disk_total)} (${usedPct.toFixed(0)}%) &middot; <b>${fmtBytes(d.disk_free)}</b> free`;
  const indexHtml =
    `Index: <b>${fmtBytes(d.index_bytes)}</b> on disk &middot; ` +
    `<b>${d.docs.toLocaleString()}</b> documents &middot; ` +
    `avg <b>${fmtBytes(perDoc)}</b> per document` +
    (d.deleted_docs ? ` &middot; ${d.deleted_docs.toLocaleString()} deleted (space freed on merge)` : '');
  const growthHtml = g
    ? `Recent growth: <b>${fmtBytes(g.index_bytes_per_day)}/day</b> over ${g.window_days} days` +
      (g.days_until_full ? ` &middot; disk full in about <b>${Math.round(g.days_until_full)}</b> days at this rate` : '')
    : 'Growth: collecting history (needs about a day of samples)';

  // Grouped by type, then alphabetical by source within each type.
  const sorted = d.sources.slice().sort((a, b) =>
    (a.host || '').localeCompare(b.host || '') || a.name.localeCompare(b.name));
  const rows = sorted.map(x => {
    const dpd = g && g.docs_per_day_by_source ? g.docs_per_day_by_source[x.name] : null;
    return `
    <tr>
      <td class="${hostColorClass(x.host)}">${esc(x.name)}</td>
      <td class="${hostColorClass(x.host)}">${esc(x.host)}</td>
      <td class="num">${x.docs.toLocaleString()}</td>
      <td class="num">${fmtBytes(x.raw_bytes)}</td>
      <td class="num">${fmtBytes(x.avg_doc_bytes)}</td>
      <td class="num"><b>${fmtBytes(x.est_index_bytes)}</b></td>
      <td class="num">${x.pct.toFixed(1)}%</td>
      <td class="num ${x.measured_pct < 100 ? 'warn' : ''}">${x.measured_pct.toFixed(0)}%</td>
      <td class="num">${dpd === null || dpd === undefined ? '-' : Math.round(dpd).toLocaleString()}</td>
    </tr>`;
  }).join('');

  const updated = s.updated ? new Date(s.updated * 1000).toLocaleString() : '-';
  const errHtml = s.error ? `<div class="meta warn">Last refresh failed (showing older data): ${esc(s.error)}</div>` : '';

  const div = document.createElement('div');
  div.className = 'job';
  div.innerHTML = `
    <h2>Index &middot; ${esc(d.index)}</h2>
    <div class="meta">${indexHtml}</div>
    <div class="meta">${diskHtml}</div>
    <div class="meta">${growthHtml}</div>
    ${errHtml}
    <table><thead>
      <tr><th>Source</th><th>Type</th><th class="num">Documents</th><th class="num">Raw file size</th>
      <th class="num">Avg stored doc</th><th class="num">Est. index size</th><th class="num">% of index</th><th class="num">Sized</th><th class="num">Docs/day</th></tr>
    </thead><tbody>${rows}</tbody></table>
    <div class="hint">
      Documents and raw file size are exact. OpenSearch reports the real size of the whole index but not per source, so
      Est. index size splits it by each source's document bytes. <b>Sized</b> is the share of a source's documents whose size
      was measured when they were indexed; the rest (indexed before sizing was added) are estimated from a sample of
      ${d.sample_docs} documents, so a source below 100% is less certain. Updated ${esc(updated)}.
    </div>
  `;
  return div;
}

async function refreshStorage() {
  const el = document.getElementById('storage');
  try {
    const res = await fetch('/storage.json?' + Date.now());
    if (!res.ok) throw new Error('bad response');
    const s = await res.json();
    if (!s.data) {
      el.innerHTML = '<div class="job"><h2>OpenSearch storage</h2><div class="meta">' +
        (s.error ? 'Unavailable: ' + esc(s.error) : 'Collecting first sample...') + '</div></div>';
      return;
    }
    el.innerHTML = '';
    el.appendChild(renderStorage(s));
  } catch (e) {
    // keep whatever is on screen; the next poll will retry
  }
}

// Fixed display order and heading text for each job_type -- anything absent or
// unrecognised (an older status file from before job_type existed, or some
// future crawler kind) falls into "other" at the end rather than being dropped.
const JOB_TYPE_GROUPS = [
  { key: 'smb', label: 'SMB Shares' },
  { key: 'exchange', label: 'Exchange Online' },
  { key: 'sharepoint', label: 'SharePoint Online' },
  { key: 'acl', label: 'ACL Sync' },
  { key: 'other', label: 'Other' },
];
const KNOWN_JOB_TYPES = new Set(JOB_TYPE_GROUPS.map(g => g.key));
const jobTypeOf = j => KNOWN_JOB_TYPES.has(j.job_type) ? j.job_type : 'other';

// "Active" is synthetic (spans every type, filtered by status rather than
// job_type) and comes first so it's the default sub-tab on page load.
const CRAWL_SUBTABS = [{ key: 'active', label: 'Active' }, ...JOB_TYPE_GROUPS];
let currentCrawlSubTab = 'active';

function showCrawlSubTab(key) {
  currentCrawlSubTab = key;
  document.querySelectorAll('#crawl-subtabs .tab').forEach(t => t.classList.toggle('active', t.dataset.subtab === key));
  refresh();
}

(() => {
  const el = document.getElementById('crawl-subtabs');
  el.innerHTML = CRAWL_SUBTABS.map(({ key, label }) => {
    const colorClass = key === 'active' ? '' : ' c-' + key;
    const activeClass = key === currentCrawlSubTab ? ' active' : '';
    return `<button type="button" class="tab${activeClass}${colorClass}" data-subtab="${key}">${esc(label)}</button>`;
  }).join('');
  el.querySelectorAll('.tab').forEach(t => t.addEventListener('click', () => showCrawlSubTab(t.dataset.subtab)));
})();

async function refresh() {
  const root = document.getElementById('root');
  try {
    const res = await fetch('/status.json?' + Date.now());
    if (!res.ok) throw new Error('bad response');
    const data = await res.json();
    consecutiveFailures = 0;

    const jobs = data.jobs || [];
    if (jobs.length === 0) {
      root.innerHTML = '<div id="empty">No crawler jobs have reported in yet.</div>';
      return;
    }

    const shown = (currentCrawlSubTab === 'active'
      ? jobs.filter(j => j.status === 'running')
      : jobs.filter(j => jobTypeOf(j) === currentCrawlSubTab)
    ).sort((a, b) => (a.job_name || '').localeCompare(b.job_name || ''));

    root.innerHTML = '';
    if (!shown.length) {
      root.innerHTML = `<div id="empty">${currentCrawlSubTab === 'active' ? 'No crawls currently running.' : 'No jobs in this category.'}</div>`;
      return;
    }
    shown.forEach(job => root.appendChild(renderJob(job)));
  } catch (e) {
    consecutiveFailures++;
    if (consecutiveFailures >= FAILURE_THRESHOLD) {
      root.innerHTML = '<span id="err">Status not available yet.</span>';
    }
    // else: keep showing the last good data, ignore the blip
  }
}
function showTab(name) {
  document.querySelectorAll('#top-tabs .tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
  document.getElementById('tab-crawling').hidden = name !== 'crawling';
  document.getElementById('tab-storage').hidden = name !== 'storage';
  history.replaceState(null, '', '#' + name);  // a page refresh keeps you on the same tab
}
document.querySelectorAll('#top-tabs .tab').forEach(t => t.addEventListener('click', () => showTab(t.dataset.tab)));
showTab(location.hash === '#storage' ? 'storage' : 'crawling');

refresh();
setInterval(refresh, 3000);
refreshStorage();
setInterval(refreshStorage, 30000);
</script>
</body>
</html>
"""


def _collect_jobs() -> list:
    jobs = []
    for path in sorted(glob.glob(os.path.join(STATUS_DIR, "status-*.json"))):
        try:
            with open(path) as f:
                jobs.append(json.load(f))
        except (OSError, json.JSONDecodeError):
            continue  # skip a file mid-write or corrupted; next poll will pick it up
    return jobs


# ------------------------------------------------------------ storage collection
#
# Runs in a background thread and caches its result, so the page never waits on
# OpenSearch and a slow/failed query can't affect the crawler job status above.

_storage_lock = threading.Lock()
_storage = {"data": None, "error": None, "updated": None}
_avg_doc_cache: dict = {}   # source name -> (sampled_at, avg stored doc bytes)


def _os(method: str, path: str, body=None):
    payload = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(OS_HOST + path, data=payload, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        raise RuntimeError(f"OpenSearch {exc.code} on {path}: {detail}") from None


def _avg_unmeasured_doc_bytes(source: str) -> float:
    """Average stored (_source) size of a random sample of this source's docs
    that have no measured doc_bytes (indexed before sizing was added), cached
    so the (relatively heavy) sample isn't repeated every refresh."""
    cached = _avg_doc_cache.get(source)
    if cached and time.time() - cached[0] < SAMPLE_TTL_SECONDS:
        return cached[1]
    body = {
        "size": SAMPLE_DOCS,
        "track_total_hits": False,
        "query": {"function_score": {
            "query": {"bool": {
                "filter": [{"term": {"share": source}}],
                "must_not": [{"exists": {"field": "doc_bytes"}}],
            }},
            "random_score": {},
        }},
    }
    hits = _os("POST", f"/{SEARCH_INDEX}/_search", body)["hits"]["hits"]
    sizes = [len(json.dumps(h["_source"], ensure_ascii=False).encode("utf-8")) for h in hits]
    avg = sum(sizes) / len(sizes) if sizes else 0.0
    _avg_doc_cache[source] = (time.time(), avg)
    return avg


def _read_history() -> list:
    snaps = []
    try:
        with open(HISTORY_PATH) as f:
            for line in f:
                try:
                    snaps.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        pass
    return snaps


def _record_history(data: dict) -> None:
    snaps = _read_history()
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
    tmp = HISTORY_PATH + ".tmp"
    with open(tmp, "w") as f:
        for snap in snaps:
            f.write(json.dumps(snap) + "\n")
    os.replace(tmp, HISTORY_PATH)


def _growth(current: dict):
    """Growth rate over the last GROWTH_WINDOW_DAYS from saved snapshots, or
    None until there is at least a day of history."""
    cutoff = time.time() - GROWTH_WINDOW_DAYS * 86400
    window = [s for s in _read_history() if s["ts"] >= cutoff]
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


def _collect_storage() -> dict:
    stats = _os("GET", f"/{SEARCH_INDEX}/_stats/store,docs")["_all"]
    index_bytes = stats["total"]["store"]["size_in_bytes"]   # all shard copies = real disk footprint
    docs = stats["primaries"]["docs"]["count"]
    deleted = stats["primaries"]["docs"].get("deleted", 0)

    nodes = list(_os("GET", "/_nodes/stats/fs")["nodes"].values())
    disk_total = sum(n["fs"]["total"]["total_in_bytes"] for n in nodes)
    disk_free = sum(n["fs"]["total"]["available_in_bytes"] for n in nodes)

    agg = _os("POST", f"/{SEARCH_INDEX}/_search", {
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
        legacy_bytes = legacy_docs * _avg_unmeasured_doc_bytes(b["key"]) if legacy_docs > 0 else 0.0
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
        "index": SEARCH_INDEX,
        "index_bytes": index_bytes,
        "docs": docs,
        "deleted_docs": deleted,
        "disk_total": disk_total,
        "disk_free": disk_free,
        "sample_docs": SAMPLE_DOCS,
        "sources": sources,
    }
    _record_history(data)
    data["growth"] = _growth(data)
    return data


def _storage_loop() -> None:
    while True:
        try:
            data = _collect_storage()
            with _storage_lock:
                _storage.update(data=data, error=None, updated=time.time())
        except Exception as exc:  # keep the last good data; surface the error on the page
            with _storage_lock:
                _storage["error"] = f"{type(exc).__name__}: {exc}"
        time.sleep(STORAGE_REFRESH_SECONDS)


class Handler(http.server.BaseHTTPRequestHandler):
    def _send_json(self, payload) -> None:
        data = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.startswith("/status.json"):
            self._send_json({"jobs": _collect_jobs()})
        elif self.path.startswith("/storage.json"):
            with _storage_lock:
                snapshot = dict(_storage)
            self._send_json(snapshot)
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(PAGE.encode())

    def log_message(self, format, *args):
        pass  # keep container logs quiet


if __name__ == "__main__":
    threading.Thread(target=_storage_loop, daemon=True).start()
    http.server.ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
