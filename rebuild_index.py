"""
Index jobs from the admin portal's Index page, run by a worker:

  check          sign in to an embeddings server through OpenSearch and embed
                 a test sentence; nothing else changes
  rebuild        build a new copy of the index with the vector settings asked
                 for (or without vectors), from the documents already in the
                 index -- nothing is crawled again -- then switch search to it
  switch_back    point search at the previous index again
  drop_previous  delete the previous index, and its model and pipelines
  tidy           remove what a rebuild that never finished (its worker
                 stopped) left behind; rebuild and drop_previous do this first

The index name (SEARCH_INDEX, e.g. `documents`) becomes an alias of
numbered indexes (`documents-1`, `documents-2`, ...). The first rebuild of a
plain index copies it to the first number (a clone: instant, and shares its
files on disk), so it can be kept as the previous index, and then frees the
name for the alias. Each rebuild with vectors registers its own model and
pipelines (pelican-embed-<n>, pelican-search-<n>), so the index in use keeps
working while the next one is built; the copy re-embeds every document. One
previous index is kept to switch back to; a rebuild deletes any older one.

The portal holds crawls, ACL syncs and removals while a rebuild or switch
runs, so nothing is written to the index meanwhile.

Runs as the pelican-maintainer OpenSearch account (OS_MAINT_USERNAME,
OS_MAINT_PASSWORD). The job comes as JSON in INDEX_OP:
  {"action": "rebuild", "requested_by": "...", "vectors": null | {
      "embeddings_url": ..., "model": ..., "chunk_words": 300,
      "chunk_overlap": 0.1, "max_chunks": 100}}
"""

import datetime
import json
import os
import re
import signal
import sys
import time

import requests

from pelican import settings, vectors

ALIAS = settings.SEARCH_INDEX
NUMBERED = re.compile(rf"^{re.escape(ALIAS)}-(\d+)$")
MAINT_USER = os.environ.get("OS_MAINT_USERNAME") or "pelican-maintainer"
MAINT_PASSWORD = os.environ.get("OS_MAINT_PASSWORD", "")
STATUS_FILE = os.path.join(settings.STATUS_DIR, "status-index.json")
POLL_SECONDS = 10
CHECK_WAIT_SECONDS = 180
# Documents per batch the copy reads. Each is embedded on the way in, and a
# document can have up to max_chunks passages, so keep batches small then.
BATCH_PLAIN, BATCH_VECTORS = 500, 25
REMOVE_VECTORS = "; ".join(f"ctx._source.remove('{f}')" for f in vectors.VECTOR_FIELDS)

_session = requests.Session()
_session.auth = (MAINT_USER, MAINT_PASSWORD)
_session.verify = settings.OS_CA_CERTS or True
cancelled = False


class Failed(Exception):
    """The job can't go on; the message is shown in the portal."""


def req(method: str, path: str, body=None, ok_missing: bool = False, timeout: float = 120):
    resp = _session.request(method, settings.OS_HOST.rstrip("/") + path, json=body, timeout=timeout)
    if ok_missing and resp.status_code == 404:
        return None
    if not resp.ok:
        raise RuntimeError(f"{method} {path.split('?')[0]}: {resp.status_code} {resp.text[:300]}")
    return resp.json() if resp.content else {}


def progress(text: str) -> None:
    """Running status for the portal (the worker sends it with each heartbeat)."""
    try:
        tmp = STATUS_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"progress": text}, f)
        os.replace(tmp, STATUS_FILE)
    except OSError:
        pass


def _on_signal(signum, frame):
    global cancelled
    cancelled = True


def check_cancel() -> None:
    if cancelled:
        raise Failed("cancelled")


# ----------------------------------------------------------- the indexes

def layout() -> tuple[str | None, bool, dict]:
    """(live, plain, numbered): the index searches go to (None if there's
    none), whether ALIAS is still a plain index rather than an alias, and
    every numbered index with its settings and mapping."""
    numbered = {name: info for name, info in (req("GET", f"/{ALIAS}-*") or {}).items() if NUMBERED.match(name)}
    # Keyed by the real index: the name itself while it's a plain index.
    # (/_alias/<name> would need rights on every index.)
    live = next(iter(req("GET", f"/{ALIAS}/_alias", ok_missing=True) or {}), None)
    return live, live == ALIAS, numbered


def number(name: str) -> int:
    m = NUMBERED.match(name)
    return int(m.group(1)) if m else 0


def index_info(name: str) -> dict:
    return next(iter(req("GET", f"/{name}").values()))


def count(name: str, query: dict | None = None) -> int:
    return req("POST", f"/{name}/_count", {"query": query or {"match_all": {}}})["count"]


def with_vectors_query() -> dict:
    return {"nested": {"path": vectors.VECTOR_FIELD, "query": {"exists": {"field": f"{vectors.VECTOR_FIELD}.knn"}}}}


def pipelines_of(info: dict) -> tuple[str | None, str | None]:
    s = (info.get("settings") or {}).get("index") or {}
    return s.get("default_pipeline"), (s.get("search") or {}).get("default_pipeline")


def remove_index(name: str, keep: dict | None = None) -> None:
    """Delete an index, then the pipelines and models only it used (not those
    of `keep`, the live index's info)."""
    info = req("GET", f"/{name}", ok_missing=True)
    if info is None:
        return
    info = next(iter(info.values()))
    ingest, search = pipelines_of(info)
    models = vectors.pipeline_model_ids(req, ingest, search)
    keep_ingest, keep_search = pipelines_of(keep) if keep else (None, None)
    keep_models = vectors.pipeline_model_ids(req, keep_ingest, keep_search) if keep else set()
    req("DELETE", f"/{name}", ok_missing=True)
    for kind, pipeline, kept in (("_ingest", ingest, keep_ingest), ("_search", search, keep_search)):
        if pipeline and pipeline != kept:
            req("DELETE", f"/{kind}/pipeline/{pipeline}", ok_missing=True)
    for model_id in models - keep_models:
        vectors.delete_model(req, model_id)
    print(f"deleted {name}" + (f" and its model and pipelines" if models - keep_models else ""))


def built(info: dict) -> dict:
    return ((info.get("mappings") or {}).get("_meta") or {}).get("pelican") or {}


def leftovers(live: str | None, plain: bool, numbered: dict) -> list[str]:
    """Numbered indexes a rebuild that didn't finish left behind: before the
    first switch there should be none; after it, every one but the previous
    index has been live (switched_at)."""
    if plain:
        return sorted(numbered)
    return sorted(name for name, info in numbered.items()
                  if name != live and built(info) and not built(info).get("switched_at"))


def tidy() -> tuple[str | None, bool, dict]:
    """Remove an unfinished rebuild's indexes and models, and let writes back
    into a plain index it had blocked. Returns layout() afterwards."""
    live, plain, numbered = layout()
    keep = index_info(live) if live else None
    for name in leftovers(live, plain, numbered):
        print(f"{name} was left by a rebuild that didn't finish")
        remove_index(name, keep)
    if plain and str(((keep or {}).get("settings") or {}).get("index", {}).get("blocks", {}).get("write")) == "true":
        req("PUT", f"/{ALIAS}/_settings", {"index.blocks.write": None})
        print(f"let writes back into {ALIAS}, blocked by a rebuild that didn't finish")
    live, plain, numbered = layout()
    # Models of Pelican's that no remaining index's pipelines use.
    used = set()
    for name, info in ({**numbered, **({live: index_info(live)} if live else {})}).items():
        used |= vectors.pipeline_model_ids(req, *pipelines_of(info))
    res = req("POST", "/_plugins/_ml/models/_search", {"size": 100, "query": {
        "prefix": {"name.keyword": f"{vectors.MODEL_GROUP}-"}}}, ok_missing=True) or {}
    for hit in (res.get("hits") or {}).get("hits", []):
        if hit["_id"] not in used and "model_group_id" in hit.get("_source", {}):
            print(f"removing model {hit['_source'].get('name')} ({hit['_id']}), which no index uses")
            vectors.delete_model(req, hit["_id"])
    return live, plain, numbered


def describe(info: dict) -> str:
    meta = built(info)
    if (info.get("mappings") or {}).get("properties", {}).get(vectors.VECTOR_FIELD):
        return f"vectors from {meta.get('model') or 'the model set in .env'}"
    return "no vectors"


# ----------------------------------------------------------- the actions

def check(spec: dict) -> None:
    want = spec.get("vectors") or {}
    url = want.get("embeddings_url") or ""
    if not url:
        raise Failed("no embeddings server given")
    progress(f"asking {url} for a test embedding")
    vectors.trust_endpoint(req, url)
    name = f"{vectors.MODEL_GROUP}-check-{int(time.time())}"
    model_id, _ = vectors.register_model(req, name, url, settings.EMBEDDINGS_API_KEY, want.get("model") or "")
    try:
        dim = vectors.wait_until_embeds(req, model_id, url, CHECK_WAIT_SECONDS)
        started = time.monotonic()
        vectors.wait_until_embeds(req, model_id, url, 0)
        took = time.monotonic() - started
    finally:
        vectors.delete_model(req, model_id)
    print(f"{url} answers: {dim}-dimension vectors, {took:.2f} s for a test sentence")


def rebuild(spec: dict) -> None:
    want = spec.get("vectors")
    live, plain, numbered = tidy()
    if live is None:
        raise Failed(f"there's no '{ALIAS}' index yet: crawl a source first")
    older = [name for name in numbered if name != live]   # deleted once the new index is live
    n = max([number(name) for name in numbered] + [0]) + 1
    made: list[str] = []          # to undo on failure
    source = live
    blocked = False
    try:
        if plain:
            # The alias needs the name, so keep the plain index under a number
            # instead. A clone shares the index's files, so it's quick and
            # takes almost no extra space; it needs writes blocked meanwhile
            # (the portal holds crawls anyway).
            source = f"{ALIAS}-{n}"
            n += 1
            progress(f"keeping {ALIAS} as {source}")
            req("PUT", f"/{ALIAS}/_settings", {"index.blocks.write": True})
            blocked = True
            req("POST", f"/{ALIAS}/_clone/{source}", {"settings": {"index.blocks.write": None}}, timeout=600)
            made.append(source)
            req("GET", f"/_cluster/health/{source}?wait_for_status=yellow&timeout=300s", timeout=330)
            print(f"kept {ALIAS} as {source} (a clone)")
        target = f"{ALIAS}-{n}"
        source_info = index_info(source)
        total = count(source)
        print(f"building {target} from {source}: {total:,} documents, "
              f"{'vectors from ' + want['model'] if want else 'no vectors'}")

        meta = {"generation": n, "vectors": bool(want), "built_from": source,
                "built_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                "built_by": spec.get("requested_by") or ""}
        index_settings = {"number_of_shards": int(source_info["settings"]["index"]["number_of_shards"]),
                          # Put back once the copy is done.
                          "number_of_replicas": 0, "refresh_interval": "-1"}
        properties = {k: v for k, v in source_info["mappings"].get("properties", {}).items()
                      if k not in vectors.VECTOR_FIELDS}
        if want:
            check_cancel()
            url = want["embeddings_url"]
            progress(f"connecting to {url}")
            vectors.trust_endpoint(req, url)
            model_id, _ = vectors.register_model(req, f"{vectors.MODEL_GROUP}-{n}", url,
                                                 settings.EMBEDDINGS_API_KEY, want["model"])
            ingest, search = f"{settings.INGEST_PIPELINE}-{n}", f"{settings.SEARCH_PIPELINE}-{n}"
            made += [f"model:{model_id}"]
            dim = vectors.wait_until_embeds(req, model_id, url, CHECK_WAIT_SECONDS)
            req("PUT", f"/_ingest/pipeline/{ingest}", vectors.ingest_pipeline(
                model_id, want["chunk_words"], want["chunk_overlap"], want["max_chunks"]))
            made.append(f"ingest:{ingest}")
            req("PUT", f"/_search/pipeline/{search}", vectors.search_pipeline(model_id))
            made.append(f"search:{search}")
            index_settings.update(vectors.index_settings(ingest, search, want["max_chunks"], want["chunk_words"]))
            properties.update(vectors.index_properties(dim))
            meta.update({k: want[k] for k in ("embeddings_url", "model", "chunk_words", "chunk_overlap",
                                              "max_chunks")})
            meta.update({"dimension": dim, "model_id": model_id})
            print(f"{want['model']} at {url}: {dim} dimensions, model {model_id}, pipelines {ingest} / {search}")
        mappings = {k: v for k, v in source_info["mappings"].items() if k not in ("properties", "_meta")}
        mappings.update({"properties": properties, "_meta": {"pelican": meta}})
        req("PUT", f"/{target}", {"settings": index_settings, "mappings": mappings})
        made.append(target)

        copied = copy(source, target, total, bool(want))
        progress("checking the copy")
        req("POST", f"/{target}/_refresh")
        got = count(target)
        if got != total:
            raise Failed(f"the copy has {got:,} documents, {source} has {total:,}; search stays on {live}")
        embedded = count(target, with_vectors_query()) if want else 0
        replicas = source_info["settings"]["index"].get("number_of_replicas", "0")
        req("PUT", f"/{target}/_settings", {"index": {"number_of_replicas": int(replicas), "refresh_interval": None}})

        progress("switching search to the new index")
        check_cancel()
        actions = [{"add": {"index": target, "alias": ALIAS}}]
        actions.append({"remove_index": {"index": ALIAS}} if plain else {"remove": {"index": live, "alias": ALIAS}})
        req("POST", "/_aliases", {"actions": actions})
        made = []   # live now: nothing to undo
        blocked = False
        meta["switched_at"] = time.time()
        meta["documents"] = got
        req("PUT", f"/{target}/_mapping", {"_meta": {"pelican": meta}})
        print(f"search now uses {target}: {got:,} documents"
              + (f", {embedded:,} with vectors ({got - embedded:,} have no text to embed)" if want else "")
              + f", copied in {copied}")
    except BaseException:
        undo(made, plain and blocked)
        raise
    keep = index_info(target)
    for name in older:
        remove_index(name, keep)
    print(f"done: {target} is live; {source} is kept as the previous index")


def copy(source: str, target: str, total: int, embed: bool) -> str:
    """Reindex source -> target (through target's pipeline, which embeds),
    leaving out the old vectors. Returns how long it took, as text."""
    started = time.monotonic()
    task = req("POST", "/_reindex?wait_for_completion=false&slices=auto", {
        "source": {"index": source, "size": BATCH_VECTORS if embed else BATCH_PLAIN},
        "dest": {"index": target},
        "script": {"lang": "painless", "source": REMOVE_VECTORS},
    })["task"]
    print(f"copying ({'embedding every document' if embed else 'no embedding'}), task {task}")
    while True:
        time.sleep(POLL_SECONDS)
        if cancelled:
            req("POST", f"/_tasks/{task}/_cancel", {}, ok_missing=True)
            raise Failed("cancelled")
        t = req("GET", f"/_tasks/{task}")
        done = copied_so_far(task, (t.get("task") or {}).get("status") or {})
        elapsed = time.monotonic() - started
        if t.get("completed"):
            if t.get("error"):
                raise Failed(f"the copy failed: {json.dumps(t['error'])[:400]}")
            failures = (t.get("response") or {}).get("failures") or []
            if failures:
                raise Failed(f"the copy failed on {len(failures)} document(s), e.g.: {json.dumps(failures[0])[:400]}")
            return _duration(elapsed)
        left = ""
        if done and total > done:
            left = f" · about {_duration(elapsed / done * (total - done))} left"
        progress(f"{done:,} of {total:,} documents copied ({done / max(total, 1):.0%}){left}")


def copied_so_far(task: str, status: dict) -> int:
    """Documents copied so far. A sliced copy's own status only counts slices
    that have finished, so add up the running ones' too."""
    done = status.get("created", 0) + status.get("updated", 0)
    try:
        running = req("GET", f"/_tasks?parent_task_id={task}&detailed=true")
        for node in (running.get("nodes") or {}).values():
            for child in (node.get("tasks") or {}).values():
                cs = child.get("status") or {}
                done += cs.get("created", 0) + cs.get("updated", 0)
    except RuntimeError:
        pass   # then only the finished slices show
    return done


def undo(made: list[str], unblock: bool) -> None:
    """Remove what a failed or cancelled rebuild made; search stays where it was."""
    for item in reversed(made):
        try:
            kind, _, name = item.partition(":") if ":" in item else ("index", "", item)
            if kind == "index":
                req("DELETE", f"/{name}", ok_missing=True)
            elif kind == "model":
                vectors.delete_model(req, name)
            elif kind == "ingest":
                req("DELETE", f"/_ingest/pipeline/{name}", ok_missing=True)
            elif kind == "search":
                req("DELETE", f"/_search/pipeline/{name}", ok_missing=True)
        except Exception as exc:
            print(f"couldn't remove {item}: {exc}")
    if unblock:
        try:
            req("PUT", f"/{ALIAS}/_settings", {"index.blocks.write": None})
        except Exception as exc:
            print(f"couldn't let writes back into {ALIAS}: {exc}")
    if made:
        print("removed what this rebuild had made; search is unchanged")


def switch_back(spec: dict) -> None:
    live, plain, numbered = layout()
    others = sorted((name for name in numbered if name != live), key=number)
    if plain or not others:
        raise Failed("there's no previous index to switch back to")
    previous = others[-1]
    req("POST", "/_aliases", {"actions": [{"add": {"index": previous, "alias": ALIAS}},
                                          {"remove": {"index": live, "alias": ALIAS}}]})
    print(f"search uses {previous} again ({describe(numbered[previous])}); {live} is kept as the previous index")


def drop_previous(spec: dict) -> None:
    live, plain, numbered = tidy()
    others = [name for name in numbered if name != live]
    if not others:
        print("there's no previous index")
        return
    keep = numbered.get(live) or (index_info(live) if live else None)
    for name in others:
        remove_index(name, keep)


def _duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 90:
        return f"{seconds} s"
    if seconds < 5400:
        return f"{round(seconds / 60)} min"
    return f"{seconds // 3600} h {round(seconds % 3600 / 60)} min"


def tidy_up(spec: dict) -> None:
    tidy()
    print("tidied up")


ACTIONS = {"check": check, "rebuild": rebuild, "switch_back": switch_back, "drop_previous": drop_previous,
           "tidy": tidy_up}


def main() -> int:
    if not MAINT_PASSWORD:
        print("OS_MAINT_PASSWORD isn't set on this worker: index jobs need the pelican-maintainer account")
        return 2
    try:
        spec = json.loads(os.environ.get("INDEX_OP") or "{}")
    except ValueError:
        spec = {}
    action = ACTIONS.get(spec.get("action"))
    if not action:
        print(f"unknown index job: {spec.get('action')!r}")
        return 2
    signal.signal(signal.SIGTERM, _on_signal)
    try:
        action(spec)
    except Failed as exc:
        print(f"{exc}")
        return 1
    except (vectors.VectorError, RuntimeError, requests.RequestException) as exc:
        print(f"failed: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
