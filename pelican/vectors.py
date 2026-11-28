"""
Vector search plumbing in OpenSearch, shared by the setup job
(opensearch_setup.py, from .env) and index rebuilds (rebuild_index.py, from
the admin portal):

- a connector and remote model for a Text Embeddings Inference server,
- the ingest pipeline that splits `content` into passages and embeds them,
- the search pipeline that gives neural queries their model and blends
  hybrid scores,
- the index settings and fields that use them.

Every function takes `req(method, path, body=None, ok_missing=False)`,
which calls OpenSearch as whichever account the caller signs in with and
returns the parsed reply (None for a 404 when ok_missing), raising
RuntimeError otherwise.
"""

import re
import time

# Name of the ML Commons model group, and the prefix of every connector and
# model Pelican registers.
MODEL_GROUP = "pelican-embeddings"
# Fields written by the ingest pipeline (crawlers never write them).
CHUNK_FIELD = "content_chunks"
VECTOR_FIELD = "content_embedding"
DOC_VECTOR_FIELD = "content_embedding_mean"
VECTOR_FIELDS = (CHUNK_FIELD, VECTOR_FIELD, DOC_VECTOR_FIELD)
# One vector for the whole document: its passages' average, scaled to length 1.
# Kept in _source only, so it adds nothing to search or to the kNN graphs.
DOC_VECTOR_MAPPING = {"type": "float", "index": False, "doc_values": False}
# Temporary field the ingest pipeline splits into passages, then removes.
CHUNK_SOURCE_FIELD = "pelican_chunk_source"
# How long to wait for an embeddings server (first start downloads the model).
WAIT_SECONDS = 900


class VectorError(RuntimeError):
    """Vector search can't be set up as asked; the message says why."""


def chunk_source_chars(max_chunks: int, chunk_words: int) -> int:
    """The pipeline splits a copy of `content` cut to this many characters --
    room for max_chunks passages of chunk_words words at up to 8 characters a
    word -- so a huge document can't exceed the analyzer's token limit, which
    is raised to match (a token is at least one character)."""
    return max_chunks * chunk_words * 8


def index_settings(ingest_pipeline: str, search_pipeline: str, max_chunks: int, chunk_words: int) -> dict:
    """kNN on, the embedding pipeline run on every write (including roles.py's
    update_by_query, where it reuses existing vectors when the content hasn't
    changed), and the search pipeline for neural and hybrid queries."""
    return {
        "index.knn": True,
        "index.default_pipeline": ingest_pipeline,
        "index.search.default_pipeline": search_pipeline,
        "index.analyze.max_token_count": chunk_source_chars(max_chunks, chunk_words),
    }


def index_properties(dimension: int) -> dict:
    return {
        # Kept only so the pipeline can tell unchanged passages apart; not searched.
        CHUNK_FIELD: {"type": "text", "index": False},
        DOC_VECTOR_FIELD: DOC_VECTOR_MAPPING,
        VECTOR_FIELD: {
            "type": "nested",
            "properties": {"knn": {
                "type": "knn_vector",
                "dimension": dimension,
                "method": {"name": "hnsw", "engine": "faiss", "space_type": "cosinesimil"},
            }},
        },
    }


def trust_endpoint(req, url: str) -> None:
    """Let ML Commons call `url`, keeping endpoints already trusted (another
    index may still use them)."""
    current = req("GET", "/_cluster/settings?flat_settings=true")
    key = "plugins.ml_commons.trusted_connector_endpoints_regex"
    trusted = (current.get("persistent") or {}).get(key) or []
    if isinstance(trusted, str):
        trusted = [trusted]
    wanted = f"^{re.escape(url)}$"
    req("PUT", "/_cluster/settings", {"persistent": {
        "plugins.ml_commons.only_run_on_ml_node": False,
        # The embeddings server is on the compose network, at a private address.
        "plugins.ml_commons.connector.private_ip_enabled": True,
        key: trusted if wanted in trusted else [*trusted, wanted],
    }})


def find(req, kind: str, name: str) -> list[str]:
    """Ids of ML Commons objects (connectors, models, model_groups) by exact name."""
    res = req("POST", f"/_plugins/_ml/{kind}/_search",
              {"size": 100, "query": {"term": {"name.keyword": name}}}, ok_missing=True)
    return [h["_id"] for h in ((res or {}).get("hits") or {}).get("hits", [])]


def register_model(req, name: str, url: str, api_key: str, description: str) -> tuple[str, str]:
    """A connector to the TEI server at `url` and a deployed remote model
    using it, both called `name`. Returns (model_id, connector_id)."""
    groups = find(req, "model_groups", MODEL_GROUP)
    group_id = groups[0] if groups else req(
        "POST", "/_plugins/_ml/model_groups/_register",
        {"name": MODEL_GROUP, "description": "Pelican embedding models"})["model_group_id"]
    connector_id = req("POST", "/_plugins/_ml/connectors/_create", {
        "name": name,
        "description": f"Text Embeddings Inference at {url}",
        "version": 1,
        "protocol": "http",
        "parameters": {},
        "credential": {"api_key": api_key},
        # Seconds. A bulk write queues every passage of every document in it,
        # so allow for a long wait (on a CPU especially) and retry when the
        # server says it's overloaded rather than failing the write.
        "client_config": {"read_timeout": 300, "max_connection": 64, "max_retry_times": 5,
                          "retry_backoff_policy": "exponential_full_jitter", "retry_timeout_seconds": 300},
        "actions": [{
            "action_type": "predict",
            "method": "POST",
            "url": url,
            "headers": {"content-type": "application/json",
                        "Authorization": "Bearer ${credential.api_key}"},
            # truncate: a passage longer than the model's limit is cut, not rejected.
            "request_body": '{ "inputs": ${parameters.texts}, "truncate": true }',
            # Turns the pipeline's / query's text_docs into parameters.texts.
            "pre_process_function": "connector.pre_process.cohere.embedding",
            # TEI answers with a bare list of vectors.
            "post_process_function": "connector.post_process.default.embedding",
        }],
    })["connector_id"]
    model_id = req("POST", "/_plugins/_ml/models/_register?deploy=true", {
        # Not the model's own name: one with a "/" is taken as the model id.
        "name": name,
        "description": description,
        "function_name": "remote",
        "model_group_id": group_id,
        "connector_id": connector_id,
    })["model_id"]
    return model_id, connector_id


def wait_until_embeds(req, model_id: str, url: str, wait_seconds: int = WAIT_SECONDS, log=print) -> int:
    """Deploying is asynchronous, and the embeddings server downloads its
    model on first start, so retry a test embedding for a while. Returns the
    number of dimensions the model gives."""
    deadline = time.monotonic() + wait_seconds
    while True:
        try:
            out = req("POST", f"/_plugins/_ml/_predict/text_embedding/{model_id}", {"text_docs": ["test"]})
            return int(out["inference_results"][0]["output"][0]["shape"][0])
        except (RuntimeError, KeyError, IndexError, TypeError, ValueError) as exc:
            if time.monotonic() > deadline:
                raise VectorError(f"no embeddings from {url} after {wait_seconds}s: {str(exc)[:300]}")
            log(f"[vector] waiting for the embeddings server: {str(exc)[:200]}")
            time.sleep(10)


def delete_model(req, model_id: str, wait_seconds: float = 60) -> None:
    """Undeploy and delete a model and its connector; missing ones are ignored.
    Undeploying finishes in the background, and a model can't be deleted
    until it has, so the delete is retried for a while."""
    model = req("GET", f"/_plugins/_ml/models/{model_id}", ok_missing=True)
    if model is None:
        return
    deadline = time.monotonic() + wait_seconds
    while True:
        # Asked again each time: one sent while the model is still deploying is ignored.
        req("POST", f"/_plugins/_ml/models/{model_id}/_undeploy", {}, ok_missing=True)
        try:
            req("DELETE", f"/_plugins/_ml/models/{model_id}", ok_missing=True)
            break
        except RuntimeError as exc:
            if "undeploy" not in str(exc).lower() or time.monotonic() > deadline:
                raise
            time.sleep(2)
    if model.get("connector_id"):
        req("DELETE", f"/_plugins/_ml/connectors/{model['connector_id']}", ok_missing=True)


def ingest_pipeline(model_id: str, chunk_words: int, chunk_overlap: float, max_chunks: int) -> dict:
    return {
        "description": f"Pelican: split content into passages of {chunk_words} words and embed them",
        "processors": [
            # Only the start of a long document is embedded (max_chunks), so
            # split a copy cut to that size; see chunk_source_chars.
            {"script": {
                "source": "String c = ctx.content; if (c != null && c.length() > params.max) "
                          "{ c = c.substring(0, params.max); } ctx[params.field] = c;",
                "params": {"max": chunk_source_chars(max_chunks, chunk_words), "field": CHUNK_SOURCE_FIELD},
            }},
            {"text_chunking": {
                "algorithm": {"fixed_token_length": {
                    "token_limit": chunk_words, "overlap_rate": chunk_overlap,
                    "tokenizer": "standard", "max_chunk_limit": max_chunks}},
                "field_map": {CHUNK_SOURCE_FIELD: CHUNK_FIELD},
            }},
            {"remove": {"field": CHUNK_SOURCE_FIELD, "ignore_missing": True}},
            # No passages (no text): drop any vectors carried over from the
            # stored document by an update_by_query, which would otherwise
            # stay searchable and break the next write's skip_existing.
            {"script": {
                "source": "if (ctx[params.chunks] == null || ctx[params.chunks].isEmpty()) "
                          "{ ctx.remove(params.vectors); }",
                "params": {"chunks": CHUNK_FIELD, "vectors": VECTOR_FIELD},
            }},
            {"text_embedding": {
                "model_id": model_id,
                # Reuse stored vectors when the passages haven't changed, so
                # role-only updates (acl sync) don't re-embed anything.
                "skip_existing": True,
                "field_map": {CHUNK_FIELD: VECTOR_FIELD},
            }},
            # After embedding, so it sees reused vectors too. Runs on every write,
            # which fills it in on documents whose passages haven't changed.
            {"script": {"source": DOC_VECTOR_SCRIPT, "params": {"vectors": VECTOR_FIELD, "mean": DOC_VECTOR_FIELD}}},
        ],
    }


def search_pipeline(model_id: str) -> dict:
    return {
        "description": "Pelican: model id for neural queries, score blending for hybrid ones",
        "request_processors": [{"neural_query_enricher": {"default_model_id": model_id}}],
        "phase_results_processors": [{"normalization-processor": {
            "normalization": {"technique": "min_max"},
            "combination": {"technique": "arithmetic_mean", "parameters": {"weights": [0.5, 0.5]}},
        }}],
    }


def pipeline_model_ids(req, ingest_name: str | None, search_name: str | None) -> set[str]:
    """The models two pipelines call (to clean up after the index using them)."""
    ids = set()
    if ingest_name:
        p = (req("GET", f"/_ingest/pipeline/{ingest_name}", ok_missing=True) or {}).get(ingest_name) or {}
        ids |= {proc["text_embedding"]["model_id"] for proc in p.get("processors", []) if "text_embedding" in proc}
    if search_name:
        p = (req("GET", f"/_search/pipeline/{search_name}", ok_missing=True) or {}).get(search_name) or {}
        ids |= {proc["neural_query_enricher"]["default_model_id"] for proc in p.get("request_processors", [])
                if "neural_query_enricher" in proc}
    return ids


# The passages' average, scaled to length 1, or nothing if there are no passages.
DOC_VECTOR_SCRIPT = """
def passages = ctx[params.vectors];
ctx.remove(params.mean);
if (passages != null && !passages.isEmpty()) {
  double[] sum = null;
  for (def passage : passages) {
    def knn = passage.knn;
    if (sum == null) { sum = new double[knn.size()]; }
    for (int i = 0; i < sum.length; i++) { sum[i] += knn.get(i); }
  }
  double total = 0;
  for (int i = 0; i < sum.length; i++) { total += sum[i] * sum[i]; }
  double norm = Math.sqrt(total);
  if (norm > 0) {
    def mean = new ArrayList();
    for (int i = 0; i < sum.length; i++) { mean.add((float) (sum[i] / norm)); }
    ctx[params.mean] = mean;
  }
}
"""
