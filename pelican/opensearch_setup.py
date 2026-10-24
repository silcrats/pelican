"""
OpenSearch security setup for the compose example, run as two one-shot jobs:

  python -m pelican.opensearch_setup certs   before OpenSearch starts
  python -m pelican.opensearch_setup users   once OpenSearch is healthy

`certs` creates a private CA, a server certificate for the `opensearch`
host and an admin client certificate in CERTS_DIR, if they're not there yet,
and gives the snapshot volume (SNAPSHOT_DIR) to OpenSearch. Run it as root:
it hands the server key and snapshot folder to OpenSearch's user (1000) and
the admin key to Pelican's (10001).

`users` signs in with the admin certificate and creates (or updates) the
accounts and their roles from environment variables:

  OS_PASSWORD          `pelican`: crawlers -- write to the index   (required)
  OS_STATUS_PASSWORD   `pelican-status`: status page -- read, stats (required)
  OS_READER_PASSWORD   `pelican-reader`: search UI -- read only    (optional)
  OS_ADMIN_PASSWORD    `admin`: full access, for you               (optional)

It then registers the snapshot repository and a snapshot policy for the
index (OpenSearch runs the policy itself):

  OS_SNAPSHOT_SCHEDULE   cron, in TZ (default UTC); default "0 2 * * *",
                         "off" to not set up backups
  OS_SNAPSHOT_KEEP       how many snapshots to keep (default 14)

With vector.enabled on (VECTOR_ENABLED=true; see config/pelican.yaml), it
also connects OpenSearch to the embeddings server (EMBEDDINGS_URL,
EMBEDDINGS_API_KEY) and creates the embedding and search pipelines, and
gives the crawler and reader accounts the ML permissions those need.

Re-running it applies password and schedule changes from the environment.
"""

import datetime
import ipaddress
import os
import re
import secrets
import sys
import time

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from . import index as index_mod
from . import settings

CERTS_DIR = os.environ.get("CERTS_DIR", "/certs")
SNAPSHOT_DIR = os.environ.get("SNAPSHOT_DIR", "/snapshots")
# Where OpenSearch sees the snapshot volume (path.repo in opensearch.yml).
SNAPSHOT_LOCATION = "/usr/share/opensearch/snapshots"
SNAPSHOT_REPOSITORY = "pelican-backups"
SNAPSHOT_POLICY = "pelican-daily"
OS_UID = 1000        # the OpenSearch image's user
PELICAN_UID = 10001  # the Pelican images' user
VALID_DAYS = 3650
# Name of the ML Commons connector and model group behind vector search.
VECTOR_CONNECTOR = "pelican-embeddings"
# How long to wait for the embeddings server (first start downloads the model).
VECTOR_WAIT_SECONDS = 900
# Temporary field the ingest pipeline splits into passages, then removes.
CHUNK_SOURCE_FIELD = "pelican_chunk_source"

NODE_DN = "CN=opensearch,O=Pelican"
ADMIN_DN = "CN=pelican-admin,O=Pelican"


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Pelican"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _write(name: str, data: bytes, mode: int, uid: int) -> None:
    path = os.path.join(CERTS_DIR, name)
    with open(path, "wb") as f:
        f.write(data)
    os.chmod(path, mode)
    os.chown(path, uid, uid)


def _issue(cn, ca_key, ca_name, usages, sans=None, ca=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(_name(cn))
               .issuer_name(ca_name or _name(cn))
               .public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(minutes=5))
               .not_valid_after(now + datetime.timedelta(days=VALID_DAYS))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
               # Python 3.13+ rejects certificates without these (strict X.509 checks).
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                   (ca_key or key).public_key()), critical=False)
               .add_extension(x509.KeyUsage(
                   digital_signature=not ca, key_encipherment=not ca, key_cert_sign=ca, crl_sign=ca,
                   content_commitment=False, data_encipherment=False, key_agreement=False,
                   encipher_only=False, decipher_only=False), critical=True))
    if usages:
        builder = builder.add_extension(x509.ExtendedKeyUsage(usages), critical=False)
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    cert = builder.sign(ca_key or key, hashes.SHA256())
    # OpenSearch only reads unencrypted PKCS#8 keys.
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    return key, cert, key_pem, cert.public_bytes(serialization.Encoding.PEM)


def make_certs() -> None:
    if os.path.isdir(SNAPSHOT_DIR):
        os.chown(SNAPSHOT_DIR, OS_UID, OS_UID)
    if os.path.exists(os.path.join(CERTS_DIR, "ca.pem")):
        print(f"[certs] {CERTS_DIR}/ca.pem exists, leaving certificates as they are")
        return
    os.makedirs(CERTS_DIR, exist_ok=True)
    ca_key, ca_cert, _, ca_pem = _issue("Pelican CA", None, None, None, ca=True)
    _, _, node_key, node_pem = _issue(
        "opensearch", ca_key, ca_cert.subject,
        [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH],
        sans=[x509.DNSName("opensearch"), x509.DNSName("localhost"),
              x509.IPAddress(ipaddress.ip_address("127.0.0.1"))])
    _, _, admin_key, admin_pem = _issue("pelican-admin", ca_key, ca_cert.subject,
                                        [ExtendedKeyUsageOID.CLIENT_AUTH])
    # The CA key isn't kept: delete the volume to re-issue everything.
    _write("ca.pem", ca_pem, 0o644, 0)
    _write("node.pem", node_pem, 0o644, OS_UID)
    _write("node-key.pem", node_key, 0o600, OS_UID)
    _write("admin.pem", admin_pem, 0o644, PELICAN_UID)
    _write("admin-key.pem", admin_key, 0o600, PELICAN_UID)
    print(f"[certs] created CA, server and admin certificates in {CERTS_DIR}, valid {VALID_DAYS} days")


def _request(method: str, path: str, body: dict | None = None, ok_missing: bool = False,
             auth: tuple[str, str] | None = None) -> dict | None:
    """Call OpenSearch with the admin certificate, or as `auth` (user,
    password) if given. With ok_missing, a 404 returns None instead of
    raising."""
    resp = requests.request(
        method, f"{settings.OS_HOST.rstrip('/')}{path}", json=body,
        auth=auth,
        cert=None if auth else (os.path.join(CERTS_DIR, "admin.pem"), os.path.join(CERTS_DIR, "admin-key.pem")),
        verify=os.path.join(CERTS_DIR, "ca.pem"), timeout=60)
    if ok_missing and resp.status_code == 404:
        return None
    if not resp.ok:
        raise RuntimeError(f"{method} {path}: {resp.status_code} {resp.text[:300]}")
    return resp.json()


def _api(method: str, path: str, body: dict) -> None:
    _request(method, f"/_plugins/_security/api/{path}", body)


def _account(user: str, password: str, role: str, role_body: dict | None) -> None:
    if role_body is not None:
        _api("PUT", f"roles/{role}", role_body)
    _api("PUT", f"internalusers/{user}", {"password": password})
    _api("PUT", f"rolesmapping/{role}", {"users": [user]})
    print(f"[users] {user}: role {role}")


def make_users() -> None:
    passwords = {k: os.environ.get(k, "") for k in
                 ("OS_PASSWORD", "OS_STATUS_PASSWORD", "OS_READER_PASSWORD", "OS_ADMIN_PASSWORD")}
    missing = [k for k in ("OS_PASSWORD", "OS_STATUS_PASSWORD") if not passwords[k]]
    if missing:
        sys.exit(f"[users] missing environment variable(s): {', '.join(missing)}")
    index = settings.SEARCH_INDEX
    if settings.VECTOR_ENABLED and not settings.EMBEDDINGS_API_KEY:
        sys.exit("[vector] vector.enabled is on but EMBEDDINGS_API_KEY is not set")
    # The embedding pipeline runs as the writer: it reads the model, calls it,
    # and (skip_existing) fetches the stored copy of each document. Neural
    # queries read the model and embed the search text as the searcher.
    ml_use = ["cluster:admin/opensearch/ml/models/get", "cluster:admin/opensearch/ml/predict"]
    crawler_vector = ["indices:data/read/mget", *ml_use] if settings.VECTOR_ENABLED else []
    reader_vector = ml_use if settings.VECTOR_ENABLED else []

    _account("pelican", passwords["OS_PASSWORD"], "pelican_crawler", {
        # Checked at cluster level: bulk writes, and the scroll and tasks
        # APIs behind the async update_by_query in roles.py.
        "cluster_permissions": ["indices:data/write/bulk", "indices:data/read/scroll",
                                "indices:data/read/scroll/clear", "cluster:monitor/task/get"] + crawler_vector,
        "index_permissions": [{
            "index_patterns": [index],
            # search_shards and refresh*: update_by_query (slices="auto", refresh=True)
            # and refreshing the index (refresh* includes the per-shard action).
            "allowed_actions": ["crud", "create_index", "indices:admin/get", "indices:admin/mappings/get",
                                "indices:admin/shards/search_shards", "indices:admin/refresh*"],
        }],
    })
    _account("pelican-status", passwords["OS_STATUS_PASSWORD"], "pelican_status", {
        "cluster_permissions": ["cluster:monitor/nodes/stats"],
        "index_permissions": [{"index_patterns": [index], "allowed_actions": ["read", "indices:monitor/stats"]}],
    })
    if passwords["OS_READER_PASSWORD"]:
        _account("pelican-reader", passwords["OS_READER_PASSWORD"], "pelican_reader", {
            "cluster_permissions": reader_vector,
            "index_permissions": [{"index_patterns": [index], "allowed_actions": ["read"]}],
        })
    if passwords["OS_ADMIN_PASSWORD"]:
        _account("admin", passwords["OS_ADMIN_PASSWORD"], "all_access", None)
    if settings.VECTOR_ENABLED:
        setup_vector()
    setup_snapshots(index)


def _find(kind: str, name: str, auth: tuple[str, str]) -> list[str]:
    """Ids of ML Commons objects (connectors, models, model_groups) by name."""
    res = _request("POST", f"/_plugins/_ml/{kind}/_search",
                   {"size": 100, "query": {"term": {"name.keyword": name}}}, ok_missing=True, auth=auth)
    return [h["_id"] for h in ((res or {}).get("hits") or {}).get("hits", [])]


def setup_vector() -> None:
    """Connect OpenSearch to the embeddings server and create the ingest and
    search pipelines the vector index uses (see index.add_vector_mapping).

    Each run registers a fresh connector and model (a connector can't be
    edited while its model is deployed), waits until it embeds, repoints both
    pipelines at it, then removes the ones it replaced.

    The ML calls run as a `pelican-ml` account with a password made up for
    this run: signed in with the admin certificate, ML Commons registers
    models it can't then find."""
    url = settings.EMBEDDINGS_URL
    ml_auth = ("pelican-ml", f"{secrets.token_urlsafe(24)}-Aa1!")
    _account(*ml_auth, "ml_full_access", None)

    def ml(method: str, path: str, body: dict | None = None, ok_missing: bool = False) -> dict | None:
        return _request(method, f"/_plugins/_ml/{path}", body, ok_missing=ok_missing, auth=ml_auth)

    _request("PUT", "/_cluster/settings", {"persistent": {
        "plugins.ml_commons.only_run_on_ml_node": False,
        # The embeddings server is on the compose network, at a private address.
        "plugins.ml_commons.connector.private_ip_enabled": True,
        "plugins.ml_commons.trusted_connector_endpoints_regex": [f"^{re.escape(url)}$"],
    }})

    old_models = _find("models", VECTOR_CONNECTOR, ml_auth)
    old_connectors = _find("connectors", VECTOR_CONNECTOR, ml_auth)
    group_ids = _find("model_groups", VECTOR_CONNECTOR, ml_auth)
    group_id = group_ids[0] if group_ids else ml(
        "POST", "model_groups/_register",
        {"name": VECTOR_CONNECTOR, "description": "Pelican embedding models"})["model_group_id"]

    connector_id = ml("POST", "connectors/_create", {
        "name": VECTOR_CONNECTOR,
        "description": f"Text Embeddings Inference at {url}",
        "version": 1,
        "protocol": "http",
        "parameters": {},
        "credential": {"api_key": settings.EMBEDDINGS_API_KEY},
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
    model_id = ml("POST", "models/_register?deploy=true", {
        # Not the model's own name: one with a "/" is taken as the model id.
        "name": VECTOR_CONNECTOR,
        "description": settings.EMBEDDINGS_MODEL,
        "function_name": "remote",
        "model_group_id": group_id,
        "connector_id": connector_id,
    })["model_id"]
    _wait_until_embeds(lambda: ml("POST", f"_predict/text_embedding/{model_id}", {"text_docs": ["test"]}))

    _request("PUT", f"/_ingest/pipeline/{settings.INGEST_PIPELINE}", {
        "description": "Pelican: split content into passages and embed them",
        "processors": [
            # Only the start of a long document is embedded (max_chunks), so
            # split a copy cut to that size; see index.CHUNK_SOURCE_CHARS.
            {"script": {
                "source": "String c = ctx.content; if (c != null && c.length() > params.max) "
                          "{ c = c.substring(0, params.max); } ctx[params.field] = c;",
                "params": {"max": index_mod.CHUNK_SOURCE_CHARS, "field": CHUNK_SOURCE_FIELD},
            }},
            {"text_chunking": {
                "algorithm": {"fixed_token_length": {
                    "token_limit": settings.CHUNK_WORDS, "overlap_rate": settings.CHUNK_OVERLAP,
                    "tokenizer": "standard", "max_chunk_limit": settings.MAX_CHUNKS}},
                "field_map": {CHUNK_SOURCE_FIELD: index_mod.CHUNK_FIELD},
            }},
            {"remove": {"field": CHUNK_SOURCE_FIELD, "ignore_missing": True}},
            # No passages (no text): drop any vectors carried over from the
            # stored document by an update_by_query, which would otherwise
            # stay searchable and break the next write's skip_existing.
            {"script": {
                "source": "if (ctx[params.chunks] == null || ctx[params.chunks].isEmpty()) "
                          "{ ctx.remove(params.vectors); }",
                "params": {"chunks": index_mod.CHUNK_FIELD, "vectors": index_mod.VECTOR_FIELD},
            }},
            {"text_embedding": {
                "model_id": model_id,
                # Reuse stored vectors when the passages haven't changed, so
                # role-only updates (acl sync) don't re-embed anything.
                "skip_existing": True,
                "field_map": {index_mod.CHUNK_FIELD: index_mod.VECTOR_FIELD},
            }},
        ],
    })
    _request("PUT", f"/_search/pipeline/{settings.SEARCH_PIPELINE}", {
        "description": "Pelican: model id for neural queries, score blending for hybrid ones",
        "request_processors": [{"neural_query_enricher": {"default_model_id": model_id}}],
        "phase_results_processors": [{"normalization-processor": {
            "normalization": {"technique": "min_max"},
            "combination": {"technique": "arithmetic_mean", "parameters": {"weights": [0.5, 0.5]}},
        }}],
    })

    for old in old_models:
        ml("POST", f"models/{old}/_undeploy", {}, ok_missing=True)
        ml("DELETE", f"models/{old}", ok_missing=True)
    for old in old_connectors:
        ml("DELETE", f"connectors/{old}", ok_missing=True)
    print(f"[vector] {settings.EMBEDDINGS_MODEL} at {url}: model {model_id}, "
          f"pipelines {settings.INGEST_PIPELINE} / {settings.SEARCH_PIPELINE}"
          f"{f', replaced {len(old_models)} older model(s)' if old_models else ''}")


def _wait_until_embeds(predict) -> None:
    """Deploying is asynchronous, and the embeddings server downloads its
    model on first start, so retry a test embedding for a while."""
    deadline = time.monotonic() + VECTOR_WAIT_SECONDS
    while True:
        try:
            out = predict()
            dim = out["inference_results"][0]["output"][0]["shape"][0]
            if dim != settings.VECTOR_DIMENSION:
                sys.exit(f"[vector] {settings.EMBEDDINGS_MODEL} returns {dim} dimensions, "
                         f"vector.dimension is {settings.VECTOR_DIMENSION}")
            return
        except RuntimeError as exc:
            if time.monotonic() > deadline:
                sys.exit(f"[vector] no embeddings from {settings.EMBEDDINGS_URL} after "
                         f"{VECTOR_WAIT_SECONDS}s: {exc}")
            print(f"[vector] waiting for the embeddings server: {str(exc)[:200]}")
            time.sleep(10)


def setup_snapshots(index: str) -> None:
    schedule = os.environ.get("OS_SNAPSHOT_SCHEDULE") or "0 2 * * *"
    if schedule.lower() == "off":
        print("[snapshots] OS_SNAPSHOT_SCHEDULE=off, not setting up backups")
        return
    keep = int(os.environ.get("OS_SNAPSHOT_KEEP") or 14)
    tz = os.environ.get("TZ") or "UTC"
    _request("PUT", f"/_snapshot/{SNAPSHOT_REPOSITORY}",
             {"type": "fs", "settings": {"location": SNAPSHOT_LOCATION}})
    policy = {
        "description": f"Snapshot of the {index} index",
        "creation": {"schedule": {"cron": {"expression": schedule, "timezone": tz}}},
        # Old snapshots are pruned an hour after each creation run.
        "deletion": {
            "schedule": {"cron": {"expression": _an_hour_later(schedule), "timezone": tz}},
            "condition": {"max_count": keep, "min_count": 1},
        },
        "snapshot_config": {
            "indices": index,
            "repository": SNAPSHOT_REPOSITORY,
            "include_global_state": False,
            "ignore_unavailable": True,   # no index yet before the first crawl
            "date_format": "yyyy-MM-dd-HH-mm",
        },
    }
    path = f"/_plugins/_sm/policies/{SNAPSHOT_POLICY}"
    existing = _request("GET", path, ok_missing=True)
    if existing is None:
        _request("POST", path, policy)
    else:  # updates must name the version they replace
        _request("PUT", f"{path}?if_seq_no={existing['_seq_no']}&if_primary_term={existing['_primary_term']}",
                 policy)
    print(f"[snapshots] {index} -> repository {SNAPSHOT_REPOSITORY}: cron \"{schedule}\" ({tz}), keep {keep}")


def _an_hour_later(cron: str) -> str:
    """The same schedule one hour later, for the pruning run. Falls back to
    hourly at :30 if the hour field isn't a plain number."""
    fields = cron.split()
    if len(fields) == 5 and fields[1].isdigit():
        fields[1] = str((int(fields[1]) + 1) % 24)
        return " ".join(fields)
    return "30 * * * *"


if __name__ == "__main__":
    commands = {"certs": make_certs, "users": make_users}
    if len(sys.argv) != 2 or sys.argv[1] not in commands:
        sys.exit(f"usage: python -m pelican.opensearch_setup {{{'|'.join(commands)}}}")
    commands[sys.argv[1]]()
