"""
Loads config/pelican.yaml (or PELICAN_CONFIG) once, with ${VAR} /
${VAR:-fallback} environment interpolation, and exposes the values every
crawler shares: OpenSearch target, role encoding, per-source host values,
state DB and status locations.
"""

import os
import re

import yaml

APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_DIR = os.path.join(APP_ROOT, "config")
CONFIG_PATH = os.environ.get("PELICAN_CONFIG", os.path.join(CONFIG_DIR, "pelican.yaml"))

# ${VAR} or ${VAR:-fallback}; the fallback may contain one level of braces.
_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-((?:[^{}]|\{[^{}]*\})*))?\}")


def _interpolate(value):
    if isinstance(value, str):
        def sub(m):
            v = os.environ.get(m.group(1))
            return v if v else (m.group(2) or "")
        return _ENV_REF.sub(sub, value)
    if isinstance(value, list):
        return [_interpolate(v) for v in value]
    if isinstance(value, dict):
        return {k: _interpolate(v) for k, v in value.items()}
    return value


def load_yaml(path: str) -> dict:
    """Read any Pelican YAML file with the same env interpolation."""
    with open(path) as f:
        return _interpolate(yaml.safe_load(f) or {})


def config_path(env_var: str, filename: str) -> str:
    """Location of a per-source config file: env override, else config/<filename>."""
    return os.environ.get(env_var) or os.path.join(CONFIG_DIR, filename)


_cfg = load_yaml(CONFIG_PATH)
_os = _cfg.get("opensearch") or {}
_roles = _cfg.get("roles") or {}
_prefixes = _roles.get("prefixes") or {}
_state = _cfg.get("state") or {}
_status = _cfg.get("status") or {}

OS_HOST: str = _os.get("host") or "http://opensearch:9200"
SEARCH_INDEX: str = _os.get("index") or "documents"
OS_TIMEOUT: int = int(_os.get("timeout_seconds") or 60)
OS_USERNAME: str = _os.get("username") or ""
OS_PASSWORD: str = _os.get("password") or ""
OS_CA_CERTS: str = _os.get("ca_certs") or ""
_mapping = _os.get("mapping_file") or "search_index_mapping.json"
INDEX_MAPPING_PATH: str = _mapping if os.path.isabs(_mapping) else os.path.join(APP_ROOT, _mapping)

PREFIX_USER: str = str(_prefixes.get("user", "1"))
PREFIX_GROUP: str = str(_prefixes.get("group", "2"))
PREFIX_ROLE: str = str(_prefixes.get("role", "R"))
EVERYONE_ROLE: str = f"{PREFIX_ROLE}{_roles.get('everyone', 'guest')}"
RESTRICTED_ROLE: str = f"{PREFIX_ROLE}{_roles.get('restricted', 'admin')}"

_sources = _cfg.get("sources") or {}
HOST_SMB: str = _sources.get("smb", "smb-share")
HOST_EXCHANGE: str = _sources.get("exchange", "exchange-online")
HOST_SHAREPOINT: str = _sources.get("sharepoint", "sharepoint-online")

_vector = _cfg.get("vector") or {}
VECTOR_ENABLED: bool = str(_vector.get("enabled", "false")).strip().lower() in ("true", "1", "yes", "on")
EMBEDDINGS_URL: str = _vector.get("embeddings_url") or "http://embeddings/embed"
EMBEDDINGS_API_KEY: str = _vector.get("api_key") or ""
EMBEDDINGS_MODEL: str = _vector.get("model") or "BAAI/bge-base-en-v1.5"
VECTOR_DIMENSION: int = int(_vector.get("dimension") or 768)
CHUNK_WORDS: int = int(_vector.get("chunk_words") or 300)
CHUNK_OVERLAP: float = float(_vector.get("chunk_overlap") or 0.1)
MAX_CHUNKS: int = int(_vector.get("max_chunks") or 100)
# Fixed names: the index refers to these pipelines, the setup job creates them.
INGEST_PIPELINE = "pelican-embed"
SEARCH_PIPELINE = "pelican-search"

STATE_DB_PATH: str = _state.get("db_path") or "/state/pelican_state.db"

STATUS_DIR: str = _status.get("dir") or "/status"
JOB_NAME: str = _status.get("job_name") or "primary"
# None = the container's local time (set TZ); a number pins a fixed offset.
_offset = _status.get("utc_offset_hours")
STATUS_UTC_OFFSET_HOURS: float | None = float(_offset) if _offset not in (None, "") else None
