"""
The OpenSearch side shared by every crawler: the client, index bootstrap,
document ids, the document schema (build_doc), and bulk write/delete.

Every crawler writes the same schema (see search_index_mapping.json) so a
search UI sees SMB files, mail and SharePoint together; only `host` differs
per crawler (settings.HOST_*).
"""

import hashlib
import json
import os
import time
from pathlib import Path

from opensearchpy import OpenSearch, helpers

from . import settings

SEARCH_INDEX = settings.SEARCH_INDEX
# OpenSearch refuses any JSON string over 50 million characters, so a huge
# text file would fail on every crawl (and, through an ingest pipeline, take
# others in its bulk batch with it). Its text is cut to this length.
MAX_CONTENT_CHARS = int(os.environ.get("MAX_CONTENT_CHARS", "10000000"))

client = OpenSearch(
    hosts=[settings.OS_HOST],
    timeout=settings.OS_TIMEOUT,   # the client default (10s) is too tight once multiple
                                   # crawlers write concurrently and the cluster is under real load
    max_retries=3,
    retry_on_timeout=True,         # transient slow responses get retried instead of aborting a whole source
    http_auth=(settings.OS_USERNAME, settings.OS_PASSWORD) if settings.OS_USERNAME else None,
    verify_certs=True,             # https hosts only; plain http ignores it
    ca_certs=settings.OS_CA_CERTS or None,
)


# Vector search (settings.VECTOR_ENABLED): the ingest pipeline splits
# `content` into CHUNK_FIELD and embeds each passage into VECTOR_FIELD, one
# nested {"knn": [...]} object per passage. Crawlers never write either.
CHUNK_FIELD = "content_chunks"
VECTOR_FIELD = "content_embedding"
# The pipeline splits a copy of `content` cut to this many characters --
# room for max_chunks passages of chunk_words words at up to 8 characters a
# word -- so a huge document can't exceed the analyzer's token limit, which
# is raised to match (a token is at least one character).
CHUNK_SOURCE_CHARS = settings.MAX_CHUNKS * settings.CHUNK_WORDS * 8


def add_vector_mapping(mapping: dict) -> None:
    """Extend the index body from search_index_mapping.json for vector
    search: kNN on, the embedding pipeline run on every write (including
    roles.py's update_by_query, where it reuses existing vectors when the
    content hasn't changed), and the search pipeline that supplies the model
    id to neural queries and blends hybrid scores."""
    mapping.setdefault("settings", {}).update({
        "index.knn": True,
        "index.default_pipeline": settings.INGEST_PIPELINE,
        "index.search.default_pipeline": settings.SEARCH_PIPELINE,
        "index.analyze.max_token_count": CHUNK_SOURCE_CHARS,
    })
    mapping.setdefault("mappings", {}).setdefault("properties", {}).update({
        # Kept only so the pipeline can tell unchanged passages apart; not searched.
        CHUNK_FIELD: {"type": "text", "index": False},
        VECTOR_FIELD: {
            "type": "nested",
            "properties": {"knn": {
                "type": "knn_vector",
                "dimension": settings.VECTOR_DIMENSION,
                "method": {"name": "hnsw", "engine": "faiss", "space_type": "cosinesimil"},
            }},
        },
    })


def ensure_index_exists() -> None:
    """Create the index with our own explicit mapping if it doesn't exist
    yet -- makes a fresh OpenSearch instance self-sufficient on first run,
    rather than relying on dynamic mapping (which can silently pick a
    different, less predictable type for a field like "share").

    With multiple crawlers starting close together, a plain check-then-create
    has a real race: two containers can both see "does not exist" and both
    attempt to create it, and the loser would crash on startup. Catch that
    specific case and treat it as success instead."""
    already_exists = client.indices.exists(index=SEARCH_INDEX)
    print(f"[bootstrap] client.indices.exists('{SEARCH_INDEX}') = {already_exists}")
    if already_exists:
        try:
            real_mapping = client.indices.get_mapping(index=SEARCH_INDEX)
            print(f"[bootstrap] index already exists, current mapping: {json.dumps(real_mapping)}")
            has_vectors = VECTOR_FIELD in real_mapping[SEARCH_INDEX]["mappings"].get("properties", {})
            if settings.VECTOR_ENABLED and not has_vectors:
                print(f"[bootstrap] WARNING: vector.enabled is on but '{SEARCH_INDEX}' was created without "
                      f"vectors -- new documents won't be embedded until the index is recreated")
        except Exception as exc:
            print(f"[bootstrap] index exists but get_mapping failed: {exc}")
        return
    with open(settings.INDEX_MAPPING_PATH) as f:
        mapping = json.load(f)
    if settings.VECTOR_ENABLED:
        add_vector_mapping(mapping)
    print(f"[bootstrap] index does not exist -- attempting to create with our mapping"
          f"{' (with vectors)' if settings.VECTOR_ENABLED else ''}")
    try:
        client.indices.create(index=SEARCH_INDEX, body=mapping)
        print(f"[bootstrap] Created index '{SEARCH_INDEX}' with purpose-built mapping")
    except Exception as exc:
        print(f"[bootstrap] create() raised: {type(exc).__name__}: {exc}")
        if "resource_already_exists_exception" in str(exc):
            print(f"[bootstrap] index was created by another crawler instance in the same moment -- continuing")
        else:
            raise


def doc_id(key: str) -> str:
    """Stable document _id for a source key (an smb:// URL, or a Graph
    ID-based key for mail/SharePoint so moves and renames don't duplicate)."""
    return hashlib.md5(key.encode("utf-8")).hexdigest()


_MIME_TYPES = {
    "pdf": "application/pdf",
    "eml": "message/rfc822",
    "msg": "application/vnd.ms-outlook",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "txt": "text/plain",
    "csv": "text/csv",
    "html": "text/html",
    "htm": "text/html",
    "xml": "application/xml",
    "json": "application/json",
}

# Optional fields copied from extract_text()'s metadata when present.
_EMAIL_FIELDS = ("email_from", "email_to", "email_cc", "email_subject", "email_attachments", "email_message_id")
_IMAGE_FIELDS = ("image_camera_make", "image_camera_model", "image_location")
_IMAGE_NUMERIC_FIELDS = ("image_gps_lat", "image_gps_lon")   # 0.0 is a real value, so presence not truthiness


def build_doc(url: str, filename: str, text: str, roles: list[str], raw_size: int,
              meta: dict, share_name: str, file_mtime_epoch: float, host: str,
              id_key: str | None = None, acl_group: str | None = None) -> dict:
    """One bulk-index action in the shared schema.

    url        what a user opens/downloads (smb:// URL, Outlook or SharePoint web link)
    id_key     key the _id is derived from; defaults to url
    share_name the source entry this came from (share / mailbox / site name)
    host       which crawler wrote it (settings.HOST_*)
    acl_group  SMB only -- see acl_sync"""
    real_modified = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(file_mtime_epoch))
    ext = Path(filename).suffix.lstrip(".").lower() or "other"
    if text and len(text) > MAX_CONTENT_CHARS:
        print(f"  '{filename}': keeping the first {MAX_CONTENT_CHARS:,} of {len(text):,} characters of text")
        text = text[:MAX_CONTENT_CHARS]
    source = {
        "url": url,
        "share": share_name,
        "host": host,
        "title": filename,
        "filename": filename,
        "content": text,
        "role": roles,
        "filetype": ext,
        "mimetype": _MIME_TYPES.get(ext, "application/octet-stream"),
        "content_length": raw_size,
        # "timestamp" is the primary date shown/filtered in the UI: for
        # emails, the real Date header (send/received time); for images,
        # EXIF's capture time if present; otherwise the file's real
        # modification time. Never the moment this pipeline happened to index it.
        "timestamp": meta.get("email_date") or meta.get("image_date_taken") or real_modified,
        "last_modified": real_modified,  # always the real file mtime, distinct from an email's own date
    }
    # Email fields: populated only for .eml/.msg -- lets the search UI filter
    # by sender/recipient directly instead of only full-text-matching against
    # the "From: .../To: ..." lines embedded in content. Image fields:
    # populated only for images with EXIF data -- see extract_text.
    for field in _EMAIL_FIELDS + _IMAGE_FIELDS:
        if meta.get(field):
            source[field] = meta[field]
    for field in _IMAGE_NUMERIC_FIELDS:
        if field in meta:
            source[field] = meta[field]
    # SMB only: the ACL group (directory, or file if acl_scope: file) this document's
    # permissions were computed from -- lets acl_sync re-apply a later permission
    # change to every document in the group without re-downloading it.
    if acl_group is not None:
        source["acl_group"] = acl_group

    # Serialized size of this document as indexed. Lets the status page work
    # out how much of the index each source accounts for from measured sizes
    # rather than a sample. Set last so it covers every field above.
    source["doc_bytes"] = len(json.dumps(source, ensure_ascii=False).encode("utf-8"))

    return {"_index": SEARCH_INDEX, "_id": doc_id(id_key or url), "_source": source}


def bulk_index(actions: list[dict]) -> None:
    helpers.bulk(client, actions)


def delete_docs(id_keys) -> None:
    """Delete documents by the keys their _ids were derived from. Missing
    documents are ignored."""
    actions = [{"_op_type": "delete", "_index": SEARCH_INDEX, "_id": doc_id(k)} for k in id_keys]
    for i in range(0, len(actions), 500):
        helpers.bulk(client, actions[i:i + 500], raise_on_error=False, stats_only=True)
