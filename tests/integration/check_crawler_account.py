"""
Runs inside a crawler container against the compose example's secured
OpenSearch, as the `pelican` account: does every OpenSearch operation a
crawl does, checks the results as stored, and checks that the account is
refused what it shouldn't be able to do. Exits non-zero on any failure.
"""

import sys
import time

from opensearchpy import exceptions

from pelican import index, roles, settings

failures = []


def check(label: str, ok: bool) -> None:
    print(f"{'ok  ' if ok else 'FAIL'} {label}")
    if not ok:
        failures.append(label)


def refused(label: str, call) -> None:
    try:
        call()
        check(f"refused: {label}", False)
    except exceptions.AuthorizationException:
        check(f"refused: {label}", True)


client = index.client
check(f"signed in as {settings.OS_USERNAME!r} over https", settings.OS_USERNAME == "pelican"
      and settings.OS_HOST.startswith("https://"))

index.ensure_index_exists()
check("index exists", client.indices.exists(index=settings.SEARCH_INDEX))

docs = [index.build_doc(f"smb://test/share/{name}", name, text, ["1alice"], len(text), {}, "share",
                        time.time(), settings.HOST_SMB)
        for name, text in (("keep.txt", "kept document"), ("gone.txt", "deleted document"))]
index.bulk_index(docs)
client.indices.refresh(index=settings.SEARCH_INDEX)

roles.apply_roles_to_indexed_docs(client, settings.SEARCH_INDEX, "share", settings.HOST_SMB, ["2staff"])
index.delete_docs(["smb://test/share/gone.txt"])
client.indices.refresh(index=settings.SEARCH_INDEX)

# delete_docs ignores errors, so check what's actually stored.
hits = client.search(index=settings.SEARCH_INDEX, body={"query": {"term": {"share": "share"}}})["hits"]["hits"]
stored = {h["_source"]["filename"]: h["_source"]["role"] for h in hits}
check("bulk delete removed gone.txt", "gone.txt" not in stored)
check("role update applied to keep.txt", stored.get("keep.txt") == ["2staff"])

refused("delete the index", lambda: client.indices.delete(index=settings.SEARCH_INDEX))
refused("create another index", lambda: client.indices.create(index="not-pelican"))
refused("write to another index", lambda: client.index(index="not-pelican", body={"x": 1}))
refused("read the security config",
        lambda: client.transport.perform_request("GET", "/_plugins/_security/api/internalusers"))
refused("take a snapshot", lambda: client.snapshot.create(repository="pelican-backups", snapshot="x"))

sys.exit(f"{len(failures)} check(s) failed" if failures else 0)
