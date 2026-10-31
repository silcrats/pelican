#!/usr/bin/env bash
# Integration test: runs the compose example (secured OpenSearch, status
# page, scheduler proxy) plus a test Samba server, crawls it, and checks
# the results and the access controls. Builds the images from this checkout.
#
#   tests/integration/run.sh            from the repo root
#   VECTOR=1 tests/integration/run.sh   the same with vector search on (the
#                                       CPU embeddings image; downloads the
#                                       model, ~450 MB, on each run)
#
# Needs Docker with Compose and python3. Uses its own project name and
# volumes and removes them afterwards; refuses to run if .env exists, since
# it writes one with test passwords.
set -uo pipefail

cd "$(dirname "$0")/../.."
if [ -e .env ]; then
  echo ".env exists; move it aside first (this test writes its own)" >&2
  exit 2
fi

PROJECT=pelican-itest
COMPOSE=(docker compose -p "$PROJECT" -f docker-compose.example.yml -f tests/integration/compose.test.yml)
ADMIN_PW='Itest-Owner-Pw-9!'
STATUS_PW='Itest-Status-Page-Pw-1'
failures=0
HITS=$(mktemp)

cat > .env <<EOF
OS_PASSWORD='Itest-Crawler-Pw-7!'
OS_STATUS_PASSWORD='Itest-Status-Pw-8!'
OS_ADMIN_PASSWORD='$ADMIN_PW'
STATUS_PASSWORD='$STATUS_PW'
SMB_USER=pelican-test
SMB_PASS=Smb-Test-Pw-1
SMB_DOMAIN=
EOF
SERVICES=(status samba samba-encrypted)
READER_PW='Itest-Reader-Pw-5!'
if [ "${VECTOR:-}" = 1 ]; then
  cat >> .env <<EOF
OS_READER_PASSWORD='$READER_PW'
VECTOR_ENABLED=true
COMPOSE_PROFILES=vector
EMBEDDINGS_API_KEY=Itest-Embeddings-Key-1
EOF
  SERVICES+=(embeddings)
fi

cleanup() {
  if [ "${KEEP:-}" != 1 ]; then
    "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1
  fi
  rm -f .env "$HITS"
}
trap cleanup EXIT

check() {  # check <label> <command...>
  local label=$1; shift
  if "$@"; then echo "ok   $label"; else echo "FAIL $label"; failures=$((failures + 1)); fi
}

# Admin request to OpenSearch, from inside its container (9200 isn't published).
os_admin() {
  "${COMPOSE[@]}" exec -T opensearch curl -sk -u "admin:$ADMIN_PW" -H 'Content-Type: application/json' "$@"
}

echo "== build"
"${COMPOSE[@]}" build opensearch-certs status || exit 1

echo "== start OpenSearch, accounts, status page, Samba"
"${COMPOSE[@]}" up -d --no-build "${SERVICES[@]}" || { "${COMPOSE[@]}" logs; exit 1; }
"${COMPOSE[@]}" logs opensearch-users | grep -E '\[(users|vector|snapshots)\]'

echo "== crawler account"
check "crawler account can do a crawl's operations, and no more" \
  "${COMPOSE[@]}" run --rm --no-deps -e PYTHONPATH=/app --entrypoint python crawl-smb \
  /tests/check_crawler_account.py

echo "== SMB crawl"
# Without vectors, start from an index as an older Pelican made it, so that this
# run covers upgrading one, with the crawler's own permissions. With vectors,
# the crawler creates the index itself.
if [ "${VECTOR:-}" != 1 ]; then
  python3 -c '
import json
m = json.load(open("search_index_mapping.json"))
for f in ("email_thread_id", "email_in_reply_to", "email_references", "email_thread_index"):
    del m["mappings"]["properties"][f]
print(json.dumps(m))' > "$HITS"
  # The account check above has already created the index.
  os_admin -XDELETE https://localhost:9200/documents >/dev/null
  created=$(os_admin -XPUT https://localhost:9200/documents -d @- < "$HITS")
  check "an index as an older Pelican made it, without thread fields, is in place" grep -q '"acknowledged":true' <<< "$created"
fi
crawl_out=$("${COMPOSE[@]}" run --rm --no-deps crawl-smb 2>&1); crawl_rc=$?
check "crawl_smb.py exits 0" test "$crawl_rc" = 0
os_admin -XPOST https://localhost:9200/documents/_refresh >/dev/null

thread_fields_mapped() {
  os_admin https://localhost:9200/documents/_mapping > "$HITS"
  python3 - "$HITS" <<'EOF'
import json, sys
props = json.load(open(sys.argv[1]))["documents"]["mappings"]["properties"]
fields = ("email_thread_id", "email_in_reply_to", "email_references", "email_thread_index")
types = {f: props.get(f, {}).get("type") for f in fields}
print(f"     {types}")
sys.exit(0 if all(t == "keyword" for t in types.values()) else 1)
EOF
}
check "thread fields are keywords, whether the index was new or upgraded" thread_fields_mapped
if [ "${VECTOR:-}" != 1 ]; then
  check "the crawler account added them to an older index" grep -q "added to 'documents': email_in_reply_to" <<< "$crawl_out"
fi

thread_fields_indexed() {
  os_admin "https://localhost:9200/documents/_search?size=20" \
    -d '{"query": {"bool": {"filter": [{"term": {"share": "test-finance"}}, {"term": {"filetype": "eml"}}]}}}' > "$HITS"
  python3 - "$HITS" <<'EOF'
import json, sys
docs = {h["_source"]["filename"]: h["_source"] for h in json.load(open(sys.argv[1]))["hits"]["hits"]}
index_root = "Ac8AAAECAwQFBgcICQoLDA0ODxAREg=="
expected = {
    "thread-start.eml": {"email_thread_id": "<root@test>"},
    "thread-reply.eml": {"email_thread_id": "<root@test>", "email_in_reply_to": "<root@test>", "email_references": ["<root@test>"]},
    "thread-reply-2.eml": {"email_thread_id": "<root@test>", "email_in_reply_to": "<reply@test>", "email_references": ["<root@test>", "<reply@test>"]},
    "thread-parent-only.eml": {"email_thread_id": "<parent@test>", "email_in_reply_to": "<parent@test>"},
    "thread-outlook.eml": {"email_thread_id": "<outlook@test>", "email_thread_index": index_root},
    "thread-bad-headers.eml": {"email_thread_id": "<bad@test>"},
}
fields = ("email_thread_id", "email_in_reply_to", "email_references", "email_thread_index")
ok = True
for name, want in expected.items():
    doc = docs.get(name, {})
    got = {f: doc[f] for f in fields if f in doc}
    good = got == want and f"Pelican email fixture {name}" in doc.get("content", "")
    print(f"     {name}: {'ok' if good else f'MISMATCH {got}'}")
    ok &= good
sys.exit(0 if ok else 1)
EOF
}
check "each email's thread fields are indexed, and bad headers cost only those fields" thread_fields_indexed

fixtures_indexed() {  # fixtures_indexed <share name>
  os_admin "https://localhost:9200/documents/_search?size=20" \
    -d "{\"query\": {\"term\": {\"share\": \"$1\"}}}" > "$HITS"
  python3 - "$HITS" <<'EOF'
import json, sys
hits = {h["_source"]["filename"]: h["_source"] for h in json.load(open(sys.argv[1]))["hits"]["hits"]}
expected = {"notes.txt": "Pelican plain text fixture", "report.docx": "Pelican Word fixture",
            "scan.pdf": "Pelican PDF fixture", "legacy-word.doc": "Ελληνικά 中文",
            "legacy-powerpoint.ppt": "secret word walrus", "slides.pptx": "secret word walrus",
            "slides.odp": "secret word walrus", "report.odt": "Ελληνικά 中文", "report.rtf": "Ελληνικά 中文"}
ok = True
for name, phrase in expected.items():
    doc = hits.get(name)
    # Roles from a real ACL read, not the fail-closed fallback (Radmin).
    good = bool(doc) and phrase in doc.get("content", "") and doc.get("role") not in (None, [], ["Radmin"])
    print(f"     {name}: {'indexed' if doc else 'MISSING'}"
          + (f", roles {doc['role']}, text {'found' if phrase in doc.get('content', '') else 'MISSING'}" if doc else ""))
    ok &= good
if "skip.zip" in hits:
    print("     skip.zip: indexed although excluded"); ok = False
sys.exit(0 if ok else 1)
EOF
}
check "Samba on default settings: each fixture indexed with its text and ACL roles" fixtures_indexed test-finance
check "Samba requiring encryption, share with encrypt: true: each fixture indexed" fixtures_indexed test-encrypted

# The photo's EXIF, read with Pillow: camera, date taken converted to UTC
# from its offset (it becomes the document's timestamp), GPS and the place
# name reverse-geocoded from it.
photo_metadata_indexed() {
  os_admin "https://localhost:9200/documents/_search?size=1" \
    -d '{"query": {"bool": {"filter": [{"term": {"share": "test-finance"}}, {"term": {"filename.keyword": "photo.jpg"}}]}}}' > "$HITS"
  python3 - "$HITS" <<'EOF'
import json, sys
hits = json.load(open(sys.argv[1]))["hits"]["hits"]
doc = hits[0]["_source"] if hits else {}
checks = {
    "camera": (doc.get("image_camera_make"), doc.get("image_camera_model")) == ("Canon", "EOS 5D"),
    "date taken": doc.get("timestamp") == "2007-06-15T04:30:00.000Z",
    "GPS": abs((doc.get("image_gps_lat") or 0) + 33.8651) < 0.001 and abs((doc.get("image_gps_lon") or 0) - 151.2099) < 0.001,
    "place": "Sydney" in (doc.get("image_location") or ""),
}
print("     photo.jpg:", ", ".join(f"{k} {'ok' if v else 'WRONG'}" for k, v in checks.items()) if doc else "MISSING")
print("      ", {k: doc.get(k) for k in ("image_camera_make", "image_camera_model", "timestamp", "image_gps_lat", "image_gps_lon", "image_location")})
sys.exit(0 if doc and all(checks.values()) else 1)
EOF
}
check "photo indexed with its EXIF camera, date taken, GPS and place" photo_metadata_indexed
# Otherwise the check above proves nothing: a client that can't encrypt
# (SMB 2.1) must be refused by samba-encrypted.
encryption_enforced() {
  local out   # captured first: smbclient exits non-zero when refused, which pipefail would count
  out=$("${COMPOSE[@]}" run --rm --no-deps --entrypoint smbclient crawl-smb //samba-encrypted/Shared \
    -U 'pelican-test%Smb-Test-Pw-1' -m SMB2_10 -c ls 2>&1)
  grep -q NT_STATUS_ACCESS_DENIED <<< "$out"
}
check "test server refuses unencrypted (SMB 2.1) clients" encryption_enforced
check "sync_smb_acl.py exits 0" "${COMPOSE[@]}" run --rm --no-deps sync-smb-acl

if [ "${VECTOR:-}" = 1 ]; then
  echo "== vector search"
  # Vectors come back from _source only when it isn't narrowed to them (an
  # include list returns each knn as a number), so exclude content instead.
  fixtures_embedded() {
    os_admin "https://localhost:9200/documents/_search?size=20" \
      -d '{"query": {"term": {"share": "test-finance"}}, "_source": {"excludes": ["content"]}}' > "$HITS"
    python3 - "$HITS" <<'EOF'
import json, sys
hits = json.load(open(sys.argv[1]))["hits"]["hits"]
ok = len(hits) >= 9
for h in hits:
    vectors = h["_source"].get("content_embedding") or []
    print(f"     {h['_source']['filename']}: {len(vectors)} passage vector(s)")
    ok &= bool(vectors) and all(len(v["knn"]) == 768 for v in vectors)
sys.exit(0 if ok else 1)
EOF
  }
  # Hits for a neural query as pelican-reader (the search UI's account),
  # filtered to the given roles the way Frogmouth filters to a user's.
  reader_hits() {  # reader_hits <roles JSON array>
    "${COMPOSE[@]}" exec -T opensearch curl -sk -u "pelican-reader:$READER_PW" -H 'Content-Type: application/json' \
      https://localhost:9200/documents/_search -d '{"size": 50, "query": {"nested": {"path": "content_embedding",
        "query": {"neural": {"content_embedding.knn": {"query_text": "a walrus in the presentation notes", "k": 50,
          "filter": {"terms": {"role": '"$1"'}}}}}}}}' \
      | python3 -c 'import json, sys; d = json.load(sys.stdin); print(len(d["hits"]["hits"]) if "hits" in d else "error: " + str(d)[:200])'
  }
  fixture_roles=$(os_admin "https://localhost:9200/documents/_search?size=1" \
    -d '{"query": {"term": {"filename.keyword": "slides.pptx"}}}' \
    | python3 -c 'import json, sys; print(json.dumps(json.load(sys.stdin)["hits"]["hits"][0]["_source"]["role"]))')
  embed_count() { "${COMPOSE[@]}" exec -T embeddings curl -s localhost/metrics | awk '/^te_embed_count/ {print $2}'; }
  role_change_not_reembedded() {
    local before after
    before=$(embed_count)
    os_admin -XPOST "https://localhost:9200/documents/_update_by_query?refresh=true" \
      -d '{"query": {"term": {"share": "test-finance"}}, "script": {"source": "ctx._source.role.add('2itest')"}}' >/dev/null
    after=$(embed_count)
    echo "     embeddings computed: $before before, $after after"
    [ -n "$before" ] && [ "$before" = "$after" ]
  }
  check "every fixture has passage vectors" fixtures_embedded
  check "neural query as pelican-reader finds the fixtures for their roles ($fixture_roles)" \
    test "$(reader_hits "$fixture_roles")" -gt 0
  check "neural query as pelican-reader finds nothing for other roles" test "$(reader_hits '["Rnobody"]')" = 0
  check "a role change (as the ACL sync makes) doesn't re-embed" role_change_not_reembedded
fi

# Files indexed before an extractor was added are extracted again once:
# make the Office files look indexed by an older Pelican (backdated in the
# state DB, no text in the index), crawl, and expect only those re-fetched.
office_files_reextracted() {
  local rewound out
  rewound=$("${COMPOSE[@]}" run --rm --no-deps -e PYTHONPATH=/app --entrypoint python crawl-smb \
    /tests/rewind_office_files.py 2>/dev/null | tail -1)
  [ "$rewound" = 12 ] || { echo "     expected 12 state rows rewound, got '$rewound'"; return 1; }
  os_admin -XPOST "https://localhost:9200/documents/_update_by_query?refresh=true" -d '{
    "query": {"terms": {"filename.keyword": ["legacy-word.doc", "legacy-powerpoint.ppt", "slides.pptx",
                                             "slides.odp", "report.odt", "report.rtf"]}},
    "script": {"source": "ctx._source.content = \u0027\u0027"}}' >/dev/null
  out=$("${COMPOSE[@]}" run --rm --no-deps crawl-smb 2>&1)
  grep -E "finished|skipped [0-9]+ unchanged" <<< "$out" | sed 's/^/     /'
  [ "$(grep -c "finished 'test-[a-z]*': 6 documents indexed" <<< "$out")" = 2 ] \
    && os_admin -XPOST https://localhost:9200/documents/_refresh >/dev/null \
    && fixtures_indexed test-finance >/dev/null && fixtures_indexed test-encrypted >/dev/null
}
check "files indexed before Office extraction existed are extracted once, nothing else re-fetched" \
  office_files_reextracted

# Likewise emails indexed before thread fields existed.
emails_reextracted() {
  local rewound out
  rewound=$("${COMPOSE[@]}" run --rm --no-deps -e PYTHONPATH=/app --entrypoint python crawl-smb \
    /tests/rewind_email_files.py 2>/dev/null | tail -1)
  [ "$rewound" = 12 ] || { echo "     expected 12 state rows rewound, got '$rewound'"; return 1; }
  os_admin -XPOST "https://localhost:9200/documents/_update_by_query?refresh=true" -d '{
    "query": {"term": {"filetype": "eml"}},
    "script": {"source": "for (f in [\u0027email_thread_id\u0027, \u0027email_in_reply_to\u0027, \u0027email_references\u0027, \u0027email_thread_index\u0027]) { ctx._source.remove(f) }"}}' >/dev/null
  out=$("${COMPOSE[@]}" run --rm --no-deps crawl-smb 2>&1)
  grep -E "finished|skipped [0-9]+ unchanged" <<< "$out" | sed 's/^/     /'
  [ "$(grep -c "finished 'test-[a-z]*': 6 documents indexed" <<< "$out")" = 2 ] \
    && os_admin -XPOST https://localhost:9200/documents/_refresh >/dev/null \
    && thread_fields_indexed >/dev/null
}
check "emails indexed before thread fields existed are extracted once, and get them" emails_reextracted

crawl_with_failing_share() {
  local out rc
  out=$("${COMPOSE[@]}" run --rm --no-deps -e SHARES_CONFIG=/tests/shares-with-failure.yaml crawl-smb 2>&1)
  rc=$?
  echo "$out" | grep -E "^(finished|  finished|  failed|[0-9]+ share)" | sed 's/^/     /'
  [ "$rc" -ne 0 ] && grep -q "1 share(s) failed: test-missing" <<< "$out" \
    && grep -q "finished 'test-finance'" <<< "$out"
}
check "a failed share makes the crawl exit non-zero, other shares still crawled" crawl_with_failing_share

echo "== status page"
STATUS=http://localhost:18090
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
status_lists_job() { grep -q test-finance <<< "$(curl -s -u "pelican:$STATUS_PW" "$STATUS/status.json")"; }
status_reads_index() {
  curl -s -u "pelican:$STATUS_PW" "$STATUS/storage.json" | python3 -c '
import json, sys
s = json.load(sys.stdin)
sys.exit(0 if not s.get("error") and (s.get("data") or {}).get("docs", 0) >= 3 else 1)'
}
# Browser flow: sign-in page and session cookie, never the browser's popup.
COOKIES=$(mktemp)
page_redirects_to_login() {
  local headers
  headers=$(curl -s -o /dev/null -D - "$STATUS/" | tr -d '\r')
  grep -q "^HTTP/[0-9.]* 303" <<< "$headers" && grep -qi "^location: /login" <<< "$headers" \
    && ! grep -qi "^www-authenticate" <<< "$headers"
}
wrong_password_refused() {
  test "$(curl -s -o /dev/null -w '%{redirect_url}' -d 'username=pelican&password=wrong' "$STATUS/login")" \
    = "$STATUS/login?failed=1"
}
sign_in_gives_session() {
  curl -s -o /dev/null -c "$COOKIES" --data-urlencode username=pelican --data-urlencode "password=$STATUS_PW" \
    "$STATUS/login"
  grep -q test-finance <<< "$(curl -s -b "$COOKIES" "$STATUS/status.json")"
}
sign_out_ends_session() {
  local token
  token=$(awk '/pelican_status_session/ {print $7}' "$COOKIES")
  curl -s -o /dev/null -b "$COOKIES" -X POST "$STATUS/logout"
  test "$(code -b "pelican_status_session=$token" "$STATUS/status.json")" = 401
}
check "status page sends browsers to its sign-in page (no popup)" page_redirects_to_login
check "status page data refuses requests without sign-in" test "$(code "$STATUS/status.json")" = 401
check "status page sign-in refuses a wrong password" wrong_password_refused
check "status page sign-in gives a session that reads the job list" sign_in_gives_session
check "status page shows its version once signed in" \
  grep -q 'class="version">dev<' <<< "$(curl -s -u "pelican:$STATUS_PW" "$STATUS/")"
check "status page sign-out ends the session" sign_out_ends_session
rm -f "$COOKIES"
# Scripts: the same credentials as HTTP Basic.
check "status page refuses a wrong password (Basic)" test "$(code -u pelican:wrong "$STATUS/status.json")" = 401
check "status page lists the SMB job (Basic)" status_lists_job
"${COMPOSE[@]}" restart status >/dev/null 2>&1; sleep 5   # storage view refreshes at start
check "status page reads index stats with its account" status_reads_index

echo "== OpenSearch access"
anonymous_refused() {
  test "$("${COMPOSE[@]}" exec -T opensearch curl -sk -o /dev/null -w '%{http_code}' \
    https://localhost:9200/documents/_search)" = 401
}
policy_registered() { grep -q pelican-backups <<< "$(os_admin https://localhost:9200/_plugins/_sm/policies/pelican-daily)"; }
snapshot_works() {
  local out
  out=$(os_admin -XPUT 'https://localhost:9200/_snapshot/pelican-backups/itest?wait_for_completion=true' \
    -d '{"indices": "documents"}')
  grep -q '"state":"SUCCESS"' <<< "$out" || { echo "     $out" | cut -c1-300; return 1; }
}
check "anonymous requests refused" anonymous_refused
check "snapshot policy registered" policy_registered
check "snapshot of the index succeeds" snapshot_works

echo "== scheduler proxy"
"${COMPOSE[@]}" up -d --no-deps docker-api-proxy >/dev/null 2>&1
proxy() {  # proxy <method> <path> -> HTTP status, from a container on the proxy's network
  docker run --rm --network "${PROJECT}_docker-api" curlimages/curl:8.17.0 \
    -s -o /dev/null -w '%{http_code}' -X "$1" "http://docker-api-proxy:2375$2"
}
check "proxy allows reading container details" test "$(proxy GET /containers/json)" = 200
check "proxy refuses creating containers" test "$(proxy POST /containers/create)" = 403
check "proxy refuses exec" test "$(proxy POST /containers/pelican-crawl-smb/exec)" = 403
check "proxy refuses image calls" test "$(proxy GET /images/json)" = 403

echo
if [ "$failures" -gt 0 ]; then
  echo "$failures check(s) failed"
  "${COMPOSE[@]}" logs --tail 40 opensearch-users crawl-smb status samba 2>/dev/null
  exit 1
fi
echo "all checks passed"
