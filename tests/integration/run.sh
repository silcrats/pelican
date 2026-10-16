#!/usr/bin/env bash
# Integration test: runs the compose example (secured OpenSearch, status
# page, scheduler proxy) plus a test Samba server, crawls it, and checks
# the results and the access controls. Builds the images from this checkout.
#
#   tests/integration/run.sh            from the repo root
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
"${COMPOSE[@]}" up -d --no-build status samba samba-encrypted || { "${COMPOSE[@]}" logs; exit 1; }
"${COMPOSE[@]}" logs opensearch-users | grep -E '\[(users|snapshots)\]'

echo "== crawler account"
check "crawler account can do a crawl's operations, and no more" \
  "${COMPOSE[@]}" run --rm --no-deps -e PYTHONPATH=/app --entrypoint python crawl-smb \
  /tests/check_crawler_account.py

echo "== SMB crawl"
check "crawl_smb.py exits 0" "${COMPOSE[@]}" run --rm --no-deps crawl-smb
os_admin -XPOST https://localhost:9200/documents/_refresh >/dev/null

fixtures_indexed() {  # fixtures_indexed <share name>
  os_admin "https://localhost:9200/documents/_search?size=20" \
    -d "{\"query\": {\"term\": {\"share\": \"$1\"}}}" > "$HITS"
  python3 - "$HITS" <<'EOF'
import json, sys
hits = {h["_source"]["filename"]: h["_source"] for h in json.load(open(sys.argv[1]))["hits"]["hits"]}
expected = {"notes.txt": "Pelican plain text fixture", "report.docx": "Pelican Word fixture",
            "scan.pdf": "Pelican PDF fixture", "legacy-word.doc": "Ελληνικά 中文",
            "legacy-powerpoint.ppt": "secret word walrus"}
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

# Files indexed before an extractor was added are extracted again once:
# make the .doc/.ppt look indexed by an older Pelican (backdated in the
# state DB, no text in the index), crawl, and expect only those re-fetched.
legacy_office_reextracted() {
  local rewound out
  rewound=$("${COMPOSE[@]}" run --rm --no-deps -e PYTHONPATH=/app --entrypoint python crawl-smb \
    /tests/rewind_legacy_office.py 2>/dev/null | tail -1)
  [ "$rewound" = 4 ] || { echo "     expected 4 state rows rewound, got '$rewound'"; return 1; }
  os_admin -XPOST "https://localhost:9200/documents/_update_by_query?refresh=true" -d '{
    "query": {"terms": {"filename.keyword": ["legacy-word.doc", "legacy-powerpoint.ppt"]}},
    "script": {"source": "ctx._source.content = \u0027\u0027"}}' >/dev/null
  out=$("${COMPOSE[@]}" run --rm --no-deps crawl-smb 2>&1)
  grep -E "finished|skipped [0-9]+ unchanged" <<< "$out" | sed 's/^/     /'
  [ "$(grep -c "finished 'test-[a-z]*': 2 documents indexed" <<< "$out")" = 2 ] \
    && os_admin -XPOST https://localhost:9200/documents/_refresh >/dev/null \
    && fixtures_indexed test-finance >/dev/null && fixtures_indexed test-encrypted >/dev/null
}
check "files indexed before .doc/.ppt extraction existed are extracted once, nothing else re-fetched" \
  legacy_office_reextracted

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
