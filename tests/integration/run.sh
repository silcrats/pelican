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
"${COMPOSE[@]}" up -d --no-build status samba || { "${COMPOSE[@]}" logs; exit 1; }
"${COMPOSE[@]}" logs opensearch-users | grep -E '\[(users|snapshots)\]'

echo "== crawler account"
check "crawler account can do a crawl's operations, and no more" \
  "${COMPOSE[@]}" run --rm --no-deps -e PYTHONPATH=/app --entrypoint python crawl-smb \
  /tests/check_crawler_account.py

echo "== SMB crawl"
check "crawl_smb.py exits 0" "${COMPOSE[@]}" run --rm --no-deps crawl-smb
os_admin -XPOST https://localhost:9200/documents/_refresh >/dev/null
os_admin "https://localhost:9200/documents/_search?size=20" \
  -d '{"query": {"term": {"share": "test-finance"}}}' > "$HITS"
check "each fixture indexed with its text and access roles" python3 - "$HITS" <<'EOF'
import json, sys
hits = {h["_source"]["filename"]: h["_source"] for h in json.load(open(sys.argv[1]))["hits"]["hits"]}
expected = {"notes.txt": "Pelican plain text fixture", "report.docx": "Pelican Word fixture",
            "scan.pdf": "Pelican PDF fixture"}
ok = True
for name, phrase in expected.items():
    doc = hits.get(name)
    good = bool(doc) and phrase in doc.get("content", "") and bool(doc.get("role"))
    print(f"     {name}: {'indexed' if doc else 'MISSING'}"
          + (f", roles {doc['role']}, text {'found' if phrase in doc.get('content', '') else 'MISSING'}" if doc else ""))
    ok &= good
if "skip.zip" in hits:
    print("     skip.zip: indexed although excluded"); ok = False
sys.exit(0 if ok else 1)
EOF
check "sync_smb_acl.py exits 0" "${COMPOSE[@]}" run --rm --no-deps sync-smb-acl

echo "== status page"
STATUS=http://localhost:18090
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
status_lists_job() { curl -s -u "pelican:$STATUS_PW" "$STATUS/status.json" | grep -q test-finance; }
status_reads_index() {
  curl -s -u "pelican:$STATUS_PW" "$STATUS/storage.json" | python3 -c '
import json, sys
s = json.load(sys.stdin)
sys.exit(0 if not s.get("error") and (s.get("data") or {}).get("docs", 0) >= 3 else 1)'
}
check "status page refuses requests without sign-in" test "$(code "$STATUS/status.json")" = 401
check "status page refuses a wrong password" test "$(code -u pelican:wrong "$STATUS/status.json")" = 401
check "status page lists the SMB job when signed in" status_lists_job
"${COMPOSE[@]}" restart status >/dev/null 2>&1; sleep 5   # storage view refreshes at start
check "status page reads index stats with its account" status_reads_index

echo "== OpenSearch access"
anonymous_refused() {
  test "$("${COMPOSE[@]}" exec -T opensearch curl -sk -o /dev/null -w '%{http_code}' \
    https://localhost:9200/documents/_search)" = 401
}
policy_registered() { os_admin https://localhost:9200/_plugins/_sm/policies/pelican-daily | grep -q pelican-backups; }
snapshot_works() {
  os_admin -XPUT 'https://localhost:9200/_snapshot/pelican-backups/itest?wait_for_completion=true' \
    -d '{"indices": "documents"}' | grep -q '"state":"SUCCESS"'
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
