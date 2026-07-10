#!/usr/bin/env bash
# Day 2 robustness smoke: malformed corpus + honest flatten error accounting.
set -euo pipefail

cd "$(dirname "$0")/.."
HARNESS_DIR="$(pwd)"
REPO_ROOT="$HARNESS_DIR/.."
RULE_DIR="$REPO_ROOT/corpus/sigmahq/rules/windows/process_creation"
FIXTURES="$REPO_ROOT/tests/fixtures/robustness"

cargo build --release --bin null_sigma_run >/dev/null
TARGET_DIR="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
RUNNER="$TARGET_DIR/release/null_sigma_run"

[ -d "$RULE_DIR" ] || { echo "SigmaHQ corpus missing at $RULE_DIR"; exit 1; }
[ -d "$FIXTURES" ] || { echo "fixtures missing at $FIXTURES"; exit 1; }

assert_contains() {
    local haystack="$1"
    local needle="$2"
    local label="$3"
    echo "$haystack" | rg -F "$needle" >/dev/null \
        || { echo "FAIL: $label — expected '$needle'"; echo "$haystack"; exit 1; }
}

run_continue() {
    local fixture="$1"
    "$RUNNER" --on-error continue "$RULE_DIR" "$fixture" 2>&1
}

echo ">> mixed_valid_invalid.jsonl"
OUT="$(run_continue "$FIXTURES/mixed_valid_invalid.jsonl")"
assert_contains "$OUT" "ingest_errors: io_read=0 line_too_large=0 json_parse=1 flatten_not_object=1 flatten_depth=0 flatten_fields=0 flatten_total=1 total=2" "mixed errors"
assert_contains "$OUT" "ingest_accounting: events_total=5 events_ok=3 events_failed=2 invariant_ok=true" "mixed accounting"

echo ">> deep_nested.jsonl"
OUT="$(run_continue "$FIXTURES/deep_nested.jsonl")"
assert_contains "$OUT" "flatten_depth=1 flatten_fields=0 flatten_total=1 total=1" "deep nested"
assert_contains "$OUT" "ingest_accounting: events_total=2 events_ok=1 events_failed=1 invariant_ok=true" "deep accounting"

echo ">> field_explosion.jsonl"
OUT="$(run_continue "$FIXTURES/field_explosion.jsonl")"
assert_contains "$OUT" "flatten_depth=0 flatten_fields=1 flatten_total=1 total=1" "field explosion"
assert_contains "$OUT" "ingest_accounting: events_total=2 events_ok=1 events_failed=1 invariant_ok=true" "field accounting"

echo ">> missing_fields_ok.jsonl"
OUT="$(run_continue "$FIXTURES/missing_fields_ok.jsonl")"
assert_contains "$OUT" "ingest_errors: io_read=0 line_too_large=0 json_parse=0 flatten_not_object=0 flatten_depth=0 flatten_fields=0 flatten_total=0 total=0" "missing fields errors"
assert_contains "$OUT" "ingest_accounting: events_total=3 events_ok=3 events_failed=0 invariant_ok=true" "missing fields accounting"

extract_ingest_errors() {
    "$RUNNER" "$@" 2>&1 | rg '^ingest_errors: ' | head -1
}

echo ">> thread parity on mixed fixture"
MIXED="$FIXTURES/mixed_valid_invalid.jsonl"
COUNT_1="$("$RUNNER" --threads 1 --on-error continue "$RULE_DIR" "$MIXED" 2>/dev/null)"
COUNT_0="$("$RUNNER" --threads 0 --on-error continue "$RULE_DIR" "$MIXED" 2>/dev/null)"
if [ "$COUNT_1" != "$COUNT_0" ]; then
    echo "FAIL: match count drift threads=1 ($COUNT_1) vs threads=0 ($COUNT_0)"
    exit 1
fi
ERR_1="$(extract_ingest_errors --threads 1 --on-error continue "$RULE_DIR" "$MIXED")"
ERR_0="$(extract_ingest_errors --threads 0 --on-error continue "$RULE_DIR" "$MIXED")"
if [ "$ERR_1" != "$ERR_0" ]; then
    echo "FAIL: ingest_errors drift threads=1 vs threads=0"
    echo "  threads=1: $ERR_1"
    echo "  threads=0: $ERR_0"
    exit 1
fi

echo ">> line_too_large guard"
BIG_LINE="$(mktemp)"
trap 'rm -f "$BIG_LINE"' EXIT
python3 - <<'PY' >"$BIG_LINE"
print('{"x":"' + ('a' * 2048) + '"}')
PY
set +e
LINE_OUT="$("$RUNNER" --max-line-bytes 1024 --on-error continue "$RULE_DIR" "$BIG_LINE" 2>&1)"
LINE_EXIT=$?
set -e
if [ "$LINE_EXIT" -ne 0 ]; then
    echo "FAIL: continue mode exited non-zero on oversize line ($LINE_EXIT)"
    exit 1
fi
assert_contains "$LINE_OUT" "line_too_large=1" "oversize line"
assert_contains "$LINE_OUT" "ingest_accounting: events_total=1 events_ok=0 events_failed=1 invariant_ok=true" "oversize accounting"

echo ">> fail-fast on mixed fixture"
set +e
FF_OUT="$("$RUNNER" --on-error fail-fast "$RULE_DIR" "$FIXTURES/mixed_valid_invalid.jsonl" 2>&1 >/dev/null)"
FF_EXIT=$?
set -e
if [ "$FF_EXIT" -eq 0 ]; then
    echo "FAIL: fail-fast exited zero on mixed fixture"
    exit 1
fi
echo "$FF_OUT" | rg "bad event JSON|flatten failed|read error|line exceeds" >/dev/null \
    || { echo "FAIL: fail-fast did not report event error"; echo "$FF_OUT"; exit 1; }

echo "PASS: robustness corpus checks succeeded."
