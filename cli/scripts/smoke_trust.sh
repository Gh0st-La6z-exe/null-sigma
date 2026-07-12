#!/usr/bin/env bash
# Day 1 CLI trust smoke: Week 1 stderr/exit parity on committed fixtures.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$CLI_DIR/.." && pwd)"
RULE_DIR="$REPO_ROOT/tests/fixtures/rules/minimal"
MIXED="$REPO_ROOT/tests/fixtures/robustness/mixed_valid_invalid.jsonl"

cd "$CLI_DIR"
cargo build --release --bin null-sigma-cli >/dev/null
TARGET_DIR="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
RUNNER="$TARGET_DIR/release/null-sigma-cli"

[ -d "$RULE_DIR" ] || { echo "rule dir missing at $RULE_DIR"; exit 1; }
[ -f "$MIXED" ] || { echo "fixture missing at $MIXED"; exit 1; }

assert_contains() {
    local haystack="$1"
    local needle="$2"
    local label="$3"
    echo "$haystack" | rg -F "$needle" >/dev/null \
        || { echo "FAIL: $label — expected '$needle'"; echo "$haystack"; exit 1; }
}

echo ">> continue mode (file)"
CONT_OUT="$("$RUNNER" --rules "$RULE_DIR" --on-error continue "$MIXED" 2>&1 >/tmp/null_sigma_cli_count.txt)"
CONT_EXIT=$?
if [ "$CONT_EXIT" -ne 0 ]; then
    echo "FAIL: continue mode exited non-zero ($CONT_EXIT)"
    echo "$CONT_OUT"
    exit 1
fi
assert_contains "$CONT_OUT" \
    "ingest_errors: io_read=0 line_too_large=0 json_parse=1 flatten_not_object=1 flatten_depth=0 flatten_fields=0 flatten_total=1 total=2" \
    "continue errors"
assert_contains "$CONT_OUT" \
    "ingest_accounting: events_total=5 events_ok=3 events_failed=2 invariant_ok=true" \
    "continue accounting"

echo ">> continue mode (stdin)"
STDIN_OUT="$("$RUNNER" --rules "$RULE_DIR" --on-error continue - <"$MIXED" 2>&1 >/tmp/null_sigma_cli_stdin.txt)"
STDIN_EXIT=$?
if [ "$STDIN_EXIT" -ne 0 ]; then
    echo "FAIL: stdin continue exited non-zero ($STDIN_EXIT)"
    echo "$STDIN_OUT"
    exit 1
fi
assert_contains "$STDIN_OUT" \
    "ingest_accounting: events_total=5 events_ok=3 events_failed=2 invariant_ok=true" \
    "stdin accounting"
FILE_COUNT="$(cat /tmp/null_sigma_cli_count.txt)"
STDIN_COUNT="$(cat /tmp/null_sigma_cli_stdin.txt)"
if [ "$FILE_COUNT" != "$STDIN_COUNT" ]; then
    echo "FAIL: file vs stdin match-count drift ($FILE_COUNT vs $STDIN_COUNT)"
    exit 1
fi

echo ">> fail-fast mode"
set +e
FF_OUT="$("$RUNNER" --rules "$RULE_DIR" --on-error fail-fast "$MIXED" 2>&1 >/tmp/null_sigma_cli_ff.txt)"
FF_EXIT=$?
set -e
if [ "$FF_EXIT" -eq 0 ]; then
    echo "FAIL: fail-fast exited zero"
    echo "$FF_OUT"
    exit 1
fi
echo "$FF_OUT" | rg "bad event JSON|flatten failed|read error|line exceeds" >/dev/null \
    || { echo "FAIL: fail-fast did not report event error"; echo "$FF_OUT"; exit 1; }

echo ">> missing --rules exits 2"
set +e
"$RUNNER" --on-error continue "$MIXED" >/dev/null 2>/tmp/null_sigma_cli_usage.txt
USAGE_EXIT=$?
set -e
if [ "$USAGE_EXIT" -ne 2 ]; then
    echo "FAIL: expected exit 2 for missing --rules, got $USAGE_EXIT"
    cat /tmp/null_sigma_cli_usage.txt
    exit 1
fi

echo "PASS: null-sigma-cli Day 1 trust checks succeeded."
