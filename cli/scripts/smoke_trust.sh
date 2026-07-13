#!/usr/bin/env bash
# Day 2 CLI trust + alert smoke: Week 1 stderr/exit parity + NDJSON/text stdout.
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

echo ">> continue mode (file) — stderr trust"
set +e
"$RUNNER" --rules "$RULE_DIR" --on-error continue "$MIXED" \
    2>/tmp/null_sigma_cli_err.txt >/tmp/null_sigma_cli_out.txt
CONT_EXIT=$?
set -e
CONT_ERR="$(cat /tmp/null_sigma_cli_err.txt)"
if [ "$CONT_EXIT" -ne 0 ]; then
    echo "FAIL: continue mode exited non-zero ($CONT_EXIT)"
    echo "$CONT_ERR"
    exit 1
fi
assert_contains "$CONT_ERR" \
    "ingest_errors: io_read=0 line_too_large=0 json_parse=1 flatten_not_object=1 flatten_depth=0 flatten_fields=0 flatten_total=1 total=2" \
    "continue errors"
assert_contains "$CONT_ERR" \
    "ingest_accounting: events_total=5 events_ok=3 events_failed=2 invariant_ok=true" \
    "continue accounting"
assert_contains "$CONT_ERR" "emit=" "emit tax bucket"

echo ">> NDJSON alerts on stdout"
ALERTS="$(cat /tmp/null_sigma_cli_out.txt)"
ALERT_LINES="$(echo "$ALERTS" | rg -c '^\{' || true)"
if [ "${ALERT_LINES:-0}" -lt 1 ]; then
    echo "FAIL: expected ≥1 NDJSON alert lines"
    echo "$ALERTS"
    exit 1
fi
assert_contains "$ALERTS" "00000000-0000-0000-0000-000000000001" "whoami rule_id"
assert_contains "$ALERTS" '"rule_title"' "lean schema rule_title"
if echo "$ALERTS" | rg -F '"event":' >/dev/null; then
    echo "FAIL: default NDJSON should be lean (no event object)"
    echo "$ALERTS"
    exit 1
fi

echo ">> continue mode (stdin) — alert parity"
"$RUNNER" --rules "$RULE_DIR" --on-error continue - <"$MIXED" \
    2>/tmp/null_sigma_cli_stdin_err.txt >/tmp/null_sigma_cli_stdin_out.txt
STDIN_EXIT=$?
if [ "$STDIN_EXIT" -ne 0 ]; then
    echo "FAIL: stdin continue exited non-zero ($STDIN_EXIT)"
    cat /tmp/null_sigma_cli_stdin_err.txt
    exit 1
fi
assert_contains "$(cat /tmp/null_sigma_cli_stdin_err.txt)" \
    "ingest_accounting: events_total=5 events_ok=3 events_failed=2 invariant_ok=true" \
    "stdin accounting"
FILE_ALERTS="$(rg -c '^\{' /tmp/null_sigma_cli_out.txt || true)"
STDIN_ALERTS="$(rg -c '^\{' /tmp/null_sigma_cli_stdin_out.txt || true)"
if [ "$FILE_ALERTS" != "$STDIN_ALERTS" ]; then
    echo "FAIL: file vs stdin alert-count drift ($FILE_ALERTS vs $STDIN_ALERTS)"
    exit 1
fi

echo ">> --format text"
TEXT_OUT="$("$RUNNER" --rules "$RULE_DIR" --format text --on-error continue "$MIXED" 2>/dev/null)"
echo "$TEXT_OUT" | rg '^[a-z]+ ' >/dev/null \
    || { echo "FAIL: expected text alert with level prefix"; echo "$TEXT_OUT"; exit 1; }
assert_contains "$TEXT_OUT" "00000000-0000-0000-0000-000000000001" "text whoami id"

echo ">> --include-event"
INC_OUT="$("$RUNNER" --rules "$RULE_DIR" --include-event --on-error continue "$MIXED" 2>/dev/null)"
assert_contains "$INC_OUT" '"event":' "include-event payload"

echo ">> --flush-alerts still emits"
FLUSH_OUT="$("$RUNNER" --rules "$RULE_DIR" --flush-alerts --on-error continue "$MIXED" 2>/dev/null)"
FLUSH_N="$(echo "$FLUSH_OUT" | rg -c '^\{' || true)"
if [ "${FLUSH_N:-0}" -lt 1 ]; then
    echo "FAIL: --flush-alerts produced no alerts"
    exit 1
fi

echo ">> bad --format exits 2"
set +e
"$RUNNER" --rules "$RULE_DIR" --format nope "$MIXED" >/dev/null 2>/tmp/null_sigma_cli_fmt.txt
FMT_EXIT=$?
set -e
if [ "$FMT_EXIT" -ne 2 ]; then
    echo "FAIL: expected exit 2 for bad --format, got $FMT_EXIT"
    cat /tmp/null_sigma_cli_fmt.txt
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

echo "PASS: null-sigma-cli Day 2 trust + alert checks succeeded."
