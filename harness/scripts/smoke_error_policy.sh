#!/usr/bin/env bash
# Verify trust-first error policy behavior for null_sigma_run.
set -euo pipefail

cd "$(dirname "$0")/.."
HARNESS_DIR="$(pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HARNESS_DIR/.." && pwd)"
# shellcheck source=lib/rule_dir.sh
source "$SCRIPT_DIR/lib/rule_dir.sh"
RULE_DIR="$(require_rule_dir "$REPO_ROOT")"
MIXED_FILE="$REPO_ROOT/tests/fixtures/robustness/mixed_valid_invalid.jsonl"

cargo build --release --bin null_sigma_run >/dev/null
TARGET_DIR="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
RUNNER="$TARGET_DIR/release/null_sigma_run"

[ -f "$MIXED_FILE" ] || { echo "fixture missing at $MIXED_FILE"; exit 1; }

echo ">> continue mode should complete with non-zero error counters"
CONT_OUT="$("$RUNNER" --on-error continue "$RULE_DIR" "$MIXED_FILE" 2>&1 >/tmp/null_sigma_count_continue.txt)"
CONT_EXIT=$?
if [ "$CONT_EXIT" -ne 0 ]; then
    echo "FAIL: continue mode exited non-zero ($CONT_EXIT)"
    exit 1
fi
echo "$CONT_OUT" | rg "ingest_errors: io_read=0 line_too_large=0 json_parse=1 flatten_not_object=1 flatten_depth=0 flatten_fields=0 flatten_total=1 total=2" >/dev/null \
    || { echo "FAIL: continue mode error counters unexpected"; echo "$CONT_OUT"; exit 1; }
echo "$CONT_OUT" | rg "ingest_accounting: events_total=5 events_ok=3 events_failed=2 invariant_ok=true" >/dev/null \
    || { echo "FAIL: continue mode accounting mismatch"; echo "$CONT_OUT"; exit 1; }
CONT_COUNT_1="$(cat /tmp/null_sigma_count_continue.txt)"
CONT_OUT_0="$("$RUNNER" --threads 0 --on-error continue "$RULE_DIR" "$MIXED_FILE" 2>&1 >/tmp/null_sigma_count_continue_t0.txt)"
CONT_COUNT_0="$(cat /tmp/null_sigma_count_continue_t0.txt)"
if [ "$CONT_COUNT_1" != "$CONT_COUNT_0" ]; then
    echo "FAIL: continue mode count drift across thread settings ($CONT_COUNT_1 vs $CONT_COUNT_0)"
    exit 1
fi
echo "$CONT_OUT_0" | rg "ingest_accounting: events_total=5 events_ok=3 events_failed=2 invariant_ok=true" >/dev/null \
    || { echo "FAIL: continue mode accounting mismatch on threads=0"; echo "$CONT_OUT_0"; exit 1; }

echo ">> fail-fast mode should exit non-zero on first bad event"
set +e
FAIL_OUT="$("$RUNNER" --on-error fail-fast "$RULE_DIR" "$MIXED_FILE" 2>&1 >/tmp/null_sigma_count_failfast.txt)"
FAIL_EXIT=$?
set -e
if [ "$FAIL_EXIT" -eq 0 ]; then
    echo "FAIL: fail-fast mode exited zero"
    exit 1
fi
echo "$FAIL_OUT" | rg "bad event JSON|flatten failed|read error|line exceeds" >/dev/null \
    || { echo "FAIL: fail-fast mode did not report first event error"; echo "$FAIL_OUT"; exit 1; }

echo "PASS: error policy checks succeeded (continue + fail-fast)."
