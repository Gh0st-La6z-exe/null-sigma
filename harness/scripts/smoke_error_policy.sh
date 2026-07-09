#!/usr/bin/env bash
# Verify trust-first error policy behavior for null_sigma_run.
set -euo pipefail

cd "$(dirname "$0")/.."
HARNESS_DIR="$(pwd)"
RULE_DIR="$HARNESS_DIR/../corpus/sigmahq/rules/windows/process_creation"

cargo build --release --bin null_sigma_run >/dev/null
TARGET_DIR="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
RUNNER="$TARGET_DIR/release/null_sigma_run"

[ -d "$RULE_DIR" ] || { echo "SigmaHQ corpus missing at $RULE_DIR"; exit 1; }

MIXED_FILE="$(mktemp)"
trap 'rm -f "$MIXED_FILE"' EXIT

cat >"$MIXED_FILE" <<'EOF'
{"CommandLine":"C:\\Windows\\System32\\cmd.exe /c whoami","event_category":"process_creation","event_product":"windows"}
{"CommandLine":"powershell -enc ZQBjAGgAbwAgAHgA","event_category":"process_creation","event_product":"windows"}
{"CommandLine":"bad_json_line"
[1,2,3]
{"CommandLine":"C:\\Windows\\System32\\notepad.exe","event_category":"process_creation","event_product":"windows"}
EOF

echo ">> continue mode should complete with non-zero error counters"
CONT_OUT="$("$RUNNER" --on-error continue "$RULE_DIR" "$MIXED_FILE" 2>&1 >/tmp/null_sigma_count_continue.txt)"
CONT_EXIT=$?
if [ "$CONT_EXIT" -ne 0 ]; then
    echo "FAIL: continue mode exited non-zero ($CONT_EXIT)"
    exit 1
fi
echo "$CONT_OUT" | rg "ingest_errors: io_read=0 json_parse=1 flatten=1 total=2" >/dev/null \
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
echo "$FAIL_OUT" | rg "bad event JSON|flatten failed|read error" >/dev/null \
    || { echo "FAIL: fail-fast mode did not report first event error"; echo "$FAIL_OUT"; exit 1; }

echo "PASS: error policy checks succeeded (continue + fail-fast)."
