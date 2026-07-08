#!/usr/bin/env bash
# Verify null_sigma_run match counts are identical across thread counts.
set -euo pipefail

cd "$(dirname "$0")/.."
HARNESS_DIR="$(pwd)"
RULE_DIR="$HARNESS_DIR/../corpus/sigmahq/rules/windows/process_creation"
EVENTS_PATH="$HARNESS_DIR/data/events_flat_10000.jsonl"
THREADS=(1 2 4 8 0)

cargo build --release --bin null_sigma_run >/dev/null
TARGET_DIR="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
RUNNER="$TARGET_DIR/release/null_sigma_run"

[ -d "$RULE_DIR" ] || { echo "SigmaHQ corpus missing at $RULE_DIR"; exit 1; }
[ -f "$EVENTS_PATH" ] || { echo "dataset missing at $EVENTS_PATH"; exit 1; }

baseline=""
for t in "${THREADS[@]}"; do
    count="$("$RUNNER" --threads "$t" "$RULE_DIR" "$EVENTS_PATH" 2>/dev/null)"
    echo "threads=$t count=$count"
    if [ -z "$baseline" ]; then
        baseline="$count"
    elif [ "$count" != "$baseline" ]; then
        echo "FAIL: threads=$t count=$count != baseline=$baseline"
        exit 1
    fi
done

echo "PASS: all thread counts produced count=$baseline"
