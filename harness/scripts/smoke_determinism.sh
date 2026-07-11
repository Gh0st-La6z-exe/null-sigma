#!/usr/bin/env bash
# Day 3 determinism smoke: identical ingest accounting across two runs.
set -euo pipefail

cd "$(dirname "$0")/.."
HARNESS_DIR="$(pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HARNESS_DIR/.." && pwd)"
# shellcheck source=lib/rule_dir.sh
source "$SCRIPT_DIR/lib/rule_dir.sh"
RULE_DIR="$(require_rule_dir "$REPO_ROOT")"
FIXTURE="$REPO_ROOT/tests/fixtures/robustness/mixed_valid_invalid.jsonl"

cargo build --release --bin null_sigma_run >/dev/null
TARGET_DIR="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
RUNNER="$TARGET_DIR/release/null_sigma_run"

[ -f "$FIXTURE" ] || { echo "fixture missing at $FIXTURE"; exit 1; }

extract_accounting_lines() {
    "$RUNNER" "$@" 2>&1 | rg '^(ingest_errors:|ingest_accounting:) '
}

echo ">> determinism on mixed_valid_invalid.jsonl (threads=1)"
RUN1="$(extract_accounting_lines --threads 1 --on-error continue "$RULE_DIR" "$FIXTURE")"
RUN2="$(extract_accounting_lines --threads 1 --on-error continue "$RULE_DIR" "$FIXTURE")"
if [ "$RUN1" != "$RUN2" ]; then
    echo "FAIL: ingest accounting drift between identical runs"
    echo "--- run 1 ---"
    echo "$RUN1"
    echo "--- run 2 ---"
    echo "$RUN2"
    exit 1
fi

echo "PASS: determinism checks succeeded."
