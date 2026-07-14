#!/usr/bin/env bash
# Hermetic ST↔MT parity for sequenced CLI pipeline (§4b).
# Uses committed fixtures only — no SigmaHQ.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$CLI_DIR/.." && pwd)"
RULE_DIR="$REPO_ROOT/tests/fixtures/rules/minimal"
MIXED="$REPO_ROOT/tests/fixtures/robustness/mixed_valid_invalid.jsonl"
THREADS=(1 2 4 0)

SMOKE_TMP="$(mktemp -d "${TMPDIR:-/tmp}/null_sigma_cli_parallel.XXXXXX")"
cleanup() { rm -rf "$SMOKE_TMP"; }
trap cleanup EXIT

cd "$CLI_DIR"
cargo build --release --bin null-sigma-cli >/dev/null
TARGET_DIR="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
RUNNER="$TARGET_DIR/release/null-sigma-cli"

[ -d "$RULE_DIR" ] || { echo "rule dir missing at $RULE_DIR"; exit 1; }
[ -f "$MIXED" ] || { echo "fixture missing at $MIXED"; exit 1; }

baseline_err=""
baseline_out=""
for t in "${THREADS[@]}"; do
    err="$SMOKE_TMP/err_t$t.txt"
    out="$SMOKE_TMP/out_t$t.txt"
    "$RUNNER" --rules "$RULE_DIR" --threads "$t" --on-error continue "$MIXED" \
        2>"$err" >"$out"
    acct="$(rg -m1 '^ingest_accounting:' "$err" || true)"
    errs="$(rg -m1 '^ingest_errors:' "$err" || true)"
    if [ -z "$acct" ] || [ -z "$errs" ]; then
        echo "FAIL: threads=$t missing trust lines"
        cat "$err"
        exit 1
    fi
    if [ -z "$baseline_err" ]; then
        baseline_err="$acct"$'\n'"$errs"
        cp "$out" "$SMOKE_TMP/out_baseline.txt"
        baseline_out="$SMOKE_TMP/out_baseline.txt"
        echo "baseline threads=$t"
        echo "$acct"
        echo "$errs"
    else
        got="$acct"$'\n'"$errs"
        if [ "$got" != "$baseline_err" ]; then
            echo "FAIL: threads=$t trust drift"
            echo "baseline:"
            echo "$baseline_err"
            echo "got:"
            echo "$got"
            exit 1
        fi
        if ! cmp -s "$out" "$baseline_out"; then
            echo "FAIL: threads=$t NDJSON stdout not byte-identical to threads=1"
            diff -u "$baseline_out" "$out" || true
            exit 1
        fi
    fi
done

# Giant line: oversize without early newline (continue)
OVER="$SMOKE_TMP/oversize.jsonl"
python3 - <<'PY' >"$OVER"
print("x" * 200)
print('{"Image":"C:\\\\Windows\\\\System32\\\\whoami.exe"}')
PY
"$RUNNER" --rules "$RULE_DIR" --threads 2 --on-error continue \
    --max-line-bytes 50 "$OVER" 2>"$SMOKE_TMP/over_err.txt" >"$SMOKE_TMP/over_out.txt"
rg -F 'line_too_large=1' "$SMOKE_TMP/over_err.txt" >/dev/null \
    || { echo "FAIL: expected line_too_large=1"; cat "$SMOKE_TMP/over_err.txt"; exit 1; }
rg -F 'invariant_ok=true' "$SMOKE_TMP/over_err.txt" >/dev/null \
    || { echo "FAIL: oversize accounting"; cat "$SMOKE_TMP/over_err.txt"; exit 1; }

echo "PASS: null-sigma-cli parallel parity + oversize checks succeeded."
