#!/usr/bin/env bash
# =============================================================================
# Local flamegraph gate — Tier A prof_benign workload (samply).
#
# Output stays under harness/prof/ (gitignored). Does not publish artifacts.
#
# Prerequisites:
#   - SigmaHQ corpus at corpus/sigmahq (see harness/README.md)
#   - samply: cargo install samply
#
# Usage:
#   cd harness && ./scripts/prof_benign.sh
# =============================================================================
set -euo pipefail

cd "$(dirname "$0")/.."
HARNESS_DIR="$(pwd)"
PROF_DIR="$HARNESS_DIR/prof"
export CARGO_TARGET_DIR="$HARNESS_DIR/target"
mkdir -p "$PROF_DIR"

SAMPLY="${SAMPLY:-$HOME/.cargo/bin/samply}"
if [ ! -x "$SAMPLY" ]; then
    SAMPLY="$(command -v samply || true)"
fi
if [ -z "$SAMPLY" ] || [ ! -x "$SAMPLY" ]; then
    echo "samply not found — install with: cargo install samply"
    exit 1
fi

RULE_DIR="$HARNESS_DIR/../corpus/sigmahq/rules/windows/process_creation"
if [ ! -d "$RULE_DIR" ]; then
    echo "SigmaHQ corpus missing at $RULE_DIR"
    exit 1
fi

echo ">> building prof_benign (--profile prof, debug symbols)"
cargo build --profile prof --bin prof_benign

TARGET_DIR="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
BIN="$TARGET_DIR/prof/prof_benign"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
PROFILE_OUT="$PROF_DIR/samply_${TIMESTAMP}.json.gz"
SUMMARY_OUT="$PROF_DIR/summary_${TIMESTAMP}.txt"

if [ ! -f "$PROF_DIR/NOTES.md" ]; then
    cp "$HARNESS_DIR/scripts/prof_NOTES.template.md" "$PROF_DIR/NOTES.md"
    echo ">> created $PROF_DIR/NOTES.md — fill after reviewing profile"
fi

echo ">> recording with samply → $PROFILE_OUT"
"$SAMPLY" record --save-only --no-open -o "$PROFILE_OUT" "$BIN" 2>&1 | tee "$PROF_DIR/last_run_${TIMESTAMP}.log"

# Persist latest profile path for convenience
echo "$PROFILE_OUT" >"$PROF_DIR/latest_profile.txt"
ln -sf "$(basename "$PROFILE_OUT")" "$PROF_DIR/latest.json.gz" 2>/dev/null || true

echo ""
echo ">> done"
echo "   profile : $PROFILE_OUT"
echo "   stderr  : $PROF_DIR/last_run_${TIMESTAMP}.log"
echo "   notes   : $PROF_DIR/NOTES.md"
echo ""
echo "For symbolicated stacks, also run (during a live 100k loop):"
echo "   $BIN &  BPID=\$!; sleep 8; sample \$BPID 15 -mayDie -file $PROF_DIR/sample.txt; wait"
echo ""
echo "Open the samply profile:"
echo "   $SAMPLY load $PROFILE_OUT"
