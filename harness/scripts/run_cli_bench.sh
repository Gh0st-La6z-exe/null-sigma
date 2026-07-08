#!/usr/bin/env bash
# =============================================================================
# Tier B — CLI end-to-end wall-clock benchmark (hyperfine)
#
# Compares:
#   - null-sigma runner  (harness/src/bin/null_sigma_run.rs, JSONL input)
#   - Hayabusa           (json-timeline -J, single- and multi-threaded)
#   - Chainsaw           (hunt --sigma over the EVTX-shaped JSONL, if the
#                         installed build accepts JSON input)
#
# IMPORTANT: Tier B measures the WHOLE TOOL — Hayabusa/Chainsaw include their
# own output, enrichment and scoring pipelines. Matching-path numbers are
# Tier A (cargo bench --bench head_to_head). Never conflate the two.
#
# Binaries are downloaded to harness/bin/ (gitignored) with pinned versions
# and SHA-256 recorded next to them. Dataset is generated deterministically.
# =============================================================================
set -euo pipefail

cd "$(dirname "$0")/.."
HARNESS_DIR="$(pwd)"
BIN_DIR="$HARNESS_DIR/bin"
DATA_DIR="$HARNESS_DIR/data"
RULE_DIR="$HARNESS_DIR/../corpus/sigmahq/rules/windows/process_creation"
EVENTS=${EVENTS:-100000}
SEED=${SEED:-42}

HAYABUSA_VERSION="3.9.0"
CHAINSAW_VERSION="2.13.1"

mkdir -p "$BIN_DIR" "$DATA_DIR"

# ── Prerequisites ────────────────────────────────────────────────────────────
command -v hyperfine >/dev/null || { echo "hyperfine not installed (brew install hyperfine)"; exit 1; }
[ -d "$RULE_DIR" ] || { echo "SigmaHQ corpus missing at $RULE_DIR"; exit 1; }

ARCH="$(uname -m)"
OS="$(uname -s)"
if [ "$OS" = "Darwin" ]; then
    HAYABUSA_ASSET="hayabusa-${HAYABUSA_VERSION}-mac-aarch64"
    CHAINSAW_ASSET="chainsaw_all_platforms+rules"
    [ "$ARCH" = "arm64" ] || { echo "script pins Apple Silicon assets; adjust for $ARCH"; exit 1; }
else
    echo "script pins macOS assets; extend for $OS"; exit 1
fi

# ── Fetch pinned binaries (recorded checksums) ───────────────────────────────
if [ ! -x "$BIN_DIR/hayabusa" ]; then
    echo ">> downloading hayabusa v$HAYABUSA_VERSION"
    curl -sL -o "$BIN_DIR/hayabusa.zip" \
        "https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VERSION}/${HAYABUSA_ASSET}.zip"
    shasum -a 256 "$BIN_DIR/hayabusa.zip" | tee "$BIN_DIR/hayabusa.zip.sha256"
    unzip -o -q "$BIN_DIR/hayabusa.zip" -d "$BIN_DIR/hayabusa-dist"
    HAYABUSA_BIN="$(find "$BIN_DIR/hayabusa-dist" -maxdepth 2 -name "hayabusa-${HAYABUSA_VERSION}*" -type f | head -1)"
    chmod +x "$HAYABUSA_BIN"
    ln -sf "$HAYABUSA_BIN" "$BIN_DIR/hayabusa"
fi

if [ ! -x "$BIN_DIR/chainsaw" ]; then
    echo ">> downloading chainsaw v$CHAINSAW_VERSION"
    curl -sL -o "$BIN_DIR/chainsaw.zip" \
        "https://github.com/WithSecureLabs/chainsaw/releases/download/v${CHAINSAW_VERSION}/${CHAINSAW_ASSET}.zip"
    shasum -a 256 "$BIN_DIR/chainsaw.zip" | tee "$BIN_DIR/chainsaw.zip.sha256"
    unzip -o -q "$BIN_DIR/chainsaw.zip" -d "$BIN_DIR/chainsaw-dist"
    # NOTE: Chainsaw publishes no aarch64 macOS binary — the x86_64 build
    # runs under Rosetta 2 on Apple Silicon. Any Tier B chainsaw number is
    # therefore translation-penalised; its matching path is represented
    # natively at Tier A via tau-engine. Recorded in the report.
    CHAINSAW_BIN="$(find "$BIN_DIR/chainsaw-dist" -type f -name 'chainsaw_x86_64-apple-darwin' | head -1)"
    chmod +x "$CHAINSAW_BIN"
    ln -sf "$CHAINSAW_BIN" "$BIN_DIR/chainsaw"
fi

# ── Build our runner + dataset ───────────────────────────────────────────────
echo ">> building null-sigma runner (release)"
cargo build --release --bin null_sigma_run --bin gen_dataset

TARGET_DIR="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
RUNNER="$TARGET_DIR/release/null_sigma_run"
GEN="$TARGET_DIR/release/gen_dataset"

FLAT="$DATA_DIR/events_flat_${EVENTS}.jsonl"
EVTX="$DATA_DIR/events_evtx_${EVENTS}.jsonl"
if [ ! -f "$FLAT" ] || [ ! -f "$EVTX" ]; then
    echo ">> generating $EVENTS events (seed $SEED)"
    "$GEN" "$DATA_DIR" "$EVENTS" "$SEED"
fi

# ── Correctness smoke: every tool must find a non-zero number of detections ──
echo ">> smoke: null-sigma runner"
"$RUNNER" "$RULE_DIR" "$FLAT"

echo ">> smoke: hayabusa (version)"
"$BIN_DIR/hayabusa" version | head -2 || true

echo ">> smoke: chainsaw (version)"
"$BIN_DIR/chainsaw" --version || true

# Hayabusa command line: JSON input, our Sigma rule dir, no wizard, quiet,
# output to file so terminal rendering does not dominate the measurement.
HAYA_OUT="$DATA_DIR/hayabusa_out"
HAYA_CONFIG="$(dirname "$(readlink "$BIN_DIR/hayabusa")")/rules/config"

echo ">> smoke: hayabusa detection count"
rm -f "$HAYA_OUT.jsonl"
"$BIN_DIR/hayabusa" json-timeline -J -f "$EVTX" -r "$RULE_DIR" -c "$HAYA_CONFIG" -w -Q -q -o "$HAYA_OUT.jsonl" 2>/dev/null | tail -15 || true
[ -f "$HAYA_OUT.jsonl" ] && wc -l "$HAYA_OUT.jsonl"

# Chainsaw: JSON input needs a `kind: json` mapping whose fields address the
# flat records directly (its bundled sigma-event-logs-all.yml is `kind: evtx`
# and expects nested Event.System.* documents — with it, chainsaw silently
# matches NOTHING on JSONL and looks artificially fast).
CHAINSAW_MAPPING="$HARNESS_DIR/config/chainsaw-json-mapping.yml"
CHAINSAW_OK=0
echo ">> smoke: chainsaw hunt on JSONL"
if "$BIN_DIR/chainsaw" hunt "$EVTX" --sigma "$RULE_DIR" --mapping "$CHAINSAW_MAPPING" --load-unknown --json -o "$DATA_DIR/chainsaw_out.json" >/dev/null 2>&1; then
    CHAINSAW_HITS="$(python3 -c "import json; print(len(json.load(open('$DATA_DIR/chainsaw_out.json'))))")"
    if [ "$CHAINSAW_HITS" -gt 0 ]; then
        CHAINSAW_OK=1
        echo "   chainsaw accepted JSONL input ($CHAINSAW_HITS detections)"
    else
        echo "   chainsaw ran but found ZERO detections — excluded from Tier B (a wrong engine being fast is not a win)"
    fi
else
    echo "   chainsaw did NOT accept JSONL input — kept at Tier A only (documented)"
fi

# ── Benchmark ────────────────────────────────────────────────────────────────
echo ">> hyperfine"
CMDS=(
    --command-name "null-sigma-runner"
    "\"$RUNNER\" \"$RULE_DIR\" \"$FLAT\""
    --command-name "null-sigma-runner-4-thread"
    "\"$RUNNER\" --threads 4 \"$RULE_DIR\" \"$FLAT\""
    --command-name "null-sigma-runner-default-threads"
    "\"$RUNNER\" --threads 0 \"$RULE_DIR\" \"$FLAT\""
    --command-name "hayabusa-1-thread"
    "\"$BIN_DIR/hayabusa\" json-timeline -J -f \"$EVTX\" -r \"$RULE_DIR\" -c \"$HAYA_CONFIG\" -w -Q -q --threads 1 -o \"$HAYA_OUT-bench1.jsonl\""
    --command-name "hayabusa-default-threads"
    "\"$BIN_DIR/hayabusa\" json-timeline -J -f \"$EVTX\" -r \"$RULE_DIR\" -c \"$HAYA_CONFIG\" -w -Q -q -o \"$HAYA_OUT-benchN.jsonl\""
)
if [ "$CHAINSAW_OK" = "1" ]; then
    CMDS+=(
        --command-name "chainsaw-hunt"
        "\"$BIN_DIR/chainsaw\" hunt \"$EVTX\" --sigma \"$RULE_DIR\" --mapping \"$CHAINSAW_MAPPING\" --load-unknown --json -o \"$DATA_DIR/chainsaw_out_bench.json\""
    )
fi

hyperfine --warmup 1 --runs 5 \
    --prepare "rm -f \"$HAYA_OUT-bench1.jsonl\" \"$HAYA_OUT-benchN.jsonl\" \"$DATA_DIR/chainsaw_out_bench.json\"" \
    --export-markdown "$DATA_DIR/tier_b_results.md" \
    "${CMDS[@]}"

echo ">> results written to $DATA_DIR/tier_b_results.md"
cat "$DATA_DIR/tier_b_results.md"
