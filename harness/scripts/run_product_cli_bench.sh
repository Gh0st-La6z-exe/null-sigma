#!/usr/bin/env bash
# =============================================================================
# Tier B-product — null-sigma-cli wall-clock hyperfine (≠ harness count-only)
#
# Measures the PRODUCT binary: lean NDJSON alerts written to /dev/null, vs
# pinned Hayabusa on the same SigmaHQ process_creation rules + seed-42 JSONL.
#
# Do NOT confuse with harness/scripts/run_cli_bench.sh (null_sigma_run,
# count-only). That remains "Tier B harness" in PERFORMANCE.md.
#
# Scientific protocol (record with every run):
#   - host: uname -a, nproc / sysctl ncpu, date -u ISO
#   - git:  rev-parse HEAD
#   - EVENTS / SEED / Hayabusa version pinned below
#   - warmup 1 + 5 runs; redirect CLI stdout → /dev/null (stderr tax lines OK)
#   - GHA ubuntu-latest is noisy shared metal — label results accordingly
# =============================================================================
set -euo pipefail

cd "$(dirname "$0")/.."
HARNESS_DIR="$(pwd)"
REPO_ROOT="$(cd "$HARNESS_DIR/.." && pwd)"
BIN_DIR="$HARNESS_DIR/bin"
DATA_DIR="$HARNESS_DIR/data"
RULE_DIR="$REPO_ROOT/corpus/sigmahq/rules/windows/process_creation"
EVENTS=${EVENTS:-100000}
SEED=${SEED:-42}

HAYABUSA_VERSION="3.9.0"

mkdir -p "$BIN_DIR" "$DATA_DIR"

command -v hyperfine >/dev/null || {
    echo "hyperfine not installed (macOS: brew install hyperfine; Ubuntu: apt/cargo)"
    exit 1
}
command -v curl >/dev/null
command -v unzip >/dev/null
command -v python3 >/dev/null

if [ ! -d "$RULE_DIR" ]; then
    echo "SigmaHQ corpus missing at $RULE_DIR"
    echo "  git clone --depth 1 https://github.com/SigmaHQ/sigma.git \"$REPO_ROOT/corpus/sigmahq\""
    exit 1
fi

ARCH="$(uname -m)"
OS="$(uname -s)"
case "$OS/$ARCH" in
    Darwin/arm64)
        HAYABUSA_ASSET="hayabusa-${HAYABUSA_VERSION}-mac-aarch64"
        ;;
    Darwin/x86_64)
        HAYABUSA_ASSET="hayabusa-${HAYABUSA_VERSION}-mac-x64"
        ;;
    Linux/x86_64|Linux/amd64)
        HAYABUSA_ASSET="hayabusa-${HAYABUSA_VERSION}-lin-x64-gnu"
        ;;
    Linux/aarch64|Linux/arm64)
        HAYABUSA_ASSET="hayabusa-${HAYABUSA_VERSION}-lin-aarch64-gnu"
        ;;
    *)
        echo "unsupported platform for pinned Hayabusa asset: $OS/$ARCH"
        exit 1
        ;;
esac

realpath_bin() {
    python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$1"
}

# ── Host / science header ────────────────────────────────────────────────────
GIT_SHA="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
GIT_SHA_SHORT="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
NCPU="$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo unknown)"
HOST_DATE_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
UNAME_A="$(uname -a)"
META_FILE="$DATA_DIR/tier_b_product_meta.txt"
RESULTS_MD="$DATA_DIR/tier_b_product_results.md"

{
    echo "tier: B-product (null-sigma-cli lean NDJSON → /dev/null)"
    echo "date_utc: $HOST_DATE_UTC"
    echo "git_sha: $GIT_SHA"
    echo "git_sha_short: $GIT_SHA_SHORT"
    echo "uname: $UNAME_A"
    echo "ncpu: $NCPU"
    echo "events: $EVENTS"
    echo "seed: $SEED"
    echo "hayabusa: $HAYABUSA_VERSION ($HAYABUSA_ASSET)"
    echo "hyperfine: warmup=1 runs=5"
    if [ "$EVENTS" = "100000" ] && [ "$OS" = "Linux" ]; then
        echo "status: candidate_authoritative (Linux 100k; still label GHA shared-metal noise)"
    else
        echo "status: pilot_only (not a published bake-off; use EVENTS=100000 on Linux for candidate numbers)"
    fi
    echo "notes: GHA ubuntu-latest is shared/noisy; dedicated Linux may supersede. Never merge into harness Tier B table."
} | tee "$META_FILE"

# ── Fetch Hayabusa ───────────────────────────────────────────────────────────
if [ ! -x "$BIN_DIR/hayabusa" ]; then
    echo ">> downloading hayabusa v$HAYABUSA_VERSION ($HAYABUSA_ASSET)"
    curl -sL -o "$BIN_DIR/hayabusa.zip" \
        "https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VERSION}/${HAYABUSA_ASSET}.zip"
    shasum -a 256 "$BIN_DIR/hayabusa.zip" | tee "$BIN_DIR/hayabusa-product.zip.sha256"
    rm -rf "$BIN_DIR/hayabusa-dist"
    unzip -o -q "$BIN_DIR/hayabusa.zip" -d "$BIN_DIR/hayabusa-dist"
    HAYABUSA_BIN="$(find "$BIN_DIR/hayabusa-dist" -type f \( -name "hayabusa-${HAYABUSA_VERSION}*" -o -name hayabusa \) ! -name '*.dll' | head -1)"
    [ -n "$HAYABUSA_BIN" ] || { echo "hayabusa binary not found in zip"; exit 1; }
    chmod +x "$HAYABUSA_BIN"
    ln -sfn "$HAYABUSA_BIN" "$BIN_DIR/hayabusa"
fi

HAYA_REAL="$(realpath_bin "$BIN_DIR/hayabusa")"
HAYA_CONFIG="$(dirname "$HAYA_REAL")/rules/config"
[ -d "$HAYA_CONFIG" ] || {
    # Some zips nest config one level up from the binary.
    HAYA_CONFIG="$(dirname "$(dirname "$HAYA_REAL")")/rules/config"
}
[ -d "$HAYA_CONFIG" ] || { echo "hayabusa rules/config missing near $HAYA_REAL"; exit 1; }

# ── Build CLI + harness generator (+ optional count-only runner for tax) ─────
echo ">> building null-sigma-cli (release)"
(cd "$REPO_ROOT/cli" && cargo build --release --bin null-sigma-cli)

echo ">> building harness gen_dataset + null_sigma_run (release)"
cargo build --release --bin gen_dataset --bin null_sigma_run

CLI_TARGET="$(cd "$REPO_ROOT/cli" && cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
CLI_BIN="$CLI_TARGET/release/null-sigma-cli"
HARNESS_TARGET="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
GEN="$HARNESS_TARGET/release/gen_dataset"
COUNT_RUNNER="$HARNESS_TARGET/release/null_sigma_run"

[ -x "$CLI_BIN" ] || { echo "missing $CLI_BIN"; exit 1; }

FLAT="$DATA_DIR/events_flat_${EVENTS}.jsonl"
EVTX="$DATA_DIR/events_evtx_${EVENTS}.jsonl"
if [ ! -f "$FLAT" ] || [ ! -f "$EVTX" ]; then
    echo ">> generating $EVENTS events (seed $SEED)"
    "$GEN" "$DATA_DIR" "$EVENTS" "$SEED"
fi

# ── Smoke ────────────────────────────────────────────────────────────────────
echo ">> smoke: null-sigma-cli (stdout discarded)"
"$CLI_BIN" --rules "$RULE_DIR" --threads 1 --on-error continue "$FLAT" >/dev/null

echo ">> smoke: hayabusa help (3.9.0 has no 'version' subcommand)"
"$BIN_DIR/hayabusa" help 2>&1 | head -5 || true

HAYA_OUT="$DATA_DIR/hayabusa_product_out"
echo ">> smoke: hayabusa detection count"
rm -f "$HAYA_OUT.jsonl"
"$BIN_DIR/hayabusa" json-timeline -J -f "$EVTX" -r "$RULE_DIR" -c "$HAYA_CONFIG" \
    -w -Q -q -o "$HAYA_OUT.jsonl" 2>/dev/null | tail -10 || true
[ -f "$HAYA_OUT.jsonl" ] && wc -l "$HAYA_OUT.jsonl"

# ── Hyperfine ────────────────────────────────────────────────────────────────
echo ">> hyperfine (Tier B-product)"
hyperfine --warmup 1 --runs 5 \
    --prepare "rm -f \"$HAYA_OUT-bench1.jsonl\" \"$HAYA_OUT-benchN.jsonl\"" \
    --export-markdown "$RESULTS_MD" \
    --command-name "null-sigma-cli-1-thread" \
    "\"$CLI_BIN\" --rules \"$RULE_DIR\" --threads 1 --on-error continue \"$FLAT\" >/dev/null" \
    --command-name "null-sigma-cli-4-thread" \
    "\"$CLI_BIN\" --rules \"$RULE_DIR\" --threads 4 --on-error continue \"$FLAT\" >/dev/null" \
    --command-name "null-sigma-cli-default-threads" \
    "\"$CLI_BIN\" --rules \"$RULE_DIR\" --threads 0 --on-error continue \"$FLAT\" >/dev/null" \
    --command-name "null-sigma-runner-default-threads-count-only" \
    "\"$COUNT_RUNNER\" --threads 0 \"$RULE_DIR\" \"$FLAT\" >/dev/null" \
    --command-name "hayabusa-1-thread" \
    "\"$BIN_DIR/hayabusa\" json-timeline -J -f \"$EVTX\" -r \"$RULE_DIR\" -c \"$HAYA_CONFIG\" -w -Q -q --threads 1 -o \"$HAYA_OUT-bench1.jsonl\"" \
    --command-name "hayabusa-default-threads" \
    "\"$BIN_DIR/hayabusa\" json-timeline -J -f \"$EVTX\" -r \"$RULE_DIR\" -c \"$HAYA_CONFIG\" -w -Q -q -o \"$HAYA_OUT-benchN.jsonl\""

# Prepend science header into markdown for artifact consumers.
TMP_MD="$(mktemp)"
{
    echo "# Tier B-product hyperfine results"
    echo
    echo '```'
    cat "$META_FILE"
    echo '```'
    echo
    echo "## Relative interpretation"
    echo
    echo "- \`null-sigma-cli-*\` — product path (alerts serialized; stdout discarded)."
    echo "- \`null-sigma-runner-*-count-only\` — harness machine (no alert I/O); tax delta vs CLI."
    echo "- Hayabusa rows — competitor full tool (file output)."
    echo "- Do not paste these into the harness Tier B table without renaming the meter."
    echo
    cat "$RESULTS_MD"
} >"$TMP_MD"
mv "$TMP_MD" "$RESULTS_MD"

echo ">> meta:    $META_FILE"
echo ">> results: $RESULTS_MD"
cat "$RESULTS_MD"
