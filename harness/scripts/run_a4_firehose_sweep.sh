#!/usr/bin/env bash
# =============================================================================
# A4 Alert-Firehose Sweep — product tax slope vs controlled event-hit rate
#
# Sibling meter to Tier B-product (§11.12). Does NOT replace §11.12 and must
# never be merged into the harness Tier B table.
#
# Independently measures:
#   H1 Tax   = T_CLI_default / T_count_only_runner
#   H2 Falcon = T_Hayabusa_default / T_CLI_default   (>1 ⇒ we win)
#
# Profiles (m ≈ 1, one-rule pack tests/fixtures/rules/a4_hit):
#   L  hit_bpm=100   → p=1%
#   M  hit_bpm=1000  → p=10%
#   H  hit_bpm=5000  → p=50%
#
# Gates (pre-committed; printed, not CI-hard-fail except H2@M):
#   H1 @ M  PASS ≤1.15× | SOFT 1.15–1.50× | HARD >1.50×
#   H1 @ H  document stress
#   H2 @ M  PASS Falcon ≥1.0 | HARD Falcon <1.0
#
# Usage:
#   EVENTS=5000  ./scripts/run_a4_firehose_sweep.sh   # pilot / script smoke
#   EVENTS=100000 ./scripts/run_a4_firehose_sweep.sh  # candidate ink
# =============================================================================
set -euo pipefail

cd "$(dirname "$0")/.."
HARNESS_DIR="$(pwd)"
REPO_ROOT="$(cd "$HARNESS_DIR/.." && pwd)"
BIN_DIR="$HARNESS_DIR/bin"
DATA_DIR="$HARNESS_DIR/data"
RULE_DIR="$REPO_ROOT/tests/fixtures/rules/a4_hit"
EVENTS=${EVENTS:-100000}
SEED=${SEED:-42}

HAYABUSA_VERSION="3.9.0"

# profile_name:hit_bpm pairs
PROFILES=("L:100" "M:1000" "H:5000")

mkdir -p "$BIN_DIR" "$DATA_DIR"

command -v hyperfine >/dev/null || {
    echo "hyperfine not installed (macOS: brew install hyperfine; Ubuntu: apt/cargo)"
    exit 1
}
command -v curl >/dev/null
command -v unzip >/dev/null
command -v python3 >/dev/null
command -v rg >/dev/null || {
    echo "ripgrep (rg) required for preflight"
    exit 1
}

[ -d "$RULE_DIR" ] || { echo "A4 rule pack missing at $RULE_DIR"; exit 1; }

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

expected_hits() {
    local count="$1" bpm="$2"
    python3 -c "c=int('$count'); b=min(int('$bpm'),10000); print((c//10000)*b + min(c%10000, b))"
}

# ── Host / science header ────────────────────────────────────────────────────
GIT_SHA="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
GIT_SHA_SHORT="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
NCPU="$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo unknown)"
HOST_DATE_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
UNAME_A="$(uname -a)"
META_FILE="$DATA_DIR/a4_meta.txt"
RESULTS_MD="$DATA_DIR/a4_results.md"
SLOPE_CSV="$DATA_DIR/a4_slope.csv"

{
    echo "tier: A4 alert-firehose sweep (sibling to §11.12 B-product; never merge meters)"
    echo "date_utc: $HOST_DATE_UTC"
    echo "git_sha: $GIT_SHA"
    echo "git_sha_short: $GIT_SHA_SHORT"
    echo "uname: $UNAME_A"
    echo "ncpu: $NCPU"
    echo "events: $EVENTS"
    echo "seed: $SEED"
    echo "profiles: L=100bpm(1%) M=1000bpm(10%) H=5000bpm(50%) m≈1"
    echo "rules: $RULE_DIR"
    echo "hayabusa: $HAYABUSA_VERSION ($HAYABUSA_ASSET)"
    echo "hyperfine: warmup=1 runs=5"
    echo "gates: H1@M PASS≤1.15 SOFT≤1.50 HARD>1.50; H2@M PASS Falcon≥1.0"
    if [ "$EVENTS" = "100000" ] && [ "$OS" = "Linux" ]; then
        echo "status: candidate_authoritative (Linux 100k; label GHA shared-metal noise if applicable)"
    else
        echo "status: pilot_only (not a published slope ink; use EVENTS=100000 on Linux for candidate)"
    fi
    echo "notes: Do not merge into §11.12 or harness Tier B. Dual metrics H1 tax / H2 Falcon."
} | tee "$META_FILE"

# ── Fetch Hayabusa ───────────────────────────────────────────────────────────
if [ ! -x "$BIN_DIR/hayabusa" ]; then
    echo ">> downloading hayabusa v$HAYABUSA_VERSION ($HAYABUSA_ASSET)"
    curl -sL -o "$BIN_DIR/hayabusa.zip" \
        "https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VERSION}/${HAYABUSA_ASSET}.zip"
    shasum -a 256 "$BIN_DIR/hayabusa.zip" | tee "$BIN_DIR/hayabusa-a4.zip.sha256"
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
    HAYA_CONFIG="$(dirname "$(dirname "$HAYA_REAL")")/rules/config"
}
[ -d "$HAYA_CONFIG" ] || { echo "hayabusa rules/config missing near $HAYA_REAL"; exit 1; }

# ── Build ────────────────────────────────────────────────────────────────────
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
[ -x "$GEN" ] || { echo "missing $GEN"; exit 1; }
[ -x "$COUNT_RUNNER" ] || { echo "missing $COUNT_RUNNER"; exit 1; }

# Slope CSV header
echo "profile,hit_bpm,p,expected_hits,measured_matches,stdout_lines,t_count,t_cli_default,tax,t_haya_default,falcon,t_cli_st,t_haya_st,h1_gate,h2_gate" >"$SLOPE_CSV"

HF_SECTIONS=""

for entry in "${PROFILES[@]}"; do
    PROF="${entry%%:*}"
    BPM="${entry##*:}"
    EXPECTED="$(expected_hits "$EVENTS" "$BPM")"
    P_PCT="$(python3 -c "print('{:.2f}'.format(int('$BPM')/100))")"

    echo ""
    echo "========== profile $PROF  hit_bpm=$BPM  p=${P_PCT}%  expected_hits=$EXPECTED =========="

    FLAT="$DATA_DIR/events_flat_a4_${EVENTS}_bpm${BPM}.jsonl"
    EVTX="$DATA_DIR/events_evtx_a4_${EVENTS}_bpm${BPM}.jsonl"
    if [ ! -f "$FLAT" ] || [ ! -f "$EVTX" ]; then
        echo ">> generating A4 dataset bpm=$BPM"
        "$GEN" "$DATA_DIR" "$EVENTS" "$SEED" --a4-hit-bpm "$BPM"
    else
        echo ">> reusing $FLAT"
    fi

    PRE_ERR="$DATA_DIR/a4_preflight_${PROF}_err.txt"
    PRE_OUT="$DATA_DIR/a4_preflight_${PROF}_out.txt"
    echo ">> preflight: null-sigma-cli (assert matches ≈ expected)"
    "$CLI_BIN" --rules "$RULE_DIR" --threads 1 --on-error continue "$FLAT" \
        >"$PRE_OUT" 2>"$PRE_ERR"

    MATCHES_LINE="$(rg -m1 'matches: [0-9]+' "$PRE_ERR" || true)"
    MEASURED="$(echo "$MATCHES_LINE" | python3 -c 'import re,sys; m=re.search(r"matches: (\d+)", sys.stdin.read()); print(m.group(1) if m else "")')"
    if [ -z "$MEASURED" ]; then
        echo "FAIL: preflight could not parse matches from stderr"
        cat "$PRE_ERR"
        exit 1
    fi
    DELTA="$(python3 -c "print(abs(int('$MEASURED')-int('$EXPECTED')))")"
    if [ "$DELTA" -gt 1 ]; then
        echo "FAIL: matches=$MEASURED expected=$EXPECTED (delta=$DELTA > 1)"
        cat "$PRE_ERR"
        exit 1
    fi
    STDOUT_LINES="$(wc -l <"$PRE_OUT" | tr -d ' ')"
    LINE_DELTA="$(python3 -c "print(abs(int('$STDOUT_LINES')-int('$MEASURED')))")"
    if [ "$LINE_DELTA" -gt 1 ]; then
        echo "FAIL: stdout lines=$STDOUT_LINES measured matches=$MEASURED"
        exit 1
    fi
    echo ">> preflight OK: matches=$MEASURED expected=$EXPECTED stdout_lines=$STDOUT_LINES"

    HAYA_SMOKE_OUT="$DATA_DIR/hayabusa_a4_${PROF}_smoke.jsonl"
    echo ">> preflight: hayabusa must load ≥1 rule and detect ≈ expected"
    rm -f "$HAYA_SMOKE_OUT"
    HAYA_SMOKE_LOG="$DATA_DIR/a4_haya_preflight_${PROF}.txt"
    set +e
    "$BIN_DIR/hayabusa" json-timeline -J -f "$EVTX" -r "$RULE_DIR" -c "$HAYA_CONFIG" \
        -w -Q -q -o "$HAYA_SMOKE_OUT" >"$HAYA_SMOKE_LOG" 2>&1
    HAYA_RC=$?
    set -e
    if ! python3 -c "
import pathlib,re
t=pathlib.Path('$HAYA_SMOKE_LOG').read_text(errors='replace')
t=re.sub(r'\x1b\[[0-9;]*m','',t)
import sys
sys.exit(0 if re.search(r'Total detection rules:\s*1\b', t) else 1)
"; then
        echo "FAIL: Hayabusa did not load exactly 1 detection rule (check date/status fields)"
        cat "$HAYA_SMOKE_LOG"
        ls -la "$HARNESS_DIR/logs" 2>/dev/null | tail -3 || true
        exit 1
    fi
    if ! python3 -c "
import pathlib,re
t=pathlib.Path('$HAYA_SMOKE_LOG').read_text(errors='replace')
t=re.sub(r'\x1b\[[0-9;]*m','',t)
import sys
sys.exit(0 if 'A4 Controlled Hit' in t else 1)
"; then
        echo "FAIL: Hayabusa smoke did not report A4 Controlled Hit detections"
        cat "$HAYA_SMOKE_LOG"
        exit 1
    fi
    echo ">> hayabusa preflight OK (rc=$HAYA_RC)"

    HAYA_OUT="$DATA_DIR/hayabusa_a4_${PROF}"
    HF_MD="$DATA_DIR/a4_hf_${PROF}.md"
    echo ">> hyperfine profile $PROF"
    hyperfine --warmup 1 --runs 5 \
        --prepare "rm -f \"${HAYA_OUT}-bench1.jsonl\" \"${HAYA_OUT}-benchN.jsonl\"" \
        --export-markdown "$HF_MD" \
        --command-name "null-sigma-cli-1-thread" \
        "\"$CLI_BIN\" --rules \"$RULE_DIR\" --threads 1 --on-error continue \"$FLAT\" >/dev/null" \
        --command-name "null-sigma-cli-4-thread" \
        "\"$CLI_BIN\" --rules \"$RULE_DIR\" --threads 4 --on-error continue \"$FLAT\" >/dev/null" \
        --command-name "null-sigma-cli-default-threads" \
        "\"$CLI_BIN\" --rules \"$RULE_DIR\" --threads 0 --on-error continue \"$FLAT\" >/dev/null" \
        --command-name "null-sigma-runner-default-threads-count-only" \
        "\"$COUNT_RUNNER\" --threads 0 \"$RULE_DIR\" \"$FLAT\" >/dev/null" \
        --command-name "hayabusa-1-thread" \
        "\"$BIN_DIR/hayabusa\" json-timeline -J -f \"$EVTX\" -r \"$RULE_DIR\" -c \"$HAYA_CONFIG\" -w -Q -q --threads 1 -o \"${HAYA_OUT}-bench1.jsonl\"" \
        --command-name "hayabusa-default-threads" \
        "\"$BIN_DIR/hayabusa\" json-timeline -J -f \"$EVTX\" -r \"$RULE_DIR\" -c \"$HAYA_CONFIG\" -w -Q -q -o \"${HAYA_OUT}-benchN.jsonl\""

    # Parse means from hyperfine markdown (column 2 of | name | mean ± … |)
    parse_mean() {
        local name="$1" file="$2"
        rg -F "| \`$name\`" "$file" | head -1 | python3 -c '
import sys,re
line=sys.stdin.read()
# | `name` | 1.234 ± 0.01 | ...
m=re.search(r"\|\s*`[^`]+`\s*\|\s*([0-9.]+)", line)
print(m.group(1) if m else "")
'
    }

    T_CLI_ST="$(parse_mean "null-sigma-cli-1-thread" "$HF_MD")"
    T_CLI_DEF="$(parse_mean "null-sigma-cli-default-threads" "$HF_MD")"
    T_COUNT="$(parse_mean "null-sigma-runner-default-threads-count-only" "$HF_MD")"
    T_HAYA_ST="$(parse_mean "hayabusa-1-thread" "$HF_MD")"
    T_HAYA_DEF="$(parse_mean "hayabusa-default-threads" "$HF_MD")"

    for v in T_CLI_ST T_CLI_DEF T_COUNT T_HAYA_ST T_HAYA_DEF; do
        eval "val=\$$v"
        if [ -z "$val" ]; then
            echo "FAIL: could not parse hyperfine mean for $v from $HF_MD"
            cat "$HF_MD"
            exit 1
        fi
    done

    TAX="$(python3 -c "print('{:.4f}'.format(float('$T_CLI_DEF')/float('$T_COUNT')))")"
    FALCON="$(python3 -c "print('{:.4f}'.format(float('$T_HAYA_DEF')/float('$T_CLI_DEF')))")"

    # Gate markers
    H1_GATE="$(python3 -c "
t=float('$TAX')
prof='$PROF'
if prof=='M':
    print('PASS' if t<=1.15 else ('SOFT' if t<=1.50 else 'HARD'))
elif prof=='H':
    print('STRESS_OK' if t<=1.50 else ('STRESS_SOFT' if t<=2.50 else 'STRESS_HARD'))
else:
    print('INFO')
")"
    H2_GATE="$(python3 -c "
f=float('$FALCON')
prof='$PROF'
if prof=='M':
    print('PASS' if f>=1.0 else 'HARD')
else:
    print('INFO')
")"

    echo ">> $PROF tax=$TAX ($H1_GATE)  falcon=$FALCON ($H2_GATE)"

    echo "$PROF,$BPM,${P_PCT}%,$EXPECTED,$MEASURED,$STDOUT_LINES,$T_COUNT,$T_CLI_DEF,$TAX,$T_HAYA_DEF,$FALCON,$T_CLI_ST,$T_HAYA_ST,$H1_GATE,$H2_GATE" >>"$SLOPE_CSV"

    HF_SECTIONS="${HF_SECTIONS}
## Profile ${PROF} (p=${P_PCT}%, bpm=${BPM}, matches=${MEASURED})

- **tax (H1)** = ${TAX}  gate=\`${H1_GATE}\`
- **Falcon (H2)** = ${FALCON}  gate=\`${H2_GATE}\`

$(cat "$HF_MD")
"
done

# ── Assemble results markdown ────────────────────────────────────────────────
{
    echo "# A4 Alert-Firehose Sweep results"
    echo
    echo '```'
    cat "$META_FILE"
    echo '```'
    echo
    echo "## Slope summary (H1 tax / H2 Falcon)"
    echo
    echo "| Profile | p | matches | T_count | T_CLI_def | **tax** | T_Haya_def | **Falcon** | H1 | H2 |"
    echo "|---|---:|---:|---:|---:|---:|---:|---:|---|---|"
    python3 - <<'PY'
import csv, pathlib
p = pathlib.Path("data/a4_slope.csv")
with p.open() as f:
    r = csv.DictReader(f)
    for row in r:
        print(
            f"| {row['profile']} | {row['p']} | {row['measured_matches']} | "
            f"{row['t_count']} | {row['t_cli_default']} | **{row['tax']}** | "
            f"{row['t_haya_default']} | **{row['falcon']}** | "
            f"{row['h1_gate']} | {row['h2_gate']} |"
        )
PY
    echo
    echo "## Interpretation"
    echo
    echo "- **H1 Tax** — product CLI vs count-only runner reference on the *same* A4 fixture. Tax < 1 means the product pipeline outpaced this different runner; it is not negative emit cost."
    echo "- **H2 Falcon** — Hayabusa default / CLI default on the *same* A4 fixture. Independent of tax."
    echo "- Gates: H1@M PASS≤1.15 / SOFT≤1.50 / HARD>1.50; H2@M PASS if Falcon≥1.0."
    echo "- Do **not** paste into §11.12 B-product or harness Tier B tables."
    echo
    echo "$HF_SECTIONS"
} >"$RESULTS_MD"

echo ""
echo ">> meta:    $META_FILE"
echo ">> slope:   $SLOPE_CSV"
echo ">> results: $RESULTS_MD"
cat "$RESULTS_MD"
