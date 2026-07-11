#!/usr/bin/env bash
# Day 4 trust smoke umbrella: hermetic checks using committed fixtures only.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HARNESS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$HARNESS_DIR/.." && pwd)"
# shellcheck source=lib/rule_dir.sh
source "$SCRIPT_DIR/lib/rule_dir.sh"

export RULE_DIR="$(require_rule_dir "$REPO_ROOT")"

echo ">> trust smokes (rule_dir=$RULE_DIR)"
"$SCRIPT_DIR/smoke_error_policy.sh"
"$SCRIPT_DIR/smoke_robustness.sh"
"$SCRIPT_DIR/smoke_determinism.sh"

echo "PASS: trust smoke umbrella succeeded."
