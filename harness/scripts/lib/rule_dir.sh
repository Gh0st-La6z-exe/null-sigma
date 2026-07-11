# Resolve rule directory for harness trust smokes.
# Default: committed minimal synthetic rules (hermetic CI).
# Override: RULE_DIR=/path/to/rules ./scripts/smoke_trust.sh
resolve_rule_dir() {
    local repo_root="$1"
    if [ -n "${RULE_DIR:-}" ]; then
        printf '%s\n' "$RULE_DIR"
        return
    fi
    printf '%s\n' "$repo_root/tests/fixtures/rules/minimal"
}

require_rule_dir() {
    local rule_dir
    rule_dir="$(resolve_rule_dir "$1")"
    if [ ! -d "$rule_dir" ]; then
        echo "rule dir missing at $rule_dir" >&2
        exit 1
    fi
    printf '%s\n' "$rule_dir"
}
