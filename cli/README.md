# null-sigma-cli

ROADMAP §4 product CLI. Consumes the `null-sigma` library (`json` feature) and
keeps the core crate free of I/O.

## Status (Week 2 Day 1)

**Trust parity shipped:** file + stdin JSONL, Week 1 error policy, stderr
accounting contract, exit codes 0/1/2.

**Not yet:** NDJSON / `--format text` alerts (Day 2). Stdout is temporarily a
match-count integer.

The harness binary `null_sigma_run` remains the Tier B bench runner (count-only,
Rayon, competitor deps). This CLI is the installable product path.

## Build / run

```bash
cd cli
cargo build --release
# Binary lands in cargo's target dir (respects CARGO_TARGET_DIR if set):
BIN="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/release/null-sigma-cli"
"$BIN" --rules ../tests/fixtures/rules/minimal \
  ../tests/fixtures/robustness/mixed_valid_invalid.jsonl

# stdin
"$BIN" --rules ../tests/fixtures/rules/minimal - \
  < ../tests/fixtures/robustness/mixed_valid_invalid.jsonl
```

Install (local path; crates.io later):

```bash
cargo install --path cli
```

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--rules <dir>` | required | Sigma YAML directory |
| `--on-error continue\|fail-fast` | `continue` | Event-level error policy |
| `--max-line-bytes N` | 8 MiB | Reject oversize lines before parse |
| `--max-error-samples N` | 0 | Cap `ingest_error_sample:` lines |
| `--threads N` | 1 | Accepted; MVP is single-threaded (§4b for parallel) |
| `[events.jsonl \| -]` | stdin | Input path; `-` or omit → stdin |

## Exit codes

| Code | When |
|---|---|
| 2 | Bad CLI arguments |
| 1 | Startup failure, fail-fast event error, accounting invariant |
| 0 | Continue mode completed (may still have counted event errors) |

## Trust smoke

```bash
cd cli && ./scripts/smoke_trust.sh
```

Uses committed fixtures under `tests/fixtures/` (no SigmaHQ clone).
