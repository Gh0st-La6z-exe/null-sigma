# null-sigma-cli

ROADMAP §4 product CLI. Consumes the `null-sigma` library **0.1.3**
(`json` feature) and keeps the core crate free of I/O.

**Packaging:** crate version `0.1.0`, `publish = false` — install with
`cargo install --path cli`. Library remains on crates.io as `null-sigma`
0.1.3; this binary is not published separately yet.

## Status (Days 1–3 + §4b MT slice)

**Shipped:** file + stdin JSONL, Week 1 trust/exit contract, lean NDJSON /
`--format text`, sequenced **block-chunk MT** (`--threads N|0`) with ordered
alerts + trust bags. CI: `CLI trust smoke` runs `smoke_trust.sh` and
`smoke_parallel.sh`.

**Stdout** = alerts only (ordered chunk `write_all`; see §11.10 / §11.11).  
**Stderr** = `rules:` / `tier_b_tax:` (includes `emit=`) / `ingest_errors:` /
`ingest_accounting:`.

The harness binary `null_sigma_run` remains the Tier B bench runner (count-only).
This CLI is the installable product path — **no product MT bake-off numbers
until Linux hyperfine of this binary**.

## Pipeline (do not scramble order)

1. Sequential chunker (buffered `Read`, grow / max-line)
2. Rayon workers → local `Vec<u8>` alerts + `ChunkTrustMetrics`
3. Main ordered sink → merge trust → `stdout.write_all`

## Build / run

```bash
cd cli
cargo build --release
BIN="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/release/null-sigma-cli"
"$BIN" --rules ../tests/fixtures/rules/minimal --threads 0 \
  ../tests/fixtures/robustness/mixed_valid_invalid.jsonl
```

Install (local path; crates.io later):

```bash
cargo install --path cli
```

## Lean NDJSON schema (default)

```json
{"rule_id":"...","rule_title":"...","rule_level":"high","tags":[],"score":0.7,"matched_identifiers":["selection"]}
```

With `--include-event`, adds `"event":{...}` (full flattened map).

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--rules <dir>` | required | Sigma YAML directory |
| `--on-error continue\|fail-fast` | `continue` | Event-level error policy |
| `--max-line-bytes N` | 8 MiB | Reject oversize lines before parse |
| `--max-error-samples N` | 0 | Cap `ingest_error_sample:` lines |
| `--format ndjson\|text` | `ndjson` | Alert stdout format |
| `--include-event` | off | Embed full flattened event in NDJSON |
| `--flush-alerts` | off | Flush stdout after each released chunk |
| `--threads N` | 1 | Eval workers (`0` = all cores); alerts stay ordered |
| `[events.jsonl \| -]` | stdin | Input path; `-` or omit → stdin |

## Exit codes

| Code | When |
|---|---|
| 2 | Bad CLI arguments |
| 1 | Startup failure, fail-fast event error, accounting invariant, stdout I/O error |
| 0 | Continue mode completed, or broken pipe on stdout |

## Trust + parallel smoke

```bash
cd cli && ./scripts/smoke_trust.sh && ./scripts/smoke_parallel.sh
```

Uses committed fixtures under `tests/fixtures/` (no SigmaHQ clone).
