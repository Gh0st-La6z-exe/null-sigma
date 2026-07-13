# null-sigma-cli

ROADMAP §4 product CLI. Consumes the `null-sigma` library **0.1.3**
(`json` feature) and keeps the core crate free of I/O.

**Packaging:** crate version `0.1.0`, `publish = false` — install with
`cargo install --path cli`. Library remains on crates.io as `null-sigma`
0.1.3; this binary is not published separately yet.

## Status (Week 2 Days 1–3)

**Shipped:** file + stdin JSONL, Week 1 trust/exit contract, streaming
**lean NDJSON** (default) and `--format text` alerts on stdout. CI job
`CLI trust smoke` runs `./scripts/smoke_trust.sh` on every push/PR to `main`
(hermetic fixtures; no SigmaHQ).

**Stdout** = alerts only (buffered `BufWriter`; see §11.10).  
**Stderr** = `rules:` / `tier_b_tax:` (includes `emit=`) / `ingest_errors:` /
`ingest_accounting:`.

The harness binary `null_sigma_run` remains the Tier B bench runner (count-only,
Rayon, competitor deps). This CLI is the installable product path.

## Day 2 output — do not thrash stdout

Full write-up: [`PERFORMANCE.md` §11.10](../PERFORMANCE.md).

**MVP is single-threaded.** Defaults:

1. `stdout.lock()` once → `BufWriter` → `writeln!` / `serde_json::to_writer`
2. **Do not** flush after every alert by default (`--flush-alerts` for live pipes)
3. Flush at end of stream; lean alerts by default (`--include-event` opt-in)
4. `emit=` bucket on `tier_b_tax` for measuring alert I/O

## Build / run

```bash
cd cli
cargo build --release
BIN="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/release/null-sigma-cli"
"$BIN" --rules ../tests/fixtures/rules/minimal \
  ../tests/fixtures/robustness/mixed_valid_invalid.jsonl

# stdin → jq
"$BIN" --rules ../tests/fixtures/rules/minimal - \
  < ../tests/fixtures/robustness/mixed_valid_invalid.jsonl | jq .
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
| `--flush-alerts` | off | Flush stdout after each alert |
| `--threads N` | 1 | Accepted; MVP is single-threaded (§4b for parallel) |
| `[events.jsonl \| -]` | stdin | Input path; `-` or omit → stdin |

## Exit codes

| Code | When |
|---|---|
| 2 | Bad CLI arguments |
| 1 | Startup failure, fail-fast event error, accounting invariant, stdout I/O error |
| 0 | Continue mode completed, or broken pipe on stdout |

## Trust + alert smoke

```bash
cd cli && ./scripts/smoke_trust.sh
```

Uses committed fixtures under `tests/fixtures/` (no SigmaHQ clone).
