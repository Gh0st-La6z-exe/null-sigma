# Robustness JSONL fixtures

Committed bad-input corpus for `null_sigma_run` trust checks.
Run via `harness/scripts/smoke_robustness.sh`.

| Fixture | Lines | Expected (continue mode) |
|---|---|---|
| `mixed_valid_invalid.jsonl` | 5 | total=5, ok=3, failed=2, json_parse=1, flatten_not_object=1 |
| `deep_nested.jsonl` | 2 | total=2, ok=1, failed=1, flatten_depth=1 |
| `field_explosion.jsonl` | 2 | total=2, ok=1, failed=1, flatten_fields=1 |
| `missing_fields_ok.jsonl` | 3 | total=3, ok=3, failed=0, all errors=0 |

Guards use core defaults: `max_depth=64`, `max_fields=10000`.

`smoke_robustness.sh` also asserts `ingest_errors` stderr is identical for
`--threads 1` and `--threads 0` on `mixed_valid_invalid.jsonl` (ingest is
single-threaded; eval parallelism must not affect error accounting).
`smoke_determinism.sh` asserts identical `ingest_errors` / `ingest_accounting`
lines across two consecutive runs.

With `--max-error-samples 1` on the mixed fixture, the first sample is
`line=3 kind=json_parse` (bad JSON on physical line 3).
