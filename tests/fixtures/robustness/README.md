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
