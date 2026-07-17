# A4 controlled-hit rule pack

Single Sigma rule used by `harness/scripts/run_a4_firehose_sweep.sh`.

Events are tagged by `gen_dataset --a4-hit-bpm N` with `A4Hit: "1"|"0"`.
Expected matches ≈ `N/10000 * event_count` (exact under the index tagging rule).

Hermetic — committed CI/harness input, not a SigmaHQ corpus slice.

Hayabusa 3.9 requires a `date:` field (and rejects `status: test`); this pack
uses `status: experimental` + `date: 2026/07/15` so Falcon comparisons load.
