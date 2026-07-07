# Flamegraph notes — prof_benign (local only, do not commit)

**Date:**  
**Machine:** Apple M4, macOS  
**Workload:** Tier A `single_benign_event` — 1 102 common SigmaHQ `process_creation` rules, seed-42 benign (`chrome.exe`)  
**API:** `evaluate_event_count`  
**Profile file:** `harness/prof/samply_YYYYMMDD_HHMMSS.json.gz`

## Wall-clock (from prof_benign stderr)

| Metric | Value |
|---|---|
| µs/event (100k loop) | |
| Tier A Criterion reference | ~541 µs |

## Top frames (self time / total time)

Fill from Firefox Profiler after `prof_benign.sh`:

| Rank | Function | Self % | Total % | Notes |
|---|---|---:|---:|---|
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |
| 4 | | | | |
| 5 | | | | |

## Hypothesis checklist

| Area | Expected? | Observed % | Action |
|---|---|---|---|
| `run_ac_scan` | low (~3 µs) | | |
| `HashMap` alloc/insert (`id_results`) | high | | Phase 2 EvalScratch |
| `to_lowercase` / field folding | medium | | EventView value cache |
| `match_identifier_on_view` | medium | | |
| `EventView::from_map` | low-medium | | |
| `enrich_event_cow` | low | | |
| `LogSource::matches` recheck | ? | | |

## Decision (fill after review)

- [ ] Proceed Phase 2 (`EvalScratch`) first
- [ ] Proceed value cache first
- [ ] Both — order:
- [ ] Defer perf; structural gap vs tau-engine

**Do not implement until this table is reviewed.**
