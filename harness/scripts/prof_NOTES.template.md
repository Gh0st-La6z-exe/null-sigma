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
| Tier A Criterion reference (post–value cache) | ~309 µs |
| Tier A Criterion reference (Phase 2) | ~314 µs |
| Tier A Criterion reference (Phase 1 baseline) | ~541 µs |

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

| Area | Pre–value-cache | Post–value-cache | Next action |
|---|---|---|---|
| `tokenize_pattern` / `pattern_literal` | dropped (Phase 2) | | — |
| malloc/free (`EvalScratch`) | dropped (Phase 2) | | — |
| `to_lowercase` on event fields | present | should drop | value cache shipped |
| `wildcard_match_impl` `Vec<char>` | per-call | should reuse cache | value cache shipped |
| `apply_transforms` | medium | | Pre-expand at load |
| AC scan | <1% | | No action |
| tau-engine structural gap | ~2.3× | | Architecture / Phase 3 |

## Decision (fill after review)

- [ ] Transform pre-expansion at load
- [ ] Phase 3 ingest (Tier B)
- [ ] Defer; structural gap vs tau-engine needs architecture work
