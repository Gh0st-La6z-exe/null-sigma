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
| Tier A Criterion reference (post-Phase 2) | ~314 µs |
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

| Area | Pre-Phase 2 | Post-Phase 2 | Next action |
|---|---|---|---|
| `tokenize_pattern` / `pattern_literal` | ~16% self | should drop | Re-profile after cache |
| malloc/free churn | ~20% | should drop | EvalScratch shipped |
| `HashMap` alloc (`id_results`) | medium | should drop | EvalScratch shipped |
| `to_lowercase` / field folding | ~2% | | EventView value cache |
| `wildcard_match_impl` `Vec<char>` | medium | | EventView value cache |
| `apply_transforms` | ~2% | | Pre-expand at load |
| AC scan | <1% | | No action |
| tau-engine structural gap | ~2.3× | | Architecture review |

## Decision (fill after review)

- [ ] EventView value cache next
- [ ] Transform pre-expansion at load
- [ ] Phase 3 ingest (Tier B)
- [ ] Defer; structural gap vs tau-engine needs architecture work
