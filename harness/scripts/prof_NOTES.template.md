# Flamegraph notes — prof_benign (local only, do not commit)

**Date:**  
**Machine:**  
**Workload:** Tier A `single_benign_event` — 1,110 common SigmaHQ `process_creation` rules, seed-42 benign (`chrome.exe`)  
**API:** `evaluate_event_count`  
**Profile file:** `harness/prof/samply_YYYYMMDD_HHMMSS.json.gz`

## Wall-clock (from prof_benign stderr)

| Metric | Value |
|---|---|
| µs/event (1,000 loop) | |
| Step 2 baseline (`RuleBitSet` candidate dispatch) | ~950 µs |
| Phase 5 reference (Bloom + Canonical slots) | ~1,166 µs |
| Post-AC Inverted Dispatch reference | ~3,070 µs |

## Top frames (self time / total time)

Fill from Firefox Profiler after `prof_benign.sh`:

| Rank | Function | Self % | Total % | Notes |
|---|---|---:|---:|---|
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |
| 4 | | | | |
| 5 | | | | |

## Optimization checklist

| Area | Status | Next action |
|---|---|---|
| Field-presence bitmask rejection | Shipped | 1-cycle bitwise rejection |
| Discriminator basename indexing | Shipped | Inverted image/parent_image dispatch |
| Candidate bitset iteration | Shipped | `RuleBitSet` with TZCNT/BLSR |
| Rolling bigram Bloom filter | Shipped | 1-cycle `contains` reject |
| Decision tape / flat interpreter | In Progress | Step 3: eliminate AST recursion |
| EventView buffer pooling | In Progress | Step 3: zero allocations per event |
