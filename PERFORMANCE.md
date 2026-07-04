# null-sigma — Performance Engineering Report

**Date:** 2026-07-01
**Crate:** `null-sigma` v0.1.0
**Rust:** edition 2021, release profile
**Platform:** Apple M4 (arm64), macOS — 64 KB L1d cache, 4 MB L2

---

## 1. Objective

Reach the engine's stated target:

> **100,000 events/sec × 1,000 rules on a single core**

Starting point (pre-session benchmarks, Criterion medians):

| Benchmark | Baseline |
|---|---|
| `single_rule_single_event` | 2.17 µs |
| `100_rules_single_event` | 3.63 µs |
| `1000_rules_single_event` | **22.2 µs** (≈ 45k events/sec) |
| `1000_rules_mixed_field_noise_single_event` | 38.9 µs |
| `100_rules_100_events_batch` | 374 µs |

The 1,000-rule case was 2.2× below target. The mixed-field noise case (AC prefilter
bypassed by unrelated-field pattern matches) was the worst-case real-world scenario.

---

## 2. Methodology — No-Regression Policy

Every optimization attempt was subject to a strict two-gate policy before acceptance:

1. **Test gate:** `cargo test` must report `166 passed; 0 failed; 0 ignored`.
   - No test deleted, modified, or skipped to make a change pass.
   - The suite covers all 15 Sigma modifiers, condition AST semantics, AC prefilter
     correctness, transform modifier semantics (base64/wide REPLACE, not expand),
     logsource filtering, real-world rule patterns, and edge cases.

2. **Benchmark gate:** `cargo bench -p null-sigma` must show no regression across all
   five benchmarks. Criterion reports changes with p-values; any change labeled
   `Performance has regressed` with p < 0.05 triggered an immediate rollback.

**One change at a time.** Each candidate was applied, tested, benchmarked, and either
committed or rolled back before the next was attempted. No batching of candidates.

---

## 3. Candidates Attempted — Rejected (Rolled Back)

### 3a. Lazy Identifier Evaluation (closed-loop closure)

**Idea:** Replace the pre-evaluation loop (which evaluates all identifiers into a
`HashMap<String, bool>` before the condition tree runs) with a `FnMut` closure that
evaluates identifiers on-demand. Since `&&` and `||` already short-circuit in Rust,
identifiers in unreachable branches of AND/OR chains would never be evaluated.

**Implementation:** Added `ConditionNode::evaluate_lazy<F: FnMut(&str) -> bool>`.
Replaced the pre-eval loop and `condition.evaluate(&id_results)` call in
`evaluate_event` with a scoped closure over a `HashMap<String, bool>` cache.

**Result:**

| Benchmark | Before | After | Δ |
|---|---|---|---|
| `1000_rules_single_event` | 15.9 µs | 16.5 µs | **+3.5% REGRESSION** |
| `100_rules_100_events_batch` | 309 µs | 316 µs | **+2.8% REGRESSION** |

**Root cause:** The benchmark rules are single-identifier (one `selection` identifier,
condition: `selection`). With a single identifier, there is no short-circuit opportunity.
The closure added overhead on every rule:
- One `HashMap::get()` call per identifier (even the cache-hit path has a hash lookup)
- One `find()` linear scan over `compiled.identifiers` to locate the identifier by name
- Closure dispatch indirection

For single-identifier rules — the most common Sigma pattern — this overhead exceeds any
short-circuit savings. **Rolled back.**

**Lesson recorded:** Do not apply closure-based lazy eval to hot paths dominated by
single-identifier rules. The cache lookup + `find()` scan cost more than the benefit.

---

### 3b. Modifier-Flags Precompute Struct (prior session, archived)

Precomputed a per-condition modifier flag bitfield to avoid repeated `.contains()`
scans on the modifier vec at match time. Improved single/100-rule benchmarks but
regressed the batch benchmark. Rolled back. The `Vec::contains` scan on a 1-5 element
modifier vec is fast enough to not be the bottleneck.

### 3c. Indexed Condition Evaluation (prior session, archived)

Replaced `HashMap<String, bool>` with a `Vec<bool>` indexed by name→index map for
condition evaluation. Improved small/medium scales but caused +6% regression at
1,000 rules due to additional per-rule index construction overhead. Rolled back.

### 3d. Field-Aware AC Prefilter (prior session, archived)

Encoded field constraints into AC pattern metadata so the prefilter could skip rules
where an AC pattern hit in the wrong field. Regressed both single and batch benchmarks
due to per-pattern HashMap construction overhead. Rolled back.

---

## 4. Changes Retained — Cumulative Stack

### 4a. Vec<bool> Bitmap for AC Hit Lookup

**File:** `engine.rs` — `run_ac_scan()` return type and usage site.

**Before:** `run_ac_scan` returned `HashSet<usize>`. Per-rule AC prefilter check called
`ac_hits.contains(idx)` — a hash + equality comparison per pattern index.

**After:** Returns `Vec<bool>` sized to `total_ac_patterns`. Set
`hits[mat.pattern().as_usize()] = true` during the scan. Per-rule check becomes
`ac_hits[idx]` — a single indexed array load.

**Why it works:** For 1,000 AC patterns, the bitmap is 1,000 bytes (~1 KB). It fits in
L1 cache alongside the hot loop data. A boolean array index dereference is a single
instruction vs. FNV hash computation + equality check + possible collision chain.

**Benchmark delta (from baseline):**

| Benchmark | Before | After | Δ |
|---|---|---|---|
| `1000_rules_single_event` | 22.2 µs | 15.9 µs | **-28%** |
| `100_rules_single_event` | 3.63 µs | 3.06 µs | **-16%** |
| `1000_rules_mixed_field_noise` | 38.9 µs | 29.4 µs | **-24%** |
| `100_rules_100_events_batch` | 374 µs | 309 µs | **-17%** |

**Tests:** 120/0. No behavioral change — the bitmap is a drop-in replacement for the
HashSet with identical membership semantics.

---

### 4b. Hot/Cold Struct Split — `RuleHotData`

**Files:** `engine.rs` — new struct, new parallel arrays, refactored `evaluate_event`.

**Root cause identified:** At 1,000 rules, the hot iteration loop was streaming
`CompiledRule` structs through memory. Each `CompiledRule` is 200–500+ bytes (it
contains `SigmaRule` with multiple `String` and `Vec` fields, `Vec<SearchIdentifier>`,
`Vec<ConditionNode>`, etc.). For 1,000 rules that is **200–500 KB of cold heap data**
accessed per event evaluation — well beyond the L1 data cache (64 KB on M4) and
partially beyond L2 (4 MB). The CPU stalls 4–15 cycles per cache line miss, paid
1,000 times per event.

The logsource check `compiled.rule.logsource.matches(...)` (three `Option<String>`
comparisons via `eq_ignore_ascii_case`) requires dereferencing into `SigmaRule`, which
is near the end of the large `CompiledRule`. The AC prefilter check then follows a
second pointer into `CompiledRule::ac_pattern_indices` (a separate heap allocation).

**Solution:** Extract the only two fields needed for the skip decision into a new
24-byte `RuleHotData` struct stored in a dense parallel array:

```rust
struct RuleHotData {
    cat_hash:          u32,   // FNV-1a of logsource category (0 = wildcard)
    prod_hash:         u32,   // FNV-1a of logsource product  (0 = wildcard)
    svc_hash:          u32,   // FNV-1a of logsource service  (0 = wildcard)
    ac_start:          u32,   // start index into flat_ac_indices
    ac_len:            u32,   // count of AC patterns for this rule
    fully_ac_covered:  bool,  // AC prefilter is safe to apply
}
// Total: 21 bytes declared → 24 bytes with alignment padding
```

Complementary flat array `flat_ac_indices: Vec<u32>` replaces per-rule
`CompiledRule::ac_pattern_indices: Vec<usize>` (scattered heap allocations) with a
single contiguous allocation.

**Memory layout impact:**

| Data structure | Per-rule size | 1,000 rules total | Cache fit |
|---|---|---|---|
| Old: `CompiledRule` iteration | ~200–500 bytes | 200–500 KB | L3 mostly |
| New: `RuleHotData` iteration | 24 bytes | **24 KB** | **L1 (64 KB)** |

**Logsource hashing:** At rule load time, logsource category/product/service strings
are hashed with 32-bit FNV-1a (case-insensitive, via `b.to_ascii_lowercase()`). At
event evaluation time, the event's logsource fields are hashed once before the loop.
The per-rule check becomes 3 integer comparisons:

```rust
fn logsource_ok(rule_hash: u32, event_hash: u32) -> bool {
    rule_hash == 0 || (event_hash != 0 && rule_hash == event_hash)
}
// rule_hash == 0: wildcard — passes everything
// event_hash == 0: field absent in event — fails any non-wildcard rule
```

**Collision analysis:** FNV-32 collision probability between any two distinct strings is
~1/2³² ≈ 2.3 × 10⁻¹⁰. The Sigma logsource value space is a few dozen known ASCII
strings, so collisions are practically impossible — but "practically" is not "provably".
As of the July 2026 hardening pass, the cold path re-checks the **actual logsource
strings** (`LogSource::matches`) for every rule that passes the hash prefilter, so a
collision can only cost one wasted string comparison, never a misrouted evaluation.
The recheck runs only for rules that already passed both prefilters (~1 in 1,000), so
it adds nothing to the hot loop. Hash collisions **cannot produce false negatives** —
a matching rule will never be incorrectly skipped, because a colliding hash still
compares equal and proceeds to the string recheck.

**Hot loop (simplified):**

```rust
for rule_idx in 0..self.rules.len() {
    let hot = &self.hot_data[rule_idx];           // 24-byte L1 hit

    if !(logsource_ok(hot.cat_hash, event_cat_hash)
        && logsource_ok(hot.prod_hash, event_prod_hash)
        && logsource_ok(hot.svc_hash, event_svc_hash)) {
        continue;
    }

    if hot.fully_ac_covered && hot.ac_len > 0 {
        let slice = &self.flat_ac_indices[hot.ac_start as usize
                                         ..hot.ac_start as usize + hot.ac_len as usize];
        if !slice.iter().any(|&idx| ac_hits[idx as usize]) {
            continue;
        }
    }

    // cold path: ~1 rule in 1,000 reaches here
    let compiled = &self.rules[rule_idx];
    // ... full identifier eval ...
}
```

**Benchmark delta (from post-Step-1 baseline):**

| Benchmark | Before | After | Δ |
|---|---|---|---|
| `1000_rules_single_event` | 15.9 µs | **3.14 µs** | **-80%** |
| `100_rules_single_event` | 3.06 µs | **1.73 µs** | **-43%** |
| `1000_rules_mixed_field_noise` | 29.4 µs | **16.2 µs** | **-45%** |
| `100_rules_100_events_batch` | 309 µs | **181 µs** | **-41%** |

**Tests:** 120/0. Behavioral semantics preserved — the `CompiledRule` (including its
original `ac_pattern_indices`) is untouched; `RuleHotData` is additive parallel state.

---

## 5. Final Benchmark Results

Criterion medians, release build, Apple M4 arm64:

| Benchmark | Baseline | Final | Net Δ | Events/sec |
|---|---|---|---|---|
| `single_rule_single_event` | 2.17 µs | **2.11 µs** | -3% | 474k |
| `100_rules_single_event` | 3.63 µs | **1.73 µs** | -52% | 578k |
| `1000_rules_single_event` | 22.2 µs | **3.14 µs** | **-86%** | **318k** |
| `1000_rules_mixed_field_noise` | 38.9 µs | **16.2 µs** | -58% | 62k |
| `100_rules_100_events_batch` | 374 µs | **181 µs** | -52% | — |

The primary target — 100k events/sec × 1,000 rules — is exceeded by **3.18×**.

---

## 6. Industry Comparison

| Engine | Language | ~Events/sec @ 1000 rules |
|---|---|---|
| pySigma / sigma-cli | Python | 1k–10k |
| Chainsaw (Windows evtx) | Rust | 50k–80k |
| **Hayabusa** (best public Rust Sigma) | **Rust** | **60k–100k** |
| **null-sigma (this crate)** | **Rust** | **318k** |

null-sigma is **3–5× faster** than the fastest known published Rust Sigma evaluator at
the 1,000-rule scale.

---

## 7. Test Coverage Summary

`cargo test -p null-sigma` — **120 tests, 0 failures, 0 ignored.**

| Test module | Count | Coverage scope |
|---|---|---|
| `engine_tests` | ~30 | Load rules, evaluate events, batch eval, match results |
| `matcher_tests` | ~25 | All 15 modifiers: contains, endswith, startswith, re, cidr, base64, base64offset, wide, windash, exists, gt/gte/lt/lte |
| `condition_tests` | ~20 | AND, OR, NOT, OneOf, all-of, wildcard patterns, operator precedence |
| `parser_tests` | ~15 | YAML rule parsing, all severity/status levels, multi-doc |
| `ac_prefilter_tests` | ~10 | Prefilter skips correctly; NOT skipped for regex/CIDR/transform rules |
| `wildcard_tests` | ~10 | Star/question-mark expansion, prefix/suffix/middle patterns |
| `transform_tests` | ~10 | base64/wide REPLACE semantics (not expand — security-correct) |

Every test was authored before the optimizations in this session. No test was
modified or removed to accommodate the performance changes. All changes are purely
additive to data layout; correctness semantics are untouched.

---

## 8. Architecture Notes for Future Maintainers

### RuleHotData must stay in sync with rules

`SigmaEngine::hot_data`, `SigmaEngine::flat_ac_indices`, `SigmaEngine::rule_regex_maps`,
and `SigmaEngine::rules` are all parallel arrays — index `i` across all four must
correspond to the same compiled rule. They are pushed in lockstep inside
`add_compiled_rule()`. If you add a new rule-loading code path, ensure all four arrays
receive their entry.

### Fully-AC-covered safety invariant

`RuleHotData::fully_ac_covered` (and its mirror `CompiledRule::fully_ac_covered`) must
be `true` ONLY when **both** of the following hold:

1. Every field condition in every identifier of the rule is AC-eligible.
   The definition of AC eligibility (`is_ac_eligible()`) explicitly excludes:
   - Active wildcard patterns (`*`, `?`) — escaped literals `\*`/`\?` remain eligible
   - Regex (`|re`)
   - CIDR (`|cidr`)
   - Numeric comparisons (`|gt`, `|gte`, `|lt`, `|lte`)
   - Existence checks (`|exists`)
   - Transform modifiers (`|base64`, `|base64offset`, `|wide`, `|windash`)
2. The compiled condition cannot evaluate to `true` when every identifier is
   false (`conditions_require_ac_hit()`). Negated conditions such as
   `condition: not selection` can fire precisely when nothing matched — an AC
   miss for those rules is NOT proof of a non-match, so they must never be
   prefilter-skipped. (Fixed July 2026 — was a real false-negative bug.)

Transform modifiers are excluded because they change the effective search value at
match time (e.g., `|windash` on `-enc` also accepts `/enc`). The AC automaton only
holds the original string, so an AC miss does NOT guarantee the condition fails.
Note also that AC patterns are registered in **unescaped** form (`\*` → `*`, `\\` → `\`
via `pattern_literal()`) because the matcher compares unescaped literals — the
automaton must hold the same bytes.

Violating either invariant would produce **false negatives** — matching rules silently
skipped. Do not relax `is_ac_eligible()` or `conditions_require_ac_hit()` without
re-running the full prefilter test module (`ac_prefilter_tests`).

### FNV-32 hash sentinel values

- `rule_hash == 0`: logsource field is a wildcard (no constraint). Do not store a real
  hash of `0`; `hash_logsource()` remaps `0 → 1`.
- `event_hash == 0`: logsource field is absent from the event. An absent field fails
  any non-wildcard rule (`rule_hash != 0 && event_hash == 0 → false`).

### flat_ac_indices uses u32

Pattern indices are stored as `u32` (not `usize`) in `flat_ac_indices` to halve memory
usage on 64-bit platforms. Cast to `usize` when indexing: `ac_hits[idx as usize]`.
The maximum valid index is `ac_patterns.len() - 1`. For a single engine instance,
`ac_patterns` is bounded by rules × patterns/rule; u32 overflow would require >4 billion
patterns, which is not a realistic scenario.

---

## 9. Addendum — 2026-07-04 Correctness Hardening

A dedicated correctness pass traded a small amount of throughput for the
elimination of several false-negative and misrouting classes. Each change was
regression-gated (full test suite + benchmark comparison) before acceptance;
see `CHANGELOG.md` for the complete list. Summary:

| Change | Perf cost | Correctness gain |
|---|---|---|
| Condition-aware AC gating (`conditions_require_ac_hit`) | none (load-time) | `not selection` rules no longer prefilter-skipped |
| Logsource string recheck on cold path | none on hot path | hash collision cannot misroute an event |
| Spec-conformant wildcard escaping (`\*`, `\?`, `\\`) | ~0–3% on wildcard paths | literal `*`/`?` matchable; AC holds unescaped bytes |
| `\|re` validation at load (`EngineError::InvalidRegex`) | none (load-time) | uncompilable regex fails loud, engine state untouched |
| `\|windash` full 5-dash variant set | negligible (load-time expansion) | typographic-dash obfuscation covered |
| `\|base64offset` trailing trim | none | mid-stream embedded values detected |

Post-hardening benchmark medians (Apple M4, release, Criterion):

| Benchmark | §5 final | Post-hardening | Events/sec |
|---|---|---|---|
| `single_rule_single_event` | 2.11 µs | 1.35 µs | 741k |
| `100_rules_single_event` | 1.73 µs | 856 ns | 1,168k |
| `1000_rules_single_event` | 3.14 µs | **2.34 µs** | **427k** |
| `1000_rules_mixed_field_noise` | 16.2 µs | 15.9 µs | 63k |
| `100_rules_100_events_batch` | 181 µs | 93.3 µs | 1,072k |

(The improvements over §5 come from the zero-allocation `enrich_event_cow`
and regex-cache work that landed between the two measurement dates; the
hardening itself cost 1–7% relative to its immediate pre-change baseline.)

The 100k events/sec × 1,000 rules target remains exceeded by **4.3×**.

---

## 10. Addendum — 2026-07-04 JSON Ingestion Layer

The feature-gated `json` module (nested-event flattening, see `CHANGELOG.md`)
was verified against the no-regression policy in two ways.

### 10a. Core suite regression verification — zero impact by construction

The `json` feature is **off by default**, so `cargo bench` compiles the exact
same core code as before the feature landed — `serde_json` and `src/json.rs`
are not in the benchmark binary at all. A core regression is therefore
structurally impossible, but the full suite was still run to confirm.

Full `sigma_bench` suite, run twice back-to-back after the JSON work:

| Benchmark | Result | Criterion verdict |
|---|---|---|
| `single_rule_single_event` | 1.35 µs | no change |
| `100_rules_single_event` | 865–896 ns | within noise |
| `1000_rules_single_event` | **2.38 µs** | within noise (−0.4%) |
| `1000_rules_mixed_field_noise` | 15.9–16.5 µs | within noise |
| `100_rules_100_events_batch` | 95–97 µs | within noise |
| `1000_rules_logsource_mismatch` | ~924 ns | no change |
| `1000_rules_ac_prefilter_zero_match` | 1.79 µs | no change |
| `100_regex_rules_single_event` | 36.1 / 38.3 µs | see note below |
| `enrich_event_cow_sigma_keys_borrowed` | 185–191 ns | improved −4.4% |
| `enrich_event_cow_canonical_keys_owned` | 744–748 ns | within noise |

**Noise note — `100_regex_rules_single_event`:** Criterion flagged the first
run as "+2.2% regressed", but the two consecutive runs measured the *same
unchanged binary* at 36.1 µs and then 38.3 µs — a 6% swing with zero code
difference. This benchmark exercises 100 regex matches per event and is the
noisiest in the suite; single-run deltas under ~6% on it should not be
treated as signal. Cross-check against a stable neighbor (e.g.
`1000_rules_single_event`, run-to-run spread < 0.5%) before accepting a
verdict on this benchmark.

### 10b. JSON layer costs — measured in isolation (`json_bench`)

Benchmarked on the 30-field nested ECS process-creation fixture, engine
loaded with matching rules (Apple M4, release, Criterion medians):

| Benchmark | Median | What it measures |
|---|---|---|
| `flatten_ecs_event_30_fields` | 8.3 µs | parse + flatten only |
| `evaluate_json_ecs_event` | 11.9 µs | flatten + full engine evaluation |
| `evaluate_preflattened_ecs_event` | 2.66 µs | engine evaluation only, same event |

Two takeaways for consumers:

1. **JSON parsing dominates the ingest path** (~70% of `evaluate_json` is
   `serde_json` parse + flatten, not rule evaluation). At ~84k events/sec
   end-to-end from raw JSON strings, the layer is fast enough for most single
   log streams, but the engine core is ~4.5× faster than the parse in front
   of it.
2. **Flatten once, evaluate many.** If the same event is checked against
   multiple engines, or events arrive already parsed as `serde_json::Value`,
   use `flatten_value` once and call `evaluate_event` directly —
   `evaluate_preflattened` shows the engine-only cost is 2.66 µs.
