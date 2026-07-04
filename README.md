# null-sigma

[![CI](https://github.com/Gh0st-La6z-exe/null-sigma/actions/workflows/ci.yml/badge.svg)](https://github.com/Gh0st-La6z-exe/null-sigma/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/null-sigma.svg)](https://crates.io/crates/null-sigma)
[![docs.rs](https://docs.rs/null-sigma/badge.svg)](https://docs.rs/null-sigma)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A pure-Rust [Sigma](https://sigmahq.io) rule evaluation engine.

Parse YAML rules once, compile them into an optimised internal representation,
then evaluate streams of security events against the full rule set at
**427 000 events/sec × 1 000 rules on a single core** (Apple M4, release).

```toml
[dependencies]
null-sigma = "0.1"
```

---

## Quick start

```rust
use null_sigma::SigmaEngine;
use std::collections::HashMap;

let yaml = r#"
title: Detect Encoded PowerShell
logsource: {}
detection:
    sel:
        CommandLine|contains: '-EncodedCommand'
    condition: sel
"#;

let mut engine = SigmaEngine::new();
engine.load_rule(yaml).unwrap();

let mut event = HashMap::new();
event.insert("CommandLine".to_string(), "powershell -EncodedCommand SQBFAFgA".to_string());

let matches = engine.evaluate_event(&event);   // &self — safe to call concurrently
assert_eq!(matches[0].rule_title, "Detect Encoded PowerShell");
```

```text
$ cargo run --example detect_powershell

Loaded rule: d7da0a5c-0001-0000-0000-000000000001
Engine has 1 rule(s)

[ALERT] Matched 1 rule(s)
  - Suspicious Encoded PowerShell  [high]  score=0.70
    tags: attack.execution, attack.t1059.001

Batch (2 events):
  event[0]: 1 match(es)
  event[1]: 0 match(es)
```

---

## Why it's fast

The engine achieves its throughput through four compounding optimisations.
Each one is independently measurable in the benchmark suite.

### 1 — Hot/cold struct split

The most expensive operation in a multi-rule engine is the per-rule loop: for
each loaded rule, decide as cheaply as possible whether the current event can
possibly match.

The naive approach is to store everything about a rule in one struct and
iterate it. At 200–500 bytes per rule, 1 000 rules = 200–500 KB of data
streamed per event — a guaranteed L2/L3 cache miss on every iteration.

Instead, the engine separates each rule into two regions:

**`RuleHotData`** — 24 bytes, touched on every event for every rule:

```rust
struct RuleHotData {
    cat_hash:         u32,   //  4 bytes — FNV-1a hash of logsource.category
    prod_hash:        u32,   //  4 bytes — FNV-1a hash of logsource.product
    svc_hash:         u32,   //  4 bytes — FNV-1a hash of logsource.service
    ac_start:         u32,   //  4 bytes — index into flat AC pattern slice
    ac_len:           u32,   //  4 bytes — number of AC patterns for this rule
    fully_ac_covered: bool,  //  1 byte  — safe-skip gate
                             //  3 bytes padding → total 24 bytes
}
```

**`CompiledRule`** — 200–500 bytes, dereferenced only when a rule passes
*both* prefilters (typically 1 of 1 000):

```rust
struct CompiledRule {
    rule:               SigmaRule,          // parsed YAML fields
    identifiers:        Vec<SearchIdentifier>,
    conditions:         Vec<ConditionNode>, // compiled boolean AST
    ac_pattern_indices: Vec<usize>,
    has_regex:          bool,
}
```

At 24 bytes/rule, 1 000 rules occupy 24 KB — fitting inside L1 cache (64 KB
on Apple M4). The entire prefilter scan touches only this array; the cold
`CompiledRule` heap allocations are never dereferenced for skipped rules.

The logsource fields are pre-hashed with 32-bit FNV-1a at rule load time so
the per-rule check is three integer comparisons, not three string comparisons:

```rust
#[inline(always)]
fn logsource_ok(rule_hash: u32, event_hash: u32) -> bool {
    rule_hash == 0 || (event_hash != 0 && rule_hash == event_hash)
    //           ↑                    ↑
    //      wildcard rule        field absent in event
}
```

0 is reserved as the "no constraint" sentinel. Non-zero event hashes are
guaranteed by remapping the FNV collision `h == 0 → 1`.

The hash comparison is a prefilter, not the final word: rules that pass it
are re-checked against the **actual logsource strings** on the cold path
(`LogSource::matches`) before evaluation. A 32-bit hash collision therefore
cannot route an event to the wrong rule — the recheck costs nothing on the
hot path because it only runs for rules that already passed both prefilters.

**Measured result:** 1 000 rules, event with wrong logsource category →
**912 ns** total. All 1 000 rules are rejected before a single `CompiledRule`
is touched.

---

### 2 — Aho-Corasick batch prefilter

Most Sigma rules contain one or more `|contains`, `|startswith`, or
`|endswith` string conditions. If the event field doesn't contain any of those
strings the rule cannot match — no need to evaluate the full condition AST.

At rule load time, every AC-eligible string pattern from every rule is
extracted into a single flat `Vec<String>`. A single
[`aho-corasick`](https://docs.rs/aho-corasick) automaton is compiled across
all of them. At evaluation time:

```
run_ac_scan(event)
  for each event field value:
    for each match in ac_automaton.find_iter(value):
      hits[match.pattern_id] = true   // O(n) over text, not O(n × rules)
```

The result is a dense boolean bitmap indexed by pattern ID. The hot loop then
tests a contiguous slice of that bitmap per rule — no pointer indirection, no
HashMap lookup:

```rust
let start = hot.ac_start as usize;
let end   = start + hot.ac_len as usize;
if !flat_ac_indices[start..end]
    .iter()
    .any(|&idx| ac_hits[idx as usize])
{
    continue;   // rule cannot match — skip cold eval
}
```

**Why 100 rules is faster than 1 rule:**

| Benchmark | Median |
|---|---|
| `single_rule_single_event` | 1.35 µs |
| `100_rules_single_event` | **856 ns** |

The AC automaton scans the event field once regardless of rule count. One
hundred rules sharing overlapping string vocabularies means 100 rules get
prefiltered for less total work than naively evaluating one rule's conditions.

A rule is only AC-prefiltered when two safety conditions hold:

1. **Every** field condition in **every** identifier group is AC-eligible.
   Rules containing `|re`, `|cidr`, numeric comparisons, `|exists`, or
   transform modifiers (`|base64`, `|wide`, `|windash`) bypass the prefilter
   gate and always proceed to full evaluation.
2. The compiled condition **cannot fire with all identifiers false**. This
   protects negated conditions such as `condition: not selection` — an event
   with zero AC hits can be exactly the event that should match, so those
   rules are never skipped on an AC miss.

Both checks are computed once at rule load time; violating either would
produce false negatives, so they are enforced by dedicated regression tests
(`ac_prefilter_tests`).

---

### 3 — Pre-compiled regex cache

Rules using `|re` (regex) conditions have their patterns compiled once at
`load_rule` time into a per-rule `HashMap<String, Regex>`. At evaluation time,
`match_identifier_with_cache` looks up the pre-compiled object directly:

```rust
match regex_cache.get(&pattern) {
    Some(re) => re.is_match(field_value),   // O(1) lookup + fast match
    None     => regex_matches(&pattern, field_value), // fallback compile
}
```

Compilation is also where validation happens: a `|re` pattern that fails to
compile **rejects the whole rule at load time** with
`EngineError::InvalidRegex`. An uncompilable pattern can never match, so
silently accepting it would disable the detection without any operator
signal.

Without the cache, `|re` rules call `regex::Regex::new()` on every event —
a 1–10 µs compilation penalty per pattern per call. With the cache, 100 rules
× 4 patterns = 400 `is_match` calls at ~88 ns each.

**Measured:** `100_regex_rules_single_event` → **35.9 µs**

---

### 4 — Zero-allocation field enrichment

The engine supports events in both Sigma field naming (`CommandLine`) and
application canonical naming (`command_line`). Rather than always cloning the event
and scanning all ~120 mapping entries to add aliases, `enrich_event_cow`
returns a `Cow<'_, HashMap<String, String>>`:

- **`Borrowed`** — event already uses Sigma names → no allocation
- **`Owned`** — application canonical names present → clone once, insert only the needed aliases

The reverse lookup is pre-built at `FieldMapping::new()` time so enrichment
iterates O(n_event) entries rather than O(n_mappings):

```rust
for (key, value) in event {
    if let Some(sigma_name) = self.reverse.get(&key.to_lowercase()) {
        if !event.contains_key(sigma_name.as_str()) {
            aliases.push((sigma_name.clone(), value.clone()));
        }
    }
}
if aliases.is_empty() {
    return Cow::Borrowed(event);   // hot path — zero allocation
}
```

**Measured isolation:**

| Path | Median | Allocation |
|---|---|---|
| `enrich_event_cow` (Sigma keys) | **193 ns** | None |
| `enrich_event_cow` (canonical keys) | **739 ns** | One clone |

This single change reduced `single_rule_single_event` from 2.08 µs to
**1.25 µs** — a 40% improvement — because the allocation was on the critical
path of every `evaluate_event` call.

---

## Benchmark summary

![null-sigma benchmark chart: per-event latency stays hundreds of times below naive linear scaling as rule count grows, and single-core throughput by scenario](assets/benchmarks.svg)

The left panel is the headline property: adding rules costs almost nothing.
Per-event latency at 1 000 rules is **576× below** what naive
per-rule evaluation would cost, because the prefilters reject nearly every
rule before its condition tree is ever touched. The chart is generated from
the Criterion medians below by `scripts/gen_benchmark_chart.py`.

All numbers: Apple M4, single core, `cargo bench` (release profile),
Criterion 100-sample statistical measurement.

```
single_rule_single_event          time: [1.3463 µs 1.3489 µs 1.3517 µs]
100_rules_single_event            time: [855.53 ns  856.34 ns  857.20 ns]
1000_rules_single_event           time: [2.3385 µs  2.3405 µs  2.3428 µs]
1000_rules_mixed_field_noise      time: [15.916 µs  15.934 µs  15.958 µs]
100_rules_100_events_batch        time: [93.203 µs  93.298 µs  93.399 µs]
1000_rules_logsource_mismatch     time: [909.78 ns  912.15 ns  915.89 ns]
1000_rules_ac_prefilter_zero_match time: [1.7766 µs 1.7881 µs 1.8083 µs]
100_regex_rules_single_event      time: [35.783 µs  35.877 µs  35.975 µs]
enrich_event_cow_sigma_keys       time: [192.36 ns  193.29 ns  195.25 ns]
enrich_event_cow_canonical_keys   time: [732.02 ns  738.83 ns  752.37 ns]
```

Derived throughput (single core):

| Scenario | Events/sec |
|---|---|
| 1 000 rules, matching event | **427 000** |
| 1 000 rules, wrong logsource | **1 096 000** |
| 1 000 rules, right logsource, no AC hit | **559 000** |
| 100 rules × 100 event batch | **1 072 000** |

These figures include the correctness hardening added in July 2026 (logsource
string recheck, condition-aware AC gating, spec-conformant wildcard escaping)
— a 1–7% cost versus the pre-hardening numbers, traded for the elimination of
several false-negative classes.

Interactive HTML reports are generated by Criterion at
`target/criterion/report/index.html` after running `cargo bench`.

---

## Sigma feature coverage

### SigmaHQ corpus compatibility

Validated against the full official [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)
rule corpus (July 2026 snapshot):

| Rule set | Files | Loaded |
|---|---|---|
| `rules` + `rules-emerging-threats` + `rules-threat-hunting` + `rules-compliance` | 3 745 | **3 745 (100%)** |
| `rules-placeholder` (`\|expand` — requires external placeholder catalogs by design) | 17 | 0 (documented exclusion) |

All 3 745 rules bulk-load into a single engine in **~270 ms** (one AC rebuild).
Reproduce with:

```bash
git clone --depth 1 https://github.com/SigmaHQ/sigma.git corpus/sigmahq
cargo run --release --example corpus_report -- corpus/sigmahq/rules
```

### Condition language

The condition compiler implements a full recursive-descent parser with correct
operator precedence (`NOT > AND > OR`):

```
(selection_process and selection_cmdline) and not filter
1 of selection*
all of them
3 of (sel_a, sel_b, sel_c)
```

The AST is compiled once per rule at load time into a `ConditionNode` tree
evaluated at O(n_identifiers) per event.

### Value modifiers (19)

| Category | Modifiers |
|---|---|
| String match | `contains` `startswith` `endswith` |
| Pattern | `re` (+ flag sub-modifiers `re\|i` `re\|m` `re\|s`) `cidr` |
| Quantifier | `all` |
| Transform | `base64` `base64offset` `wide` `windash` |
| Numeric | `gt` `gte` `lt` `lte` |
| Existence | `exists` |
| Field reference | `fieldref` (compare against another event field, Sigma v2) |

`fieldref` interprets the condition value as a field *name* and compares the
two event fields' values (`ParentImage|fieldref: Image` fires when a process
executes itself); it composes with `contains`/`startswith`/`endswith`.
Regex flag sub-modifiers must follow `re` (`field|re|i:`) — a bare `|i` is a
parse error. Note: `|re` is case-insensitive by default in this engine, so
`re|i` is a no-op confirmation; `re|m` (multi-line anchors) and `re|s`
(dot-matches-newline) change compilation.

Transform modifiers (`base64`, `wide`, `windash`) expand the value set before
matching:

- `base64offset` generates all three base64 boundary offset variants and trims
  the unstable characters from **both** ends, so a value embedded mid-stream
  in a longer base64 blob is still detected (not just values at the end of
  the encoded data).
- `windash` expands to the full Sigma variant set: `-`, `/`, `–` (en dash),
  `—` (em dash), and `―` (horizontal bar) — catching commands copy-pasted
  from documents with typographic dashes. Expansion is bidirectional: a rule
  written with any variant matches all of them.
- `wide` re-encodes the value as UTF-16LE.

### Condition forms

```yaml
# Single string
condition: selection

# Boolean expression
condition: selection and not filter

# Quantifier
condition: 1 of selection*
condition: all of them
condition: 3 of (sel_a, sel_b, sel_c)

# Multiple independent conditions (any fires the rule)
condition:
  - selection_a
  - selection_b and filter
```

### Field matching semantics

- **Case-insensitive** field names and string values (Sigma spec)
- **AND** within a field condition group
- **OR** across groups within an identifier
- **OR** across values within a condition (unless `|all`)
- **Keyword search** (empty field name) matches against all event values
- **Wildcards** in values: `*` (any sequence) and `?` (single char)
- **Escaping** per the Sigma spec: `\*` and `\?` are literal characters,
  `\\` is a single backslash, and a lone backslash before a normal character
  passes through unchanged — Windows paths like `\cmd.exe` need no escaping.
  Escaped literals stay eligible for the Aho-Corasick prefilter (the
  automaton stores the unescaped bytes).

---

## Type system

```
SigmaRule
├── LogSource     { category, product, service }
├── Detection
│   ├── ConditionExpr   Single(String) | Multiple(Vec<String>)
│   └── identifiers     HashMap<String, serde_yaml::Value>
│       └── SearchIdentifier
│           └── Vec<FieldConditionGroup>      ← OR across groups
│               └── Vec<FieldCondition>       ← AND within group
│                   ├── field:     String
│                   ├── values:    Vec<SigmaValue>
│                   └── modifiers: Vec<ValueModifier>
└── metadata      title, id, status, level, tags, author, …
```

`SigmaValue` is typed: `String | Integer(i64) | Float(f64) | Boolean | Null`.
Numeric comparisons use `i64` integer arithmetic when both sides parse as
integers, avoiding the 2^53 precision boundary of `f64` for large counters and
timestamps.

---

## Thread safety

After rule loading, `evaluate_event` and `evaluate_batch` both take `&self`.
The engine can be wrapped in `Arc` and evaluated from N threads concurrently
with no locking:

```rust
use std::sync::Arc;

let engine = Arc::new(engine_with_rules_loaded);

let handles: Vec<_> = events
    .chunks(chunk_size)
    .map(|chunk| {
        let eng = Arc::clone(&engine);
        std::thread::spawn(move || eng.evaluate_batch(chunk))
    })
    .collect();
```

The `rebuild_ac` call (Aho-Corasick automaton compilation) happens eagerly
inside `load_rule` / `load_rules` — never lazily inside `evaluate_event`.

---

## Testing

```
cargo test

running 196 tests
  0  unit (lib)
 10  corpus_tests   — parse known-good and known-bad YAML fixtures
 10  property_tests — proptest: invariants proven on 10,000 random inputs each
174  sigma_tests    — modifiers, conditions, engine, hardening, concurrency
  2  doc tests
```

Selected property invariants proven by proptest:

- **No panics** — arbitrary printable input to `parse_rule` never panics
- **Determinism** — same event always produces same result
- **Soundness** — absent required field never fires the rule
- **Monotonicity** — extra event fields never suppress a match
- **Wildcard logsource** — rules with empty logsource match any event source

Selected hardening tests:

- Null bytes, RTL override characters, and zero-width spaces in field values
- 10 000-character field values
- 1 000 fields in a single event
- Unicode field names
- Duplicate rule loads (both loaded, no silent deduplication)
- Brute-forced FNV-1a logsource hash collision — proven not to misroute events
- Negated conditions (`not selection`) — proven never skipped by the AC prefilter
- Invalid `|re` pattern — rejected at load, engine state left untouched

---

## Safety

- **Zero `unsafe` code** — `#![forbid(unsafe_code)]` enforced at crate level
- **No C extensions** — pure Rust, no pyo3, no bindgen, no FFI
- **No panics by design** — malformed YAML returns `ParseError`, invalid
  conditions return `CompileError`, and invalid `|re` patterns return
  `EngineError::InvalidRegex` at load time (fail loud, never fail silent)
- **No silent detection loss** — every load failure leaves the engine state
  untouched; `load_rules` collects per-rule errors so bulk ingestion reports
  exactly which rules were rejected and why
- **`#![deny(missing_docs)]`** — all public items documented
- **Clippy pedantic** — zero warnings at `-W clippy::pedantic`

---

## Cargo features

No optional features. The dependency surface is intentionally minimal:

| Crate | Role |
|---|---|
| `serde` + `serde_norway` | YAML → `SigmaRule` (maintained `serde_yaml` successor) |
| `aho-corasick` | SIMD-accelerated multi-pattern batch scan |
| `regex` | `\|re` modifier pattern matching |

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

Copyright 2026 Gh0st-La6z-exe
