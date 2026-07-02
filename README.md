# null-sigma

A pure-Rust [Sigma](https://sigmahq.io) rule evaluation engine.

Parse YAML rules once, compile them into an optimised internal representation,
then evaluate streams of security events against the full rule set at
**455 000 events/sec × 1 000 rules on a single core** (Apple M4, release).

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

**Measured result:** 1 000 rules, event with wrong logsource category →
**863 ns** total. All 1 000 rules are rejected before a single `CompiledRule`
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
| `single_rule_single_event` | 1.17 µs |
| `100_rules_single_event` | **793 ns** |

The AC automaton scans the event field once regardless of rule count. One
hundred rules sharing overlapping string vocabularies means 100 rules get
prefiltered for less total work than naively evaluating one rule's conditions.

A rule is only AC-prefiltered when *every* field condition in *every* group is
AC-eligible. Rules containing `|re`, `|cidr`, numeric comparisons, `|exists`,
or transform modifiers (`|base64`, `|wide`, `|windash`) bypass the prefilter
gate and always proceed to full evaluation — conservatively correct, never a
false negative.

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

Without the cache, `|re` rules call `regex::Regex::new()` on every event —
a 1–10 µs compilation penalty per pattern per call. With the cache, 100 rules
× 4 patterns = 400 `is_match` calls at ~88 ns each.

**Measured:** `100_regex_rules_single_event` → **34.3 µs**

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
| `enrich_event_cow` (Sigma keys) | **190 ns** | None |
| `enrich_event_cow` (canonical keys) | **751 ns** | One clone |

This single change reduced `single_rule_single_event` from 2.08 µs to
**1.17 µs** — a 43% improvement — because the allocation was on the critical
path of every `evaluate_event` call.

---

## Benchmark summary

All numbers: Apple M4, single core, `cargo bench` (release profile),
Criterion 100-sample statistical measurement.

```
single_rule_single_event          time: [1.1728 µs 1.1744 µs 1.1758 µs]
100_rules_single_event            time: [792.10 ns  793.11 ns  794.16 ns]
1000_rules_single_event           time: [2.1970 µs  2.2004 µs  2.2052 µs]
1000_rules_mixed_field_noise      time: [15.702 µs  15.720 µs  15.739 µs]
100_rules_100_events_batch        time: [86.573 µs  86.756 µs  87.064 µs]
1000_rules_logsource_mismatch     time: [862.65 ns  863.23 ns  863.87 ns]
1000_rules_ac_prefilter_zero_match time: [1.7503 µs 1.7542 µs 1.7614 µs]
100_regex_rules_single_event      time: [34.165 µs  34.346 µs  34.634 µs]
enrich_event_cow_sigma_keys       time: [189.95 ns  190.17 ns  190.50 ns]
enrich_event_cow_canonical_keys   time: [747.35 ns  751.30 ns  758.75 ns]
```

Derived throughput (single core):

| Scenario | Events/sec |
|---|---|
| 1 000 rules, matching event | **455 000** |
| 1 000 rules, wrong logsource | **1 158 000** |
| 1 000 rules, right logsource, no AC hit | **571 000** |
| 100 rules × 100 event batch | **1 152 000** |

Interactive HTML reports are generated by Criterion at
`target/criterion/report/index.html` after running `cargo bench`.

---

## Sigma feature coverage

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

### Value modifiers (15 of 15)

| Category | Modifiers |
|---|---|
| String match | `contains` `startswith` `endswith` |
| Pattern | `re` `cidr` |
| Quantifier | `all` |
| Transform | `base64` `base64offset` `wide` `windash` |
| Numeric | `gt` `gte` `lt` `lte` |
| Existence | `exists` |

Transform modifiers (`base64`, `wide`, `windash`) expand the value set before
matching. `base64offset` generates all three base64 boundary offset variants.
`windash` adds both `-` and `/` flag variants for Windows command obfuscation
detection.

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

running 166 tests
  0  unit (lib)
 10  corpus_tests   — parse known-good and known-bad YAML fixtures
  9  property_tests — proptest: invariants proven on thousands of random inputs
145  sigma_tests    — modifiers, conditions, engine, hardening, concurrency
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

---

## Safety

- **Zero `unsafe` code** — `#![forbid(unsafe_code)]` enforced at crate level
- **No C extensions** — pure Rust, no pyo3, no bindgen, no FFI
- **No panics by design** — malformed YAML returns `ParseError`, invalid
  conditions return `CompileError`, invalid regex patterns log and continue
- **`#![deny(missing_docs)]`** — all public items documented
- **Clippy pedantic** — zero warnings at `-W clippy::pedantic`

---

## Cargo features

No optional features. The dependency surface is intentionally minimal:

| Crate | Role |
|---|---|
| `serde` + `serde_yaml` | YAML → `SigmaRule` |
| `aho-corasick` | SIMD-accelerated multi-pattern batch scan |
| `regex` | `\|re` modifier pattern matching |

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

Copyright 2026 Gh0st-La6z-exe
