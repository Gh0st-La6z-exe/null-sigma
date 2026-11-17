# null-sigma — High-Performance Pure-Rust Sigma Engine

[![CI](https://github.com/Gh0st-La6z-exe/null-sigma/actions/workflows/ci.yml/badge.svg)](https://github.com/Gh0st-La6z-exe/null-sigma/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/null-sigma.svg)](https://crates.io/crates/null-sigma)
[![docs.rs](https://docs.rs/null-sigma/badge.svg)](https://docs.rs/null-sigma)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Safety: Forbid Unsafe](https://img.shields.io/badge/unsafe-forbidden-success.svg)](src/lib.rs)

A high-performance, high-assurance pure-Rust [Sigma](https://sigmahq.io) rule evaluation engine.

Parse YAML detection rules once, compile them into an optimized internal representation, and evaluate high-throughput streams of security telemetry against thousands of rules concurrently.

```toml
[dependencies]
null-sigma = "0.1"
```

---

## Key Highlights

- **12.5× Faster than `sigma-rust`:** Evaluates 1,110 official SigmaHQ `process_creation` rules in **961.50 µs** per event under Criterion 99% bootstrap confidence intervals, and **950.58 µs** in tight-loop ingest.
- **100% SigmaHQ Specification Coverage:** Loads and compiles **1,193 / 1,193 rules (100.0%)** without conversion loss or unsupported modifier rejections (compared to `tau-engine`'s 93.0% / 1,110 rules).
- **Empirically Proven Parity:** **0.0000% disagreement** across **11,100,000 evaluations** (10,000 events × 1,110 rules) against `sigma-rust` (4,132 vs 4,132 detections).
- **Zero `unsafe` Code:** Enforced at crate root via `#![forbid(unsafe_code)]` with zero C extensions, FFI, or external system dependencies.
- **Cache-Conscious 2-Tier Architecture:** Employs a 64-bit canonical field-presence bitmask, process basename discriminators, dense `RuleBitSet` candidate dispatch using hardware intrinsics (`TZCNT`/`BLSR`), and rolling bigram Bloom filters.

---

## Quick Start

### Library Usage

```rust
use null_sigma::SigmaEngine;
use std::collections::HashMap;

let yaml = r#"
title: Suspicious PowerShell Encoded Command
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: '-EncodedCommand'
        Image|endswith: '\powershell.exe'
    condition: selection
"#;

let mut engine = SigmaEngine::new();
engine.load_rule(yaml).expect("valid rule");

let mut event = HashMap::new();
event.insert("CommandLine".to_string(), "powershell.exe -EncodedCommand SQBFAFgA".to_string());
event.insert("Image".to_string(), r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string());
event.insert("event_category".to_string(), "process_creation".to_string());
event.insert("event_product".to_string(), "windows".to_string());

// Evaluate concurrently across threads with zero locking (&self)
let matches = engine.evaluate_event(&event);
assert_eq!(matches.len(), 1);
assert_eq!(matches[0].rule_title, "Suspicious PowerShell Encoded Command");
```

### JSON Telemetry Evaluation (`json` feature)

Enable the optional `json` feature in `Cargo.toml` to evaluate nested JSON records (ECS, Sysmon, CloudTrail) directly:

```toml
[dependencies]
null-sigma = { version = "0.1", features = ["json"] }
```

```rust
use null_sigma::SigmaEngine;

let mut engine = SigmaEngine::new();
engine.load_rule(yaml).unwrap();

let json_event = r#"{
    "process": {
        "command_line": "powershell.exe -EncodedCommand SQBFAFgA",
        "name": "powershell.exe"
    }
}"#;

let matches = engine.evaluate_json(json_event).expect("valid JSON event");
assert_eq!(matches.len(), 1);
```

### Product CLI (`null-sigma-cli`)

For production log processing, the repository includes `null-sigma-cli`:

```bash
# Install the product CLI
cargo install --path cli

# Stream NDJSON events into alert output
null-sigma-cli --rules ./rules < events.jsonl
# or format as human-readable text
null-sigma-cli --rules ./rules events.jsonl --format text
```

---

## Architecture: Why It's Fast

Rather than scanning all event fields against all rules with a monolithic string automaton (which suffers from whole-event scanning and field bleed), `null-sigma` routes events through an inverted dispatch matrix designed for CPU cache efficiency.

![null-sigma Tier A benchmark chart: head-to-head matcher latency on real SigmaHQ rules and optimization descent](assets/benchmarks.svg)

### 1. 2-Tier Inverted Dispatch Matrix

1. **Tier 1 — Canonical Field-Presence Bitmask (`u64`):**
   - 64 canonical Sigma fields are mapped to dense unique bit positions (`0..63`) in [`src/field_mask.rs`](src/field_mask.rs).
   - At rule compile time, boolean AST derivation computes `RuleHotData::required_fields_mask` — a bitmask of fields logically required for the rule to fire.
   - At event evaluation time, `EventView` sets bits for present fields in a single pass.
   - Non-matching rules are rejected in **1 bitwise instruction**:
     ```rust
     if (hot.required_fields_mask & event_fields_mask) != hot.required_fields_mask {
         continue; // 1-cycle bitwise rejection
     }
     ```

2. **Tier 2 — Primary & Secondary Basename Discriminators with Dense `RuleBitSet`:**
   - In process telemetry (`process_creation`), 85%+ of rules inspect binary names (`Image`, `OriginalFileName`, `ParentImage`).
   - Binary basenames are indexed into inverted buckets (`image_discriminator_index` and `parent_image_discriminator_index`).
   - Unconstrained rules are stored in a dense bitset (`unconstrained_mask`).
   - Candidate rules are accumulated into a thread-local `scratch.candidate_mask: RuleBitSet` (152 bytes for 1,200 rules, fitting within 2.4 L1 cachelines):
     ```rust
     scratch.candidate_mask.copy_from(&self.unconstrained_mask);
     if let Some(rules) = self.image_discriminator_index.get(&base) {
         for &r in rules { scratch.candidate_mask.set(r as usize); }
     }
     if let Some(rules) = self.parent_image_discriminator_index.get(&parent_base) {
         for &r in rules { scratch.candidate_mask.set(r as usize); }
     }
     for rule_idx in scratch.candidate_mask.iter_set_bits() {
         // Direct set-bit iteration with TZCNT and BLSR hardware intrinsics
     }
     ```
   - Because bit-setting is idempotent, rules appearing in multiple discriminator buckets are never evaluated more than once.

### 2. Compact 24-Byte `RuleHotData` Cacheline Split

Each rule is divided into hot prefilter metadata and cold AST storage:
- **`RuleHotData` (24 bytes):** Contains `required_fields_mask: u64`, 32-bit FNV-1a hashes of logsource category, product, and service, plus `rule_index: u32`. At 24 bytes, 1,000 rules occupy only 24 KB, fitting comfortably within CPU L1 data cache.
- **`CompiledRule` (200–500 bytes):** Holds condition trees, identifier mappings, and parsed strings. Dereferenced **only** when candidate rules pass both prefilters (typically < 1% of rules).

### 3. Sub-64 Rolling Bigram Bloom Filter

For substring search (`contains`), string scans across hundreds of rule patterns can be costly. `null-sigma` implements a 64-bit rolling bigram Bloom filter in [`src/bloom.rs`](src/bloom.rs):
- At rule compilation time, patterns compute a 64-bit bigram mask.
- At runtime, `EventView` lazily computes the event field's 64-bit bigram mask.
- Substring non-matches are rejected in **1 CPU cycle** before byte scans:
  ```rust
  if (field_bloom & pattern_bloom) != pattern_bloom {
      return false; // guaranteed non-match, 1 cycle
  }
  ```

### 4. Zero-Allocation Execution & Buffer Reuse

- **Thread-Local `EvalScratch`:** Reusable scratchpad avoiding per-event heap allocations. Identifier evaluation uses a flat boolean buffer with tri-state lazy evaluation flags.
- **Single-Condition Fast Path:** Rules with a single identifier condition bypass identifier state management and closure dispatch via `CompiledCondition::Single`.
- **Pre-Tokenized `ValueMatchCache`:** String patterns are folded and pre-tokenized into literals or wildcard slices at compile time, eliminating runtime string parsing on the hot path.
- **Fold-Once `EventView`:** Field values are folded once per event on first reference and shared across all rules and `|fieldref` lookups.

---

## Head-to-Head Benchmarks

The benchmark suite in [`harness/`](harness/) compares `null-sigma`, `tau-engine` (the matching core of Chainsaw), and `sigma-rust` on the official SigmaHQ `windows/process_creation` rule corpus.

```bash
# Clone the official SigmaHQ rules corpus
git clone --depth 1 https://github.com/SigmaHQ/sigma.git corpus/sigmahq

# Run the 11.1M-evaluation differential cross-check
cd harness && cargo run --release --bin cross_check -- ../corpus/sigmahq/rules/windows/process_creation 10000
```

### Differential Correctness & Coverage (11,100,000 Evaluations)

Evaluated across 10,000 generated events against all 1,110 common rules:

| Engine | Rules Loaded | Corpus Coverage | Disagreements vs `null-sigma` | Rule Load Time |
|---|:---:|:---:|:---:|:---:|
| **`null-sigma`** | **1,193 / 1,193** | **100.0%** | **0 (0.0000%)** [4,132 vs 4,132 hits] | **153.08 ms** |
| `tau-engine` (Chainsaw) | 1,110 / 1,193 | 93.0% (rejects 83 rules) | 53 (0.0005%)* | 660.32 ms |
| `sigma-rust` | 1,192 / 1,193 | 99.9% (rejects 1 rule) | **0 (0.0000%)** [4,132 vs 4,132 hits] | 398.15 ms |

*\*Note: The 53 cells vs `tau-engine` are isolated to Chainsaw's YAML converter treating an empty list differently on `Suspicious SYSTEM User Process Creation`.*

### Tier A Matcher Latency (`single_benign_event`)

Extended Criterion benchmarks (250 samples, 5s warmup, 30s measurement window, 99% bootstrap confidence interval, $p < 0.01$):

| Engine | Rules Evaluated | Mean Latency | 99% Confidence Interval | Relative Speedup |
|---|:---:|:---:|:---:|:---:|
| **`null-sigma` (common)** | **1,110** | **961.50 µs** | **[961.50 µs .. 997.23 µs]** | **12.5× faster** than `sigma-rust` |
| **`null-sigma` (full corpus)** | **1,193** | **1,109.20 µs** | **[1,109.20 µs .. 1,158.70 µs]** | Full corpus coverage |
| `tau-engine` (Chainsaw) | 1,110 | 492.09 µs | [492.09 µs .. 508.87 µs] | 24.4× faster than `sigma-rust` |
| `sigma-rust` | 1,110 | 12,016.00 µs | [12,016.00 µs .. 12,259.00 µs] | 1.0× (baseline) |

*Tight-Loop Ingest Profiling (`prof_benign`, 1,000 iterations):*
- Initial post-AC Inverted Dispatch baseline: **3,070 µs / event**
- Post-Bloom filter & Dense Canonical Slots: **1,166.72 µs / event**
- Post-`RuleBitSet` unified candidate dispatch: **950.58 µs / event** (**-216.14 µs drop, -18.5%**)

### Tier B End-to-End CLI Performance (100,000 Events)

Hyperfine measurement across 100,000 JSONL events comparing end-to-end ingest, parsing, evaluation, and reporting:

![Tier B wall-clock chart: null-sigma beats Hayabusa on 100k events](assets/tier_b.svg)

| Tool | Wall Time | Events / sec |
|---|:---:|:---:|
| **`null-sigma-runner` (default threads, Rayon)** | **7.26 s** | **13,780** |
| `null-sigma-runner` (4 threads) | 11.50 s | 8,690 |
| `hayabusa` (default threads) | 15.53 s | 6,440 |
| `chainsaw hunt` | 28.37 s | 3,530 |
| **`null-sigma-runner` (1 thread)** | **36.62 s** | **2,730** |
| `hayabusa` (1 thread) | 54.40 s | 1,840 |

---

## Sigma Feature Coverage

### Value Modifiers (19 Supported)

| Category | Modifiers | Description |
|---|---|---|
| **String Match** | `contains`, `startswith`, `endswith` | Case-insensitive substring, prefix, and suffix matching |
| **Pattern** | `re` (with flags `re\|i`, `re\|m`, `re\|s`), `cidr` | Pre-compiled regex and IP subnet CIDR matching |
| **Quantifier** | `all` | Requires all condition values to match |
| **Transform** | `base64`, `base64offset`, `wide`, `windash` | Multi-offset base64, UTF-16LE, and typographic dash expansion |
| **Numeric** | `gt`, `gte`, `lt`, `lte` | Integer comparisons (with `i64` precision) |
| **Existence** | `exists` | Field presence validation |
| **Field Reference** | `fieldref` | Compares one event field directly against another (Sigma v2) |

### Condition Expressions

The condition compiler implements recursive-descent parsing with standard boolean operator precedence (`NOT > AND > OR`):
- **Simple conditions:** `condition: selection`
- **Boolean expressions:** `condition: (selection_process and selection_cmdline) and not filter`
- **Quantifiers:** `1 of selection*`, `all of them`, `3 of (sel_a, sel_b, sel_c)`
- **Multi-condition rules:** List of independent conditions where any match triggers an alert

### Field Matching & Escaping Semantics

- **Case-Insensitive:** Field names and string values conform to the Sigma specification.
- **Keyword Search:** Empty field names match against all values in the event.
- **Wildcard Syntax:** `*` matches any character sequence; `?` matches a single character.
- **Spec-Conformant Escaping:** `\*` and `\?` are treated as literal characters; `\\` represents a single backslash; lone backslashes before alphanumeric characters remain unescaped (e.g. Windows paths like `\cmd.exe` require no extra escaping). Escaped literals remain eligible for Bloom filtering and literal fast paths.

---

## Thread Safety & Concurrency

After compiling rules, `SigmaEngine::evaluate_event` and `SigmaEngine::evaluate_batch` take immutable references (`&self`). An engine instance can be wrapped in `std::sync::Arc` and queried from multiple threads simultaneously with zero lock contention:

```rust
use std::sync::Arc;
use std::thread;

let engine = Arc::new(engine);

let handles: Vec<_> = events_chunks
    .into_iter()
    .map(|chunk| {
        let eng = Arc::clone(&engine);
        thread::spawn(move || {
            for event in &chunk {
                let _ = eng.evaluate_event(event);
            }
        })
    })
    .collect();

for h in handles {
    h.join().unwrap();
}
```

---

## Testing & Quality Assurance

Every release and commit is validated against an extensive test harness:

```
$ cargo test

running 239 tests:
  25  unit tests (lib)
  10  corpus replay tests (known-good and known-bad Sigma rules)
  10  property-based tests (proptest)
 192  integration tests (modifiers, conditions, engine, hardening)
   2  doc tests
```

### Proptest Property Invariants

- **Crash Freedom:** Arbitrary printable and malformed inputs to `parse_rule` and `load_rule` never panic.
- **Determinism:** The same event evaluated against the engine always yields identical match results.
- **Soundness:** Events missing required fields are proven never to fire rules.
- **Monotonicity:** Adding extra unrelated fields to an event never suppresses a valid detection.
- **Wildcard Logsource:** Rules with empty logsource constraints match any event source.

### Robustness & Hardening

- Tested against null bytes, RTL override characters, and zero-width spaces in values.
- Validated on 10,000-character field values and 1,000-field events without memory explosion.
- Brute-forced FNV-1a logsource hash collisions proven not to misroute events.
- Negated conditions (`not selection`) proven never to be skipped by field-presence or discriminator prefilters.

---

## Safety Guarantees

- **Zero `unsafe` Code:** `#![forbid(unsafe_code)]` enforced at the crate root.
- **No C / FFI Dependencies:** 100% pure Rust for predictable cross-compilation and memory safety.
- **Fail Loud, Never Fail Silent:** Malformed YAML returns `ParseError`, invalid conditions return `CompileError`, and invalid regex patterns return `EngineError::InvalidRegex` at load time.
- **Zero Warnings:** Enforced across root, tests, harness, and CLI with `cargo clippy --all-targets -- -D warnings`.
- **`#![deny(missing_docs)]`:** All public APIs and types are fully documented.

---

## Cargo Features

| Feature | Default | Description |
|---|:---:|---|
| `json` | Off | Nested JSON event ingestion (`evaluate_json`, `flatten_str`) via `serde_json` |

Minimal dependencies:

| Crate | Purpose |
|---|---|
| `serde` + `serde_norway` | YAML deserialization into `SigmaRule` |
| `regex` | Regular expression evaluation for `\|re` modifiers |
| `serde_json` | Optional flattening layer for nested JSON events (`json` feature only) |

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

Copyright 2026 Gh0st-La6z-exe
