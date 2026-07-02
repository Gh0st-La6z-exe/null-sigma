# Changelog

All notable changes to `null-sigma` are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [0.1.0] — 2026-07-02

### Added

- Full Sigma rule evaluation engine: YAML parse → condition AST compile → event match
- 15 Sigma value modifiers: `contains`, `startswith`, `endswith`, `re`, `cidr`, `all`,
  `base64`, `base64offset`, `wide`, `windash`, `gt`, `gte`, `lt`, `lte`, `exists`
- Condition language: `and`, `or`, `not`, parentheses, `1 of selection*`,
  `all of them`, `N of (id1, id2, …)`
- `SigmaEngine` with Aho-Corasick batch prefilter and 24-byte hot/cold struct split
- Cache-friendly logsource prefilter using FNV-1a hashed integer comparisons
- Pre-compiled regex cache (`match_identifier_with_cache`) — compile once, match many
- Zero-allocation `enrich_event_cow` using `Cow<HashMap>` — no clone when event
  already uses Sigma field names
- `evaluate_event` / `evaluate_batch` take `&self` — thread-safe concurrent evaluation
- `FieldMapping` with pre-built reverse map for `O(n_event)` field enrichment
- Fuzz targets: `fuzz_parse_rule`, `fuzz_evaluate_event`
- 166 tests: unit, corpus replay, proptest property-based, concurrent correctness
- 10 Criterion benchmarks including logsource-mismatch and regex isolation paths
- `#![forbid(unsafe_code)]` — compiler-enforced, zero unsafe
- Apache-2.0 license
