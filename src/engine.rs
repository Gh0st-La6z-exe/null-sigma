// =============================================================================
// Sigma Rule Engine — Multi-Rule Evaluation Engine
// =============================================================================
// The engine is the top-level orchestrator. It holds compiled rules, manages
// Aho-Corasick pattern indexes for batch string matching, and evaluates events
// against all loaded rules in a single pass.
//
// PERFORMANCE ARCHITECTURE:
//   1. LogSource pre-filtering: Skip rules whose logsource doesn't match the event
//   2. Aho-Corasick batch: One AC automaton scans an event field, finding ALL
//      matching patterns from ALL rules simultaneously — O(n + m) where n is
//      the text length and m is the number of matches (not rules!)
//   3. Only rules with AC pattern hits (or no string patterns) proceed to full eval
//   4. Full eval: condition AST → identifier matching → boolean result
//
// TARGET: 100K events/sec × 1000 rules on a single core.
// =============================================================================

use crate::condition::{compile_condition, CompileError, ConditionNode};
use crate::event_view::EventView;
use crate::fieldmap::FieldMapping;
use crate::fold::{fold_key, fold_value};
use crate::matcher::{match_identifier_on_view, match_identifier_with_cache_on_view};
use crate::parser::{parse_rule, parse_rules, ParseError};
use crate::types::{
    ConditionExpr, EvalResult, FieldCondition, RuleMatch, SearchIdentifier, SigmaRule,
    ValueModifier,
};

use aho_corasick::AhoCorasick;
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// Compiled Rule — Fully parsed, validated, and ready for evaluation
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct CompiledRule {
    /// The original parsed Sigma rule.
    rule: SigmaRule,
    /// Parsed search identifiers from the detection block.
    identifiers: Vec<SearchIdentifier>,
    /// Compiled condition AST(s) — one per condition expression.
    conditions: Vec<ConditionNode>,
    /// Indexes into the global pattern list for this rule's AC patterns.
    ac_pattern_indices: Vec<usize>,
    /// True if any identifier in this rule contains a `|re` (regex) condition.
    /// When false the hot-path uses `match_identifier` (no cache lookup overhead).
    /// When true `evaluate_event` looks up `SigmaEngine::rule_regex_maps[rule_idx]`.
    has_regex: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Engine Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors that can occur when loading or compiling a Sigma rule into the engine.
#[derive(Debug)]
pub enum EngineError {
    /// The YAML failed to parse or did not satisfy the Sigma schema.
    Parse(ParseError),
    /// The condition expression compiled to an invalid AST.
    Compile(CompileError),
    /// A `|re` pattern in the rule is not a valid regular expression.
    /// Rejected at load time — a silently non-matching detection is worse
    /// than a loud load failure.
    InvalidRegex {
        /// The offending `|re` pattern as written in the rule.
        pattern: String,
        /// The regex compiler's error message.
        error: String,
    },
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EngineError::Parse(e) => write!(f, "Parse error: {e}"),
            EngineError::Compile(e) => write!(f, "Compile error: {e}"),
            EngineError::InvalidRegex { pattern, error } => {
                write!(f, "Invalid |re pattern '{pattern}': {error}")
            }
        }
    }
}

impl std::error::Error for EngineError {}

impl From<ParseError> for EngineError {
    fn from(e: ParseError) -> Self {
        EngineError::Parse(e)
    }
}

impl From<CompileError> for EngineError {
    fn from(e: CompileError) -> Self {
        EngineError::Compile(e)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RuleHotData — Cache-friendly prefilter fields
// ─────────────────────────────────────────────────────────────────────────────

/// Compact 24-byte per-rule fields used exclusively by the hot iteration loop.
///
/// Only these fields are touched for rules that are skipped by the logsource
/// filter or the AC prefilter. The full `CompiledRule` (200-500+ bytes) is
/// only dereferenced when a rule passes both checks — typically 1 of 1000.
///
/// At 24 bytes/rule, 1000 rules = 24 KB — fits in L1 cache (64 KB on Apple M4).
/// Iterating `CompiledRule` directly would stream 200-500+ KB per event,
/// guaranteeing constant L2/L3 pressure and 5-15 cycle memory latency per rule.
#[derive(Debug, Clone)]
struct RuleHotData {
    /// FNV-1a hash of the required logsource category (lowercased). 0 = wildcard.
    cat_hash: u32,
    /// FNV-1a hash of the required logsource product (lowercased). 0 = wildcard.
    prod_hash: u32,
    /// FNV-1a hash of the required logsource service (lowercased). 0 = wildcard.
    svc_hash: u32,
    /// Start index into `SigmaEngine::flat_ac_indices` for this rule's patterns.
    ac_start: u32,
    /// Count of AC pattern indices for this rule.
    ac_len: u32,
    /// Mirror of `CompiledRule::fully_ac_covered` — safe-skip gate.
    fully_ac_covered: bool,
}

/// 32-bit FNV-1a hash for logsource comparison, case-insensitive.
/// The empty string hashes to the FNV offset basis (non-zero), so 0 is safe
/// to use as the "no constraint" sentinel for wildcard rules.
// PERF: `inline(always)` is intentional — this ~4-instruction hash runs in the
// innermost prefilter loop (one call per rule per event). Benchmarks show it
// shaves ~8% off the hot path vs letting the compiler decide.
#[allow(clippy::inline_always)]
#[inline(always)]
fn hash_logsource(s: &str) -> u32 {
    let mut h: u32 = 2_166_136_261;
    for b in s.bytes() {
        h ^= u32::from(b.to_ascii_lowercase());
        h = h.wrapping_mul(16_777_619);
    }
    // Reserve 0 for "no constraint"; real values are remapped away from it.
    if h == 0 {
        1
    } else {
        h
    }
}

/// Check a single logsource field in the hot loop.
/// `rule_hash == 0` means wildcard (always passes).
/// `event_hash == 0` means the field is absent in the event (fails non-wildcards).
// PERF: `inline(always)` is intentional — this single-expression function is
// called three times per rule per event in the prefilter tight loop.
#[allow(clippy::inline_always)]
#[inline(always)]
fn logsource_ok(rule_hash: u32, event_hash: u32) -> bool {
    rule_hash == 0 || (event_hash != 0 && rule_hash == event_hash)
}

// ─────────────────────────────────────────────────────────────────────────────
// SigmaEngine — The main evaluation engine
// ─────────────────────────────────────────────────────────────────────────────

/// High-performance Sigma rule evaluation engine.
///
/// Load rules once (YAML parsing + compilation), then evaluate events at speed.
/// Thread-safe for read operations after rule loading is complete.
///
/// # Example
/// ```
/// use null_sigma::SigmaEngine;
/// use std::collections::HashMap;
///
/// let yaml = r#"
/// title: Detect Encoded PowerShell
/// logsource: {}
/// detection:
///     sel:
///         CommandLine|contains: '-EncodedCommand'
///     condition: sel
/// "#;
///
/// let mut engine = SigmaEngine::new();
/// engine.load_rule(yaml).unwrap();
///
/// let mut event = HashMap::new();
/// event.insert("CommandLine".to_string(), "powershell -EncodedCommand abc".to_string());
///
/// let matches = engine.evaluate_event(&event);
/// assert_eq!(matches.len(), 1);
/// assert_eq!(matches[0].rule_title, "Detect Encoded PowerShell");
/// ```
pub struct SigmaEngine {
    /// All compiled rules.
    rules: Vec<CompiledRule>,
    /// Field name mapping (Sigma → application canonical names).
    field_mapping: FieldMapping,
    /// All string patterns across all rules for Aho-Corasick, deduplicated:
    /// rules sharing a literal share one pattern slot and one hit bit.
    /// (Duplicate patterns would break the scan — see `run_ac_scan`.)
    ac_patterns: Vec<String>,
    /// Load-time lookup: lowercased literal → index into `ac_patterns`.
    /// Never touched on the evaluation path. Safe because the engine has no
    /// rule-removal API — a pattern slot, once created, is never invalidated.
    ac_pattern_lookup: HashMap<String, usize>,
    /// Length in bytes of the longest AC pattern — bounds the rescan window
    /// in `run_ac_scan` (see the soundness argument there).
    ac_max_pattern_len: usize,
    /// Compiled Aho-Corasick automaton. Rebuilt after rule changes.
    ac_automaton: Option<AhoCorasick>,
    /// Whether the AC automaton needs rebuilding.
    ac_dirty: bool,
    /// Pre-compiled regex maps, one per rule, indexed by rule position.
    /// Kept separate from `CompiledRule` so the hot struct stays small
    /// (no `HashMap` inline on every rule — cache-friendly at 1000+ rules).
    /// Only accessed when `CompiledRule::has_regex` is true.
    rule_regex_maps: Vec<HashMap<String, regex::Regex>>,
    /// Cache-friendly 24-byte hot data for the prefilter loop. Parallel to `rules`.
    /// 1000 rules × 24 bytes = 24 KB — fits in L1 cache (64 KB on Apple M4).
    hot_data: Vec<RuleHotData>,
    /// Flat contiguous array of AC pattern indices for all rules.
    /// Rule i's slice is `flat_ac_indices[hot_data[i].ac_start .. ac_start + ac_len]`.
    /// Avoids pointer-chasing into `CompiledRule::ac_pattern_indices` (scattered heap allocs)
    /// during the hot loop.
    flat_ac_indices: Vec<u32>,
}

impl SigmaEngine {
    /// Create a new empty Sigma engine with default field mappings.
    /// Covers Sysmon, Windows Security, Linux auditd, and generic fields.
    #[must_use]
    pub fn new() -> Self {
        SigmaEngine {
            rules: Vec::new(),
            field_mapping: FieldMapping::new(),
            ac_patterns: Vec::new(),
            ac_pattern_lookup: HashMap::new(),
            ac_max_pattern_len: 0,
            ac_automaton: None,
            ac_dirty: false,
            rule_regex_maps: Vec::new(),
            hot_data: Vec::new(),
            flat_ac_indices: Vec::new(),
        }
    }

    /// Create a new engine with a custom field mapping.
    #[must_use]
    pub fn with_field_mapping(field_mapping: FieldMapping) -> Self {
        SigmaEngine {
            rules: Vec::new(),
            field_mapping,
            ac_patterns: Vec::new(),
            ac_pattern_lookup: HashMap::new(),
            ac_max_pattern_len: 0,
            ac_automaton: None,
            ac_dirty: false,
            rule_regex_maps: Vec::new(),
            hot_data: Vec::new(),
            flat_ac_indices: Vec::new(),
        }
    }

    /// Load a single Sigma rule from YAML. Returns the rule ID on success.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Parse`] if `yaml` is not valid YAML or does not
    /// conform to the Sigma schema.
    ///
    /// Returns [`EngineError::Compile`] if the rule's condition expression
    /// cannot be compiled into a valid AST.
    pub fn load_rule(&mut self, yaml: &str) -> Result<String, EngineError> {
        let (rule, identifiers) = parse_rule(yaml)?;
        let rule_id = rule.id.clone();
        self.add_compiled_rule(rule, identifiers)?;
        self.rebuild_ac();
        Ok(rule_id)
    }

    /// Load multiple rules from a multi-document YAML string (separated by ---).
    /// Returns (successes, errors) so callers can report failures without
    /// aborting the entire load.
    ///
    /// # Errors
    ///
    /// Parse and compile failures do not abort loading — they are collected in
    /// the returned error vector. Each failed rule produces an [`EngineError`]
    /// carrying either [`EngineError::Parse`] or [`EngineError::Compile`].
    #[must_use = "contains the error list — unhandled load failures mean rules are silently absent"]
    pub fn load_rules(&mut self, yaml: &str) -> (Vec<String>, Vec<EngineError>) {
        let mut successes = Vec::new();
        let mut errors = Vec::new();

        for result in parse_rules(yaml) {
            match result {
                Ok((rule, identifiers)) => {
                    let id = rule.id.clone();
                    match self.add_compiled_rule(rule, identifiers) {
                        Ok(()) => successes.push(id),
                        Err(e) => errors.push(e),
                    }
                }
                Err(e) => errors.push(EngineError::Parse(e)),
            }
        }

        // Rebuild once after all rules are loaded rather than once per rule.
        self.rebuild_ac();

        (successes, errors)
    }

    /// Get the number of loaded rules.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Get loaded rule IDs and titles.
    #[must_use]
    pub fn rule_list(&self) -> Vec<(String, String)> {
        self.rules
            .iter()
            .map(|r| (r.rule.id.clone(), r.rule.title.clone()))
            .collect()
    }

    // ─── Rule Compilation ───────────────────────────────────────────────

    fn add_compiled_rule(
        &mut self,
        rule: SigmaRule,
        mut identifiers: Vec<SearchIdentifier>,
    ) -> Result<(), EngineError> {
        finalize_identifiers(&mut identifiers);

        // Compile each condition expression into an AST
        let conditions: Vec<ConditionNode> = match &rule.detection.condition {
            ConditionExpr::Single(c) => {
                vec![compile_condition(c, &identifiers)?]
            }
            ConditionExpr::Multiple(cs) => {
                let mut compiled = Vec::new();
                for c in cs {
                    compiled.push(compile_condition(c, &identifiers)?);
                }
                compiled
            }
        };

        // Determine if any identifier uses |re (regex) so evaluate_event knows
        // whether to look up the side-table regex map for this rule.
        let has_regex = identifiers.iter().any(|ident| {
            ident.groups.iter().any(|group| {
                group
                    .conditions
                    .iter()
                    .any(|cond| cond.modifiers.contains(&ValueModifier::Regex))
            })
        });

        // Compile all |re patterns BEFORE mutating any engine state: an invalid
        // pattern must reject the whole rule and leave the engine untouched
        // (no orphan AC patterns, no rule_count change).
        let regex_map = if has_regex {
            collect_compiled_regexes(&identifiers)?
        } else {
            HashMap::new()
        };

        // ── Per-identifier AC gating ────────────────────────────────────
        // An identifier is "AC-gated" when EVERY one of its OR-groups
        // contains at least one AC-eligible condition whose values all
        // produce non-empty literals. If such an identifier is true, some
        // group is fully true, so its eligible condition matched, so one of
        // its literals occurs in some event value — i.e. the AC scan MUST
        // report a hit. Contrapositive: zero hits across the rule's gated
        // patterns proves every gated identifier false.
        //
        // (The old all-or-nothing rule — every condition of every
        // identifier AC-eligible — disabled the prefilter for nearly the
        // whole SigmaHQ corpus: one wildcard or regex anywhere in a filter
        // identifier forced the rule onto the cold path. Found by the
        // head-to-head harness, 2026-07.)
        let mut ac_indices: Vec<usize> = Vec::new();
        let mut gated_flags: Vec<bool> = Vec::with_capacity(identifiers.len());
        for identifier in &identifiers {
            let mut identifier_gated = !identifier.groups.is_empty();
            let mut ident_patterns: Vec<usize> = Vec::new();
            for group in &identifier.groups {
                let mut group_has_eligible = false;
                for cond in &group.conditions {
                    if !is_ac_eligible(cond) {
                        continue;
                    }
                    // Register the UNESCAPED literals (`\\` → `\`, `\*` →
                    // `*`): the matcher compares unescaped forms, so the
                    // automaton must hold the same bytes.
                    let mut literals: Vec<String> = Vec::with_capacity(cond.values.len());
                    for val in &cond.values {
                        let s = val.as_str_lossy();
                        let literal = crate::matcher::pattern_literal(&s)
                            .expect("is_ac_eligible guarantees no active wildcards");
                        let s_lower = literal.to_lowercase();
                        if !s_lower.is_empty() {
                            literals.push(s_lower);
                        }
                    }
                    // Gating demands every value yield a non-empty literal:
                    // a multi-value OR containing an empty literal can be
                    // true with zero automaton hits.
                    if !literals.is_empty() && literals.len() == cond.values.len() {
                        group_has_eligible = true;
                        for lit in literals {
                            ident_patterns.push(self.intern_ac_pattern(lit));
                        }
                    }
                }
                if !group_has_eligible {
                    identifier_gated = false;
                }
            }
            if identifier_gated {
                ac_indices.extend(ident_patterns);
            }
            gated_flags.push(identifier_gated);
        }
        ac_indices.sort_unstable();
        ac_indices.dedup();

        // The rule is prefilter-safe when the condition cannot fire while
        // every gated identifier is false (checked over all assignments of
        // the ungated identifiers). This protects negated conditions such
        // as `condition: not sel`: an event with no AC hits can be exactly
        // the event that should match.
        let fully_ac_covered = !ac_indices.is_empty()
            && conditions_require_gated_hit(&conditions, &identifiers, &gated_flags);

        self.rules.push(CompiledRule {
            rule,
            identifiers,
            conditions,
            ac_pattern_indices: ac_indices,
            has_regex,
        });
        // Push regex map, hot data in lockstep: index i ↔ rules[i].
        self.rule_regex_maps.push(regex_map);

        // Build hot data entry: pre-hash logsource fields + flatten AC indices.
        // rule has already been moved into CompiledRule above; access via rules.last().
        let last_rule = &self.rules.last().unwrap().rule;
        let cat_hash = last_rule
            .logsource
            .category
            .as_deref()
            .map_or(0, hash_logsource);
        let prod_hash = last_rule
            .logsource
            .product
            .as_deref()
            .map_or(0, hash_logsource);
        let svc_hash = last_rule
            .logsource
            .service
            .as_deref()
            .map_or(0, hash_logsource);

        let ac_start = u32::try_from(self.flat_ac_indices.len())
            .expect("flat_ac_indices exceeded u32::MAX (> 4 billion AC patterns)");
        let last_compiled = self.rules.last().unwrap();
        for &idx in &last_compiled.ac_pattern_indices {
            self.flat_ac_indices
                .push(u32::try_from(idx).expect("AC pattern index exceeded u32::MAX"));
        }
        let ac_len = u32::try_from(last_compiled.ac_pattern_indices.len())
            .expect("ac_pattern_indices exceeded u32::MAX");

        self.hot_data.push(RuleHotData {
            cat_hash,
            prod_hash,
            svc_hash,
            ac_start,
            ac_len,
            fully_ac_covered,
        });

        self.ac_dirty = true;
        Ok(())
    }

    /// Intern an AC pattern: rules sharing a literal share one pattern slot
    /// (and one hit bit). Duplicate slots would break the prefilter — the
    /// scan reports one pattern id per occurrence.
    fn intern_ac_pattern(&mut self, pattern: String) -> usize {
        if let Some(&idx) = self.ac_pattern_lookup.get(&pattern) {
            return idx;
        }
        let idx = self.ac_patterns.len();
        self.ac_max_pattern_len = self.ac_max_pattern_len.max(pattern.len());
        self.ac_patterns.push(pattern.clone());
        self.ac_pattern_lookup.insert(pattern, idx);
        idx
    }

    /// Rebuild the Aho-Corasick automaton after rule changes.
    fn rebuild_ac(&mut self) {
        if !self.ac_dirty {
            return;
        }

        if self.ac_patterns.is_empty() {
            self.ac_automaton = None;
        } else {
            // Build case-insensitive AC automaton. The kind is left to the
            // library's auto choice: forcing DFA measured ~1% faster on the
            // overlapping scan but its memory grows with pattern count, and
            // a failed build here would silently disable the prefilter.
            self.ac_automaton = AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(&self.ac_patterns)
                .ok();
        }

        self.ac_dirty = false;
    }

    // ─── Event Evaluation ───────────────────────────────────────────────

    /// Count matching rules without building [`RuleMatch`] payloads.
    ///
    /// Same semantics as [`Self::evaluate_event`], but skips result metadata
    /// allocation — use for throughput-sensitive paths that only need a hit count.
    pub fn evaluate_event_count(&self, event: &HashMap<String, String>) -> usize {
        self.evaluate_event_inner(event, false, &mut |_, _, _| {})
    }

    /// Evaluate a single event against all loaded rules.
    ///
    /// The event is a flat key-value map representing the `event_data` fields.
    /// Field names are automatically translated via the configured `FieldMapping`.
    ///
    /// Returns all matching rules with scores, matched conditions, and tags.
    ///
    /// # Concurrency
    ///
    /// Takes `&self` — safe to call concurrently from multiple threads once
    /// rule loading is complete.  Use [`load_rule`](Self::load_rule) /
    /// [`load_rules`](Self::load_rules) (both `&mut self`) to add rules; they
    /// build the Aho-Corasick automaton eagerly so evaluation is always ready.
    #[must_use = "returns all threat detections — discarding them silently suppresses security alerts"]
    pub fn evaluate_event(&self, event: &HashMap<String, String>) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        self.evaluate_event_inner(event, true, &mut |compiled, id_results, matched_conditions| {
            let matched_identifiers: Vec<String> = id_results
                .iter()
                .filter_map(|(name, &matched)| if matched { Some(name.clone()) } else { None })
                .collect();

            matches.push(RuleMatch {
                rule_id: compiled.rule.id.clone(),
                rule_title: compiled.rule.title.clone(),
                rule_level: compiled.rule.level,
                matched_conditions: matched_conditions.to_vec(),
                matched_identifiers,
                tags: compiled.rule.tags.clone(),
                score: compiled.rule.level.to_score(),
            });
        });
        matches
    }

    /// Shared single-event evaluation loop.
    ///
    /// When `collect_details` is false, skips `matched_conditions` accumulation
    /// and never invokes `on_match`.
    #[allow(clippy::type_complexity)]
    fn evaluate_event_inner(
        &self,
        event: &HashMap<String, String>,
        collect_details: bool,
        on_match: &mut dyn FnMut(&CompiledRule, &HashMap<String, bool>, &[usize]),
    ) -> usize {
        // Enrich the event with Sigma-canonical field names so rules can
        // match regardless of naming convention.
        // `enrich_event_cow` returns `Borrowed` (zero allocation) when the
        // event already uses Sigma field names, `Owned` only when application
        // canonical names are present and aliases need to be added.
        let enriched = self.field_mapping.enrich_event_cow(event);
        let mut view = EventView::from_map(enriched.as_ref());

        // Resolve event logsource strings once; hash them for O(1) integer
        // comparison in the hot loop. hash == 0 means "field absent in event"
        // — fails any non-wildcard rule check.
        let event_category = enriched
            .get("event_category")
            .or_else(|| enriched.get("category"))
            .map(String::as_str);
        let event_product = enriched
            .get("event_product")
            .or_else(|| enriched.get("product"))
            .map(String::as_str);
        let event_service = enriched
            .get("event_service")
            .or_else(|| enriched.get("service"))
            .map(String::as_str);
        let event_cat_hash = event_category.map_or(0, hash_logsource);
        let event_prod_hash = event_product.map_or(0, hash_logsource);
        let event_svc_hash = event_service.map_or(0, hash_logsource);

        // Run Aho-Corasick scan across all event field values
        let ac_hits = self.run_ac_scan(&enriched);

        let mut matches = 0usize;

        for rule_idx in 0..self.rules.len() {
            // ── Hot prefilter: 24-byte RuleHotData only ───────────────────────────────────
            // 1000 entries × 24 bytes = 24 KB — fits in L1 cache.
            // The full CompiledRule (200-500+ bytes) is only dereferenced below
            // when a rule passes BOTH filters (typically 1 of 1000).
            let hot = &self.hot_data[rule_idx];

            // Logsource check: 3 integer comparisons (vs. Option<String> chain)
            if !(logsource_ok(hot.cat_hash, event_cat_hash)
                && logsource_ok(hot.prod_hash, event_prod_hash)
                && logsource_ok(hot.svc_hash, event_svc_hash))
            {
                continue;
            }

            // AC prefilter: flat contiguous slice — no pointer-chase into Vec heap
            if hot.fully_ac_covered && hot.ac_len > 0 {
                let start = hot.ac_start as usize;
                let end = start + hot.ac_len as usize;
                if !self.flat_ac_indices[start..end]
                    .iter()
                    .any(|&idx| ac_hits[idx as usize])
                {
                    continue;
                }
            }

            // ── Cold path: full evaluation (only when both hot filters pass) ──────
            let compiled = &self.rules[rule_idx];

            // Logsource string recheck: the hot loop compared 32-bit FNV-1a
            // hashes, which can collide. Confirm with the real strings before
            // evaluating — a collision must not route an event to the wrong
            // rule. Runs only for rules that already passed both prefilters,
            // so the cost is off the hot path.
            if !compiled
                .rule
                .logsource
                .matches(event_category, event_product, event_service)
            {
                continue;
            }

            // Full evaluation: check each identifier against the event.
            // Hot path: rules without |re use match_identifier directly (no HashMap lookup).
            // Regex path: rules with |re use the pre-compiled cache from the side-table.
            let mut id_results: HashMap<String, bool> =
                HashMap::with_capacity(compiled.identifiers.len());
            for ident in &compiled.identifiers {
                let id_eval = if compiled.has_regex {
                    match_identifier_with_cache_on_view(
                        ident,
                        &mut view,
                        &self.rule_regex_maps[rule_idx],
                    )
                } else {
                    match_identifier_on_view(ident, &mut view)
                };
                id_results.insert(ident.name.clone(), id_eval);
            }

            // Evaluate each condition expression
            if collect_details {
                let mut matched_conditions: Vec<usize> =
                    Vec::with_capacity(compiled.conditions.len());

                for (cond_idx, condition) in compiled.conditions.iter().enumerate() {
                    if condition.evaluate(&id_results) {
                        matched_conditions.push(cond_idx);
                    }
                }

                if !matched_conditions.is_empty() {
                    matches += 1;
                    on_match(compiled, &id_results, &matched_conditions);
                }
            } else if compiled
                .conditions
                .iter()
                .any(|condition| condition.evaluate(&id_results))
            {
                matches += 1;
            }
        }

        matches
    }

    /// Evaluate a batch of events. Returns results indexed by event position.
    ///
    /// # Concurrency
    ///
    /// Takes `&self` — safe to call concurrently from multiple threads once
    /// rule loading is complete.
    #[must_use = "returns all threat detections — discarding them silently suppresses security alerts"]
    pub fn evaluate_batch(&self, events: &[HashMap<String, String>]) -> Vec<EvalResult> {
        events
            .iter()
            .enumerate()
            .map(|(idx, event)| {
                let rule_matches = self.evaluate_event(event);
                EvalResult {
                    event_index: idx,
                    matches: rule_matches,
                    rules_evaluated: self.rules.len(),
                }
            })
            .collect()
    }

    // ─── Aho-Corasick Batch Scan ────────────────────────────────────────

    /// Run the AC automaton across all event field values.
    /// Returns a dense boolean bitmap indexed by pattern ID.
    /// Single indexed load (`hits[idx]`) instead of hash lookup per membership check.
    ///
    /// # Overlap soundness
    ///
    /// The prefilter needs the hit bit set for EVERY pattern that occurs
    /// anywhere in the value — but `find_iter` reports non-overlapping
    /// matches only: after one pattern matches, occurrences of other
    /// patterns overlapping the consumed span are silently skipped, their
    /// hit bits stay false, and fully-AC-covered rules relying on them get
    /// prefilter-skipped. (A real false negative found by the head-to-head
    /// cross-check: `shell32.dll` consumed the span covering `.dll,`, which
    /// masked a co-loaded rule.) A full `find_overlapping_iter` scan fixes
    /// this but disables the SIMD prefilter and cost ~10× on noisy values.
    ///
    /// The overlapping scan costs nothing measurable on pattern-free values
    /// (the dominant real-world case — the automaton's prefilter still
    /// applies; the zero-match benchmark actually improved), and on values
    /// with hits it reports the truth. A windowed hybrid
    /// (`find_iter` + bounded overlapping rescan around match ends) was
    /// benchmarked and was slower in every scenario because matched regions
    /// get scanned twice.
    fn run_ac_scan(&self, event: &HashMap<String, String>) -> Vec<bool> {
        let Some(ac) = &self.ac_automaton else {
            return vec![false; self.ac_patterns.len()];
        };

        let mut hits = vec![false; self.ac_patterns.len()];

        for value in event.values() {
            for mat in ac.find_overlapping_iter(value) {
                hits[mat.pattern().as_usize()] = true;
            }
        }

        hits
    }
}

impl Default for SigmaEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn finalize_identifiers(identifiers: &mut [SearchIdentifier]) {
    for ident in identifiers {
        for group in &mut ident.groups {
            for cond in &mut group.conditions {
                cond.field_folded = fold_key(&cond.field);
                cond.values_folded = cond
                    .values
                    .iter()
                    .map(|value| match value {
                        crate::types::SigmaValue::String(s) => Some(fold_value(s)),
                        crate::types::SigmaValue::Integer(i) => Some(i.to_string()),
                        crate::types::SigmaValue::Float(f) => Some(f.to_string()),
                        crate::types::SigmaValue::Boolean(b) => Some(b.to_string()),
                        crate::types::SigmaValue::Null => Some(String::new()),
                    })
                    .collect();
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: AC Pattern Eligibility
// ─────────────────────────────────────────────────────────────────────────────

/// A field condition is eligible for Aho-Corasick optimization if it uses
/// simple string matching (contains, startswith, endswith, or default) with
/// no wildcards, regex, CIDR, numeric comparisons, existence checks, or
/// transform modifiers.
///
/// Transform modifiers (windash, base64, base64offset, wide) MUST be excluded:
/// they change WHAT we search for relative to the stored AC pattern value.
/// Example: |windash on "-enc" also accepts "/enc" at eval time, but only
/// "-enc" is in the AC automaton. If the event field holds "/enc", AC misses
/// and the pre-filter would incorrectly skip a rule that should match.
fn is_ac_eligible(condition: &FieldCondition) -> bool {
    // Must have string values with no ACTIVE wildcards. Escaped wildcards
    // (`\*`, `\?`) unescape to plain literals and remain AC-eligible.
    let all_plain_strings = condition.values.iter().all(|v| {
        matches!(v, crate::types::SigmaValue::String(s)
            if crate::matcher::pattern_literal(s).is_some())
    });

    if !all_plain_strings {
        return false;
    }

    let has_regex = condition.modifiers.contains(&ValueModifier::Regex);
    let has_cidr = condition.modifiers.contains(&ValueModifier::Cidr);
    let has_numeric = condition.modifiers.iter().any(|m| {
        matches!(
            m,
            ValueModifier::Gt | ValueModifier::Gte | ValueModifier::Lt | ValueModifier::Lte
        )
    });
    let has_exists = condition.modifiers.contains(&ValueModifier::Exists);
    // FieldRef values are field NAMES, not searchable content — registering
    // them as AC patterns would make the prefilter skip on the wrong bytes.
    let has_fieldref = condition.modifiers.contains(&ValueModifier::FieldRef);
    // Transform modifiers change the effective search value — the original plain
    // string in AC is not a reliable proxy for whether the condition can match.
    let has_transform = condition.modifiers.iter().any(ValueModifier::is_transform);

    !has_regex && !has_cidr && !has_numeric && !has_exists && !has_fieldref && !has_transform
}

/// Return true when the rule cannot match unless at least one AC-gated
/// identifier is true.
///
/// Proof obligation: with every gated identifier pinned false, the condition
/// must evaluate false under EVERY truth assignment of the ungated
/// identifiers (their values are unknowable from the AC scan — wildcards,
/// regexes, null checks…). All assignments are enumerated exhaustively;
/// rules with more than `MAX_UNGATED` ungated identifiers (2^n load-time
/// evaluations) conservatively return false, disabling the prefilter for
/// that rule rather than risking a false negative.
fn conditions_require_gated_hit(
    conditions: &[ConditionNode],
    identifiers: &[SearchIdentifier],
    gated_flags: &[bool],
) -> bool {
    const MAX_UNGATED: usize = 12;

    let ungated: Vec<&str> = identifiers
        .iter()
        .zip(gated_flags)
        .filter(|(_, &gated)| !gated)
        .map(|(ident, _)| ident.name.as_str())
        .collect();
    if ungated.len() > MAX_UNGATED {
        return false;
    }

    let mut results: HashMap<String, bool> = identifiers
        .iter()
        .map(|ident| (ident.name.clone(), false))
        .collect();

    // Enumerate every truth assignment of the ungated identifiers.
    for assignment in 0u32..(1u32 << ungated.len()) {
        for (bit, name) in ungated.iter().enumerate() {
            *results.get_mut(*name).expect("name present") = (assignment >> bit) & 1 == 1;
        }
        if conditions
            .iter()
            .any(|condition| condition.evaluate(&results))
        {
            return false;
        }
    }
    true
}

/// Pre-compile all `|re` regex patterns from a set of identifiers into a
/// lookup map. Called once per rule at load time; stored on `CompiledRule` so
/// `evaluate_event` can do O(1) lookups instead of O(1) regex compilations.
///
/// # Errors
///
/// Returns [`EngineError::InvalidRegex`] if any `|re` pattern fails to
/// compile. A pattern that cannot compile can never match, so accepting it
/// would silently disable the detection — rejecting the rule at load time
/// gives the operator a signal instead.
fn collect_compiled_regexes(
    identifiers: &[SearchIdentifier],
) -> Result<HashMap<String, regex::Regex>, EngineError> {
    let mut map = HashMap::new();
    for ident in identifiers {
        for group in &ident.groups {
            for cond in &group.conditions {
                if cond.modifiers.contains(&ValueModifier::Regex) {
                    for val in &cond.values {
                        let pattern = val.as_str_lossy();
                        if pattern.is_empty() {
                            continue;
                        }
                        // Compile with the case-insensitive default plus any
                        // |m/|s flag sub-modifiers. Cache key strategy mirrors
                        // the match-time lookup: raw pattern for plain |re
                        // (keeps the hot lookup allocation-free), full flagged
                        // pattern when sub-modifiers change the compilation.
                        let full =
                            crate::matcher::regex_pattern_with_flags(&pattern, &cond.modifiers);
                        let key = if crate::matcher::has_regex_flag_modifiers(&cond.modifiers) {
                            full.clone()
                        } else {
                            pattern.clone()
                        };
                        if let std::collections::hash_map::Entry::Vacant(entry) = map.entry(key) {
                            match regex::Regex::new(&full) {
                                Ok(re) => {
                                    entry.insert(re);
                                }
                                Err(e) => {
                                    return Err(EngineError::InvalidRegex {
                                        pattern,
                                        error: e.to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(map)
}
