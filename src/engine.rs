// =============================================================================
// NuLLAI Sigma Rule Engine — Multi-Rule Evaluation Engine
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
use crate::fieldmap::FieldMapping;
use crate::matcher::match_identifier;
use crate::parser::{parse_rule, parse_rules, ParseError};
use crate::types::{
    ConditionExpr, EvalResult, LogSource, RuleMatch, SearchIdentifier,
    SigmaRule, FieldCondition, ValueModifier,
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
    /// Multiple conditions means multiple independent evaluations (Sigma spec:
    /// each condition line is evaluated independently, any match = rule match).
    conditions: Vec<ConditionNode>,
    /// Indexes into the global pattern list for this rule's AC patterns.
    /// If empty, the rule has no simple string patterns (uses regex, etc.)
    /// and must always be fully evaluated.
    ac_pattern_indices: Vec<usize>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Engine Errors
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum EngineError {
    Parse(ParseError),
    Compile(CompileError),
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EngineError::Parse(e) => write!(f, "Parse error: {e}"),
            EngineError::Compile(e) => write!(f, "Compile error: {e}"),
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
// SigmaEngine — The main evaluation engine
// ─────────────────────────────────────────────────────────────────────────────

/// High-performance Sigma rule evaluation engine.
///
/// Load rules once (YAML parsing + compilation), then evaluate events at speed.
/// Thread-safe for read operations after rule loading is complete.
///
/// # Example
/// ```rust,ignore
/// let mut engine = SigmaEngine::new();
/// engine.load_rule(yaml_str)?;
/// let results = engine.evaluate_event(&event);
/// for m in &results {
///     println!("Rule matched: {} (score: {})", m.rule_title, m.score);
/// }
/// ```
pub struct SigmaEngine {
    /// All compiled rules.
    rules: Vec<CompiledRule>,
    /// Field name mapping (Sigma → NuLLAI).
    field_mapping: FieldMapping,
    /// All string patterns across all rules for Aho-Corasick.
    /// Each pattern has an associated (rule_index, identifier_name, condition_index).
    ac_patterns: Vec<String>,
    /// Maps pattern index → (rule index, identifier index in that rule).
    ac_pattern_map: Vec<(usize, usize)>,
    /// Compiled Aho-Corasick automaton. Rebuilt after rule changes.
    ac_automaton: Option<AhoCorasick>,
    /// Whether the AC automaton needs rebuilding.
    ac_dirty: bool,
}

impl SigmaEngine {
    /// Create a new empty Sigma engine with default NuLLAI field mappings.
    pub fn new() -> Self {
        SigmaEngine {
            rules: Vec::new(),
            field_mapping: FieldMapping::new(),
            ac_patterns: Vec::new(),
            ac_pattern_map: Vec::new(),
            ac_automaton: None,
            ac_dirty: false,
        }
    }

    /// Create a new engine with a custom field mapping.
    pub fn with_field_mapping(field_mapping: FieldMapping) -> Self {
        SigmaEngine {
            rules: Vec::new(),
            field_mapping,
            ac_patterns: Vec::new(),
            ac_pattern_map: Vec::new(),
            ac_automaton: None,
            ac_dirty: false,
        }
    }

    /// Load a single Sigma rule from YAML. Returns the rule ID on success.
    pub fn load_rule(&mut self, yaml: &str) -> Result<String, EngineError> {
        let (rule, identifiers) = parse_rule(yaml)?;
        let rule_id = rule.id.clone();
        self.add_compiled_rule(rule, identifiers)?;
        Ok(rule_id)
    }

    /// Load multiple rules from a multi-document YAML string (separated by ---).
    /// Returns (successes, errors) so callers can report failures without
    /// aborting the entire load.
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

        (successes, errors)
    }

    /// Get the number of loaded rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Get loaded rule IDs and titles.
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
        identifiers: Vec<SearchIdentifier>,
    ) -> Result<(), EngineError> {
        let rule_index = self.rules.len();

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

        // Extract simple string patterns for Aho-Corasick optimization
        let mut ac_indices = Vec::new();
        for (id_idx, identifier) in identifiers.iter().enumerate() {
            for group in &identifier.groups {
                for cond in &group.conditions {
                    // Only extract patterns suitable for AC: "contains" modifier
                    // with plain string values (no wildcards, no regex)
                    if is_ac_eligible(cond) {
                        for val in &cond.values {
                            let s = val.as_str_lossy();
                            let s_lower = s.to_lowercase();
                            if !s_lower.is_empty() {
                                let pattern_idx = self.ac_patterns.len();
                                self.ac_patterns.push(s_lower);
                                self.ac_pattern_map.push((rule_index, id_idx));
                                ac_indices.push(pattern_idx);
                            }
                        }
                    }
                }
            }
        }

        self.rules.push(CompiledRule {
            rule,
            identifiers,
            conditions,
            ac_pattern_indices: ac_indices,
        });

        self.ac_dirty = true;
        Ok(())
    }

    /// Rebuild the Aho-Corasick automaton after rule changes.
    fn rebuild_ac(&mut self) {
        if !self.ac_dirty {
            return;
        }

        if self.ac_patterns.is_empty() {
            self.ac_automaton = None;
        } else {
            // Build case-insensitive AC automaton
            self.ac_automaton = AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(&self.ac_patterns)
                .ok();
        }

        self.ac_dirty = false;
    }

    // ─── Event Evaluation ───────────────────────────────────────────────

    /// Evaluate a single event against all loaded rules.
    ///
    /// The event is a flat key-value map representing the event_data fields.
    /// Field names are automatically translated via the configured FieldMapping.
    ///
    /// Returns all matching rules with scores, matched conditions, and tags.
    pub fn evaluate_event(&mut self, event: &HashMap<String, String>) -> Vec<RuleMatch> {
        self.rebuild_ac();

        // Enrich the event with Sigma-canonical field names so rules can
        // match regardless of naming convention
        let enriched = self.field_mapping.enrich_event(event);

        // Optional metadata for logsource pre-filtering
        let event_category = enriched.get("event_category")
            .or_else(|| enriched.get("category"))
            .cloned();
        let event_product = enriched.get("event_product")
            .or_else(|| enriched.get("product"))
            .cloned();
        let event_service = enriched.get("event_service")
            .or_else(|| enriched.get("service"))
            .cloned();
        let event_logsource = LogSource {
            category: event_category,
            product: event_product,
            service: event_service,
        };

        // Run Aho-Corasick scan across all event field values
        let ac_hits = self.run_ac_scan(&enriched);

        let mut matches = Vec::new();

        for compiled in self.rules.iter() {
            // LogSource pre-filter: skip rules that don't apply to this event type
            if !compiled.rule.logsource.matches(
                event_logsource.category.as_deref(),
                event_logsource.product.as_deref(),
                event_logsource.service.as_deref(),
            ) {
                continue;
            }

            // AC pre-filter: if this rule has AC patterns, at least one must have hit
            if !compiled.ac_pattern_indices.is_empty() {
                let has_ac_hit = compiled.ac_pattern_indices.iter().any(|idx| ac_hits.contains(idx));
                if !has_ac_hit {
                    continue;
                }
            }

            // Full evaluation: check each identifier against the event
            let mut id_results: HashMap<String, bool> = HashMap::new();
            for identifier in &compiled.identifiers {
                let matched = match_identifier(identifier, &enriched);
                id_results.insert(identifier.name.clone(), matched);
            }

            // Evaluate each condition expression
            let mut matched_conditions: Vec<usize> = Vec::new();
            let mut matched_identifiers = Vec::new();

            for (cond_idx, condition) in compiled.conditions.iter().enumerate() {
                if condition.evaluate(&id_results) {
                    matched_conditions.push(cond_idx);

                    // Record which identifiers matched
                    for (name, matched) in &id_results {
                        if *matched && !matched_identifiers.contains(name) {
                            matched_identifiers.push(name.clone());
                        }
                    }
                }
            }

            if !matched_conditions.is_empty() {
                matches.push(RuleMatch {
                    rule_id: compiled.rule.id.clone(),
                    rule_title: compiled.rule.title.clone(),
                    rule_level: compiled.rule.level,
                    matched_conditions,
                    matched_identifiers,
                    tags: compiled.rule.tags.clone(),
                    score: compiled.rule.level.to_score(),
                });
            }
        }

        matches
    }

    /// Evaluate a batch of events. Returns results indexed by event position.
    pub fn evaluate_batch(
        &mut self,
        events: &[HashMap<String, String>],
    ) -> Vec<EvalResult> {
        self.rebuild_ac();

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
    /// Returns the set of pattern indices that matched.
    fn run_ac_scan(&self, event: &HashMap<String, String>) -> Vec<usize> {
        let ac = match &self.ac_automaton {
            Some(ac) => ac,
            None => return Vec::new(),
        };

        let mut hits = Vec::new();

        for value in event.values() {
            for mat in ac.find_iter(value) {
                let pattern_idx = mat.pattern().as_usize();
                if !hits.contains(&pattern_idx) {
                    hits.push(pattern_idx);
                }
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

// ─────────────────────────────────────────────────────────────────────────────
// Helper: AC Pattern Eligibility
// ─────────────────────────────────────────────────────────────────────────────

/// A field condition is eligible for Aho-Corasick optimization if it uses
/// simple string matching (contains, startswith, endswith, or default) with
/// no wildcards or regex. These are the sweet spot for AC batch matching.
fn is_ac_eligible(condition: &FieldCondition) -> bool {
    // Must have string values with no wildcards
    let all_plain_strings = condition.values.iter().all(|v| {
        matches!(v, crate::types::SigmaValue::String(s) if !s.contains('*') && !s.contains('?'))
    });

    if !all_plain_strings {
        return false;
    }

    // Must use a string-match modifier (or default exact match with contains keyword behavior)
    let has_regex = condition.modifiers.contains(&ValueModifier::Regex);
    let has_cidr = condition.modifiers.contains(&ValueModifier::Cidr);
    let has_numeric = condition.modifiers.iter().any(|m| {
        matches!(m, ValueModifier::Gt | ValueModifier::Gte | ValueModifier::Lt | ValueModifier::Lte)
    });
    let has_exists = condition.modifiers.contains(&ValueModifier::Exists);

    // Eligible if no non-string modifiers
    !has_regex && !has_cidr && !has_numeric && !has_exists
}
