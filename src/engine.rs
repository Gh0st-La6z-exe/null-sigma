// =============================================================================
// Sigma Rule Engine — Multi-Rule Evaluation Engine
// =============================================================================
// The engine is the top-level orchestrator. It holds compiled rules, manages
// the Inverted Dispatch Matrix (Primary Discriminator Index + Field-Presence
// Bitmask) for rapid candidate pruning, and evaluates events at scale.
//
// PERFORMANCE ARCHITECTURE:
//   1. Primary Discriminator Index: Inverted index on process binary basename
//      (Image, OriginalFileName), pruning candidate rules to ~10-20 candidates
//      in O(1) time without full table scans.
//   2. Field-Presence Bitmask: 64-bit mask of required canonical fields; rules
//      demanding fields absent from the event are skipped in 1 bitwise instruction.
//   3. LogSource prefilter: 32-bit FNV-1a hashes skip non-matching categories/products.
//   4. Compiled Condition AST: Boolean evaluation with short-circuiting.
//
// TARGET: >100K events/sec × 1000 rules on a single core.
// =============================================================================

use crate::condition::{compile_condition, CompileError, ConditionNode, ResolvedConditionNode};
use crate::event_view::EventView;
use crate::fieldmap::FieldMapping;
use crate::fold::{fold_key, fold_value};
use crate::matcher::{match_identifier_on_view, match_identifier_with_cache_on_view};
use crate::parser::{parse_rule, parse_rules, ParseError};
use crate::types::{
    ConditionExpr, EvalResult, RuleMatch, SearchIdentifier, SigmaRule, ValueMatchCache,
    ValueModifier,
};

use std::cell::RefCell;
use std::collections::HashMap;

thread_local! {
    static EVAL_SCRATCH: RefCell<EvalScratch> = RefCell::new(EvalScratch::new());
}

// ─────────────────────────────────────────────────────────────────────────────
// Compiled Rule — Fully parsed, validated, and ready for evaluation
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct CompiledRule {
    /// The original parsed Sigma rule.
    rule: SigmaRule,
    /// Parsed search identifiers from the detection block.
    identifiers: Vec<SearchIdentifier>,
    /// Resolved condition AST(s) with pre-mapped identifier indices for lazy evaluation.
    resolved_conditions: Vec<ResolvedConditionNode>,
    /// True if any identifier in this rule contains a `|re` (regex) condition.
    /// When false the hot-path uses `match_identifier` (no cache lookup overhead).
    /// When true `evaluate_event` looks up `SigmaEngine::rule_regex_maps[rule_idx]`.
    has_regex: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// EvalScratch — Reusable per-evaluation buffers
// ─────────────────────────────────────────────────────────────────────────────

/// Reusable scratch buffers for hot-path evaluation.
///
/// Avoids per-rule allocation of identifier evaluation results.
/// Typically obtained via thread-local storage inside [`SigmaEngine::evaluate_event`];
/// batch callers may reuse one instance across events.
#[derive(Debug, Default)]
pub struct EvalScratch {
    id_results: Vec<bool>,
    id_state: Vec<u8>,
}

impl EvalScratch {
    /// Create an empty scratch buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Resize and zero identifier results before evaluating a rule.
    pub(crate) fn reset_id_results(&mut self, ident_count: usize) {
        self.id_results.resize(ident_count, false);
        if ident_count > 0 {
            self.id_results[..ident_count].fill(false);
        }
    }

    /// Resize and zero identifier state (0 = uncomputed) before evaluating a rule lazily.
    pub(crate) fn reset_id_state(&mut self, ident_count: usize) {
        self.id_state.resize(ident_count, 0);
        if ident_count > 0 {
            self.id_state[..ident_count].fill(0);
        }
    }
}

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

/// Compact 24-byte per-rule fields used exclusively by the hot candidate evaluation loop.
///
/// Only these fields are touched for candidate rules during prefiltering.
/// The full `CompiledRule` (200-500+ bytes) is only dereferenced when a rule passes
/// both the logsource filter and the field-presence bitmask — typically < 1% of candidates.
///
/// At 24 bytes/rule, 1000 rules = 24 KB — guaranteed to fit entirely in L1 cache (64 KB).
#[derive(Debug, Clone, Copy)]
struct RuleHotData {
    /// 64-bit mask of canonical fields that are strictly required for this rule to fire.
    required_fields_mask: u64,
    /// FNV-1a hash of the required logsource category (lowercased). 0 = wildcard.
    cat_hash: u32,
    /// FNV-1a hash of the required logsource product (lowercased). 0 = wildcard.
    prod_hash: u32,
    /// FNV-1a hash of the required logsource service (lowercased). 0 = wildcard.
    svc_hash: u32,
    /// Explicit padding to ensure an exact 24-byte struct layout and cacheline alignment.
    _pad: u32,
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
    /// Pre-compiled regex maps, one per rule, indexed by rule position.
    /// Kept separate from `CompiledRule` so the hot struct stays small
    /// (no `HashMap` inline on every rule — cache-friendly at 1000+ rules).
    /// Only accessed when `CompiledRule::has_regex` is true.
    rule_regex_maps: Vec<HashMap<String, regex::Regex>>,
    /// Cache-friendly 24-byte hot data for the prefilter loop. Parallel to `rules`.
    /// 1000 rules × 24 bytes = 24 KB — guaranteed to fit in L1 cache (64 KB).
    hot_data: Vec<RuleHotData>,
    /// Inverted index for primary binary basenames: lowercased image basename -> rule indices.
    image_discriminator_index: HashMap<String, Vec<u32>>,
    /// Inverted index for parent binary basenames: lowercased parent image basename -> rule indices.
    parent_image_discriminator_index: HashMap<String, Vec<u32>>,
    /// Rule indices without strict image or parent image basename constraints.
    unconstrained_rules: Vec<u32>,
}

impl SigmaEngine {
    /// Create a new empty Sigma engine with default field mappings.
    /// Covers Sysmon, Windows Security, Linux auditd, and generic fields.
    #[must_use]
    pub fn new() -> Self {
        SigmaEngine {
            rules: Vec::new(),
            field_mapping: FieldMapping::new(),
            rule_regex_maps: Vec::new(),
            hot_data: Vec::new(),
            image_discriminator_index: HashMap::new(),
            parent_image_discriminator_index: HashMap::new(),
            unconstrained_rules: Vec::new(),
        }
    }

    /// Create a new engine with a custom field mapping.
    #[must_use]
    pub fn with_field_mapping(field_mapping: FieldMapping) -> Self {
        SigmaEngine {
            rules: Vec::new(),
            field_mapping,
            rule_regex_maps: Vec::new(),
            hot_data: Vec::new(),
            image_discriminator_index: HashMap::new(),
            parent_image_discriminator_index: HashMap::new(),
            unconstrained_rules: Vec::new(),
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

        // ── Field-presence mask & Binary discriminators ────────────
        let required_fields_mask = compute_required_fields_mask(&conditions, &identifiers);
        let image_discriminators =
            crate::discriminator::compute_rule_image_discriminators(&conditions, &identifiers);
        let parent_image_discriminators = if image_discriminators.is_none() {
            crate::discriminator::compute_rule_parent_image_discriminators(
                &conditions,
                &identifiers,
            )
        } else {
            None
        };

        let ident_index: HashMap<String, usize> = identifiers
            .iter()
            .enumerate()
            .map(|(idx, ident)| (ident.name.clone(), idx))
            .collect();

        let resolved_conditions: Vec<ResolvedConditionNode> = conditions
            .iter()
            .filter_map(|c| c.resolve_indices(&ident_index))
            .collect();

        self.rules.push(CompiledRule {
            rule,
            identifiers,
            resolved_conditions,
            has_regex,
        });
        // Push regex map, hot data in lockstep: index i ↔ rules[i].
        self.rule_regex_maps.push(regex_map);

        // Build hot data entry: pre-hash logsource fields.
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

        self.hot_data.push(RuleHotData {
            required_fields_mask,
            cat_hash,
            prod_hash,
            svc_hash,
            _pad: 0,
        });

        let rule_idx = u32::try_from(self.rules.len() - 1).expect("rule count fits in u32");
        if let Some(basenames) = image_discriminators {
            for base in basenames {
                self.image_discriminator_index
                    .entry(base)
                    .or_default()
                    .push(rule_idx);
            }
        } else if let Some(basenames) = parent_image_discriminators {
            for base in basenames {
                self.parent_image_discriminator_index
                    .entry(base)
                    .or_default()
                    .push(rule_idx);
            }
        } else {
            self.unconstrained_rules.push(rule_idx);
        }

        Ok(())
    }

    // ─── Event Evaluation ───────────────────────────────────────────────

    /// Count matching rules without building [`RuleMatch`] payloads.
    ///
    /// Same semantics as [`Self::evaluate_event`], but skips result metadata
    /// allocation — use for throughput-sensitive paths that only need a hit count.
    #[must_use = "returns the number of matching rules — discarding it silently suppresses detection counts"]
    pub fn evaluate_event_count(&self, event: &HashMap<String, String>) -> usize {
        EVAL_SCRATCH.with(|cell| {
            let mut scratch = cell.borrow_mut();
            self.evaluate_event_inner(event, false, &mut scratch, &mut |_, _, _| {})
        })
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
    /// rule loading is complete.
    #[must_use = "returns all threat detections — discarding them silently suppresses security alerts"]
    pub fn evaluate_event(&self, event: &HashMap<String, String>) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        EVAL_SCRATCH.with(|cell| {
            let mut scratch = cell.borrow_mut();
            self.evaluate_event_inner(
                event,
                true,
                &mut scratch,
                &mut |compiled, id_results, matched_conditions| {
                    let matched_identifiers: Vec<String> = compiled
                        .identifiers
                        .iter()
                        .enumerate()
                        .filter_map(|(idx, ident)| {
                            if id_results.get(idx).copied().unwrap_or(false) {
                                Some(ident.name.clone())
                            } else {
                                None
                            }
                        })
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
                },
            );
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
        scratch: &mut EvalScratch,
        on_match: &mut dyn FnMut(&CompiledRule, &[bool], &[usize]),
    ) -> usize {
        // Enrich the event with Sigma-canonical field names so rules can
        // match regardless of naming convention.
        // `enrich_event_cow` returns `Borrowed` (zero allocation) when the
        // event already uses Sigma field names, `Owned` only when application
        // canonical names are present and aliases need to be added.
        let enriched = self.field_mapping.enrich_event_cow(event);
        let mut view = EventView::from_map(enriched.as_ref());
        let event_fields_mask = view.present_fields_mask();

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

        let mut matches = 0usize;

        // Resolve event binary basename from Image or OriginalFileName for inverted dispatch
        let mut specific_slice1: &[u32] = &[];
        let mut specific_slice2: &[u32] = &[];
        let mut parent_slice: &[u32] = &[];

        if let Some(idx) = view.first_index_for_folded_field("image") {
            let raw = view.raw_at(idx);
            let s = raw.trim();
            let comp = match s.rfind(['\\', '/']) {
                Some(pos) => &s[pos + 1..],
                None => s,
            };
            if !comp.is_empty() {
                let base = comp.to_lowercase();
                if let Some(rules) = self.image_discriminator_index.get(&base) {
                    specific_slice1 = rules;
                }
            }
        }

        if let Some(idx) = view.first_index_for_folded_field("originalfilename") {
            let raw = view.raw_at(idx);
            let s = raw.trim();
            let comp = match s.rfind(['\\', '/']) {
                Some(pos) => &s[pos + 1..],
                None => s,
            };
            if !comp.is_empty() {
                let base = comp.to_lowercase();
                if let Some(rules) = self.image_discriminator_index.get(&base) {
                    if specific_slice1 != rules {
                        specific_slice2 = rules;
                    }
                }
            }
        }

        if let Some(idx) = view.first_index_for_folded_field("parentimage") {
            let raw = view.raw_at(idx);
            let s = raw.trim();
            let comp = match s.rfind(['\\', '/']) {
                Some(pos) => &s[pos + 1..],
                None => s,
            };
            if !comp.is_empty() {
                let base = comp.to_lowercase();
                if let Some(rules) = self.parent_image_discriminator_index.get(&base) {
                    parent_slice = rules;
                }
            }
        }

        let candidate_slices: [&[u32]; 4] = [
            &self.unconstrained_rules,
            specific_slice1,
            specific_slice2,
            parent_slice,
        ];

        for slice in candidate_slices {
            for &rule_idx_u32 in slice {
                let rule_idx = rule_idx_u32 as usize;
                // ── Hot prefilter: 24-byte RuleHotData only ───────────────────────────────────
                // 1000 entries × 24 bytes = 24 KB — fits in L1 cache.
                // The full CompiledRule (200-500+ bytes) is only dereferenced below
                // when a rule passes BOTH prefilters (typically < 1% of candidates).
                let hot = &self.hot_data[rule_idx];

                // Logsource check: 3 integer comparisons (vs. Option<String> chain)
                if !(logsource_ok(hot.cat_hash, event_cat_hash)
                    && logsource_ok(hot.prod_hash, event_prod_hash)
                    && logsource_ok(hot.svc_hash, event_svc_hash))
                {
                    continue;
                }

                // Field-presence check: skip rules requiring fields absent from the event
                if (hot.required_fields_mask & event_fields_mask) != hot.required_fields_mask {
                    continue;
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

                // Lazy condition evaluation:
                // Evaluates identifiers on demand with caching, short-circuiting as soon
                // as boolean AST branches (AND/OR) are determined.
                scratch.reset_id_state(compiled.identifiers.len());

                if collect_details {
                    let mut matched_conditions: Vec<usize> =
                        Vec::with_capacity(compiled.resolved_conditions.len());

                    {
                        let mut eval_ident = |idx: usize| -> bool {
                            let cached = scratch.id_state[idx];
                            if cached == 1 {
                                false
                            } else if cached == 2 {
                                true
                            } else {
                                let res = if compiled.has_regex {
                                    match_identifier_with_cache_on_view(
                                        &compiled.identifiers[idx],
                                        &mut view,
                                        &self.rule_regex_maps[rule_idx],
                                    )
                                } else {
                                    match_identifier_on_view(&compiled.identifiers[idx], &mut view)
                                };
                                scratch.id_state[idx] = if res { 2 } else { 1 };
                                res
                            }
                        };

                        for (cond_idx, condition) in compiled.resolved_conditions.iter().enumerate() {
                            if condition.evaluate_lazy(&mut eval_ident) {
                                matched_conditions.push(cond_idx);
                            }
                        }

                        if !matched_conditions.is_empty() {
                            // For matching rules only, ensure any remaining identifiers are evaluated
                            // so RuleMatch details contain all matched identifiers.
                            for idx in 0..compiled.identifiers.len() {
                                let _ = eval_ident(idx);
                            }
                        }
                    }

                    if !matched_conditions.is_empty() {
                        matches += 1;
                        scratch.reset_id_results(compiled.identifiers.len());
                        for idx in 0..compiled.identifiers.len() {
                            scratch.id_results[idx] = scratch.id_state[idx] == 2;
                        }
                        on_match(compiled, &scratch.id_results, &matched_conditions);
                    }
                } else {
                    let mut eval_ident = |idx: usize| -> bool {
                        let cached = scratch.id_state[idx];
                        if cached == 1 {
                            false
                        } else if cached == 2 {
                            true
                        } else {
                            let res = if compiled.has_regex {
                                match_identifier_with_cache_on_view(
                                    &compiled.identifiers[idx],
                                    &mut view,
                                    &self.rule_regex_maps[rule_idx],
                                )
                            } else {
                                match_identifier_on_view(&compiled.identifiers[idx], &mut view)
                            };
                            scratch.id_state[idx] = if res { 2 } else { 1 };
                            res
                        }
                    };

                    for condition in &compiled.resolved_conditions {
                        if condition.evaluate_lazy(&mut eval_ident) {
                            matches += 1;
                            break;
                        }
                    }
                }
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
}

impl Default for SigmaEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn condition_eval_cost(cond: &crate::types::FieldCondition) -> u32 {
    let mut base_cost = 10;
    if cond.modifiers.contains(&ValueModifier::Exists) {
        return 0;
    }
    if cond.modifiers.contains(&ValueModifier::Regex) {
        return 1000;
    }
    if cond.modifiers.contains(&ValueModifier::Cidr) {
        return 500;
    }
    if cond.modifiers.contains(&ValueModifier::FieldRef) {
        return 300;
    }
    if cond.modifiers.iter().any(ValueModifier::is_transform) {
        base_cost += 200;
    }
    if cond.modifiers.contains(&ValueModifier::Contains) {
        base_cost += 50;
    } else if cond.modifiers.contains(&ValueModifier::StartsWith)
        || cond.modifiers.contains(&ValueModifier::EndsWith)
    {
        base_cost += 20;
    }

    base_cost + (cond.values.len() as u32 * 5)
}

fn finalize_identifiers(identifiers: &mut [SearchIdentifier]) {
    for ident in identifiers {
        for group in &mut ident.groups {
            for cond in &mut group.conditions {
                cond.field_folded = fold_key(&cond.field);
                cond.field_bit = crate::field_mask::field_bit(&cond.field_folded);
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
                cond.values_match_cache = cond
                    .values_folded
                    .iter()
                    .map(|folded| {
                        if cond.modifiers.iter().any(ValueModifier::is_transform) {
                            ValueMatchCache::default()
                        } else {
                            folded
                                .as_deref()
                                .map(crate::matcher::build_value_match_cache)
                                .unwrap_or_default()
                        }
                    })
                    .collect();
                cond.require_all = cond.modifiers.contains(&ValueModifier::All);
                cond.has_transforms = cond.modifiers.iter().any(ValueModifier::is_transform);
                cond.needs_chars = !cond.has_transforms
                    && cond.values_match_cache.iter().any(|c| c.tokens.is_some());
            }
            // Cost-Ranked AST Reordering: sort AND-grouped conditions so cheap,
            // highly-selective conditions evaluate first and short-circuit early.
            group.conditions.sort_by_key(condition_eval_cost);
        }
    }
}

/// Compute the 64-bit mask of canonical fields that are strictly required for this rule
/// to match.
///
/// Proof obligation: if any field corresponding to a bit in this mask is absent from the
/// event, the rule's condition AST provably evaluates to `false` under EVERY possible
/// truth assignment of the remaining identifiers.
fn compute_required_fields_mask(
    conditions: &[ConditionNode],
    identifiers: &[SearchIdentifier],
) -> u64 {
    const MAX_UNCONSTRAINED: usize = 12;
    if identifiers.len() > MAX_UNCONSTRAINED {
        return 0;
    }

    // 1. For each identifier, determine which canonical field bits are strictly required.
    // An identifier requires field bit B if EVERY one of its groups contains at least one
    // condition checking a field that maps to bit B (and not `exists: false`).
    let mut ident_required_masks = Vec::with_capacity(identifiers.len());
    for ident in identifiers {
        let mut ident_mask: u64 = u64::MAX;
        if ident.groups.is_empty() {
            ident_mask = 0;
        } else {
            for group in &ident.groups {
                let mut group_mask: u64 = 0;
                for cond in &group.conditions {
                    if cond.field.is_empty() || cond.modifiers.contains(&ValueModifier::Exists) {
                        continue;
                    }
                    if let Some(bit) = crate::field_mask::field_bit(&cond.field_folded) {
                        group_mask |= 1u64 << bit;
                    }
                }
                ident_mask &= group_mask;
            }
        }
        ident_required_masks.push(ident_mask);
    }

    let candidate_bits_union: u64 = ident_required_masks.iter().fold(0u64, |acc, &m| acc | m);
    if candidate_bits_union == 0 {
        return 0;
    }

    let mut rule_required_mask: u64 = 0;
    let mut results: HashMap<String, bool> = identifiers
        .iter()
        .map(|ident| (ident.name.clone(), false))
        .collect();

    // 2. For each candidate bit, test if pinning all identifiers that require that bit
    // to `false` prevents the condition from firing under any assignment of other idents.
    for bit in 0..64 {
        let bit_mask = 1u64 << bit;
        if (candidate_bits_union & bit_mask) == 0 {
            continue;
        }

        let unconstrained: Vec<&str> = identifiers
            .iter()
            .zip(&ident_required_masks)
            .filter(|(_, &m)| (m & bit_mask) == 0)
            .map(|(ident, _)| ident.name.as_str())
            .collect();

        if unconstrained.len() == identifiers.len() {
            continue;
        }

        let mut can_fire = false;
        for assignment in 0u32..(1u32 << unconstrained.len()) {
            for ident in identifiers {
                *results.get_mut(&ident.name).expect("name present") = false;
            }
            for (i, name) in unconstrained.iter().enumerate() {
                *results.get_mut(*name).expect("name present") = (assignment >> i) & 1 == 1;
            }
            if conditions.iter().any(|cond| cond.evaluate(&results)) {
                can_fire = true;
                break;
            }
        }

        if !can_fire {
            rule_required_mask |= bit_mask;
        }
    }

    rule_required_mask
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_hot_data_size_is_24_bytes() {
        assert_eq!(
            std::mem::size_of::<RuleHotData>(),
            24,
            "RuleHotData must remain exactly 24 bytes for optimal L1 cache line density"
        );
    }
}
