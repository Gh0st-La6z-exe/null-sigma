// =============================================================================
// Sigma Rule Engine — Multi-Rule Evaluation Engine
// =============================================================================
// The engine is the top-level orchestrator. It holds compiled rules, manages
// the 3-Tier Inverted Dispatch Matrix (Hard Logsource Partitioning + Primary
// Basename Discriminators + Field-Presence Bitmask) for rapid candidate pruning,
// and evaluates events at scale.
//
// PERFORMANCE ARCHITECTURE:
//   1. Hard Logsource Partitioning: Unconstrained rules are partitioned into
//      category, service, product, and wildcard bitsets, completely eliminating
//      cross-category evaluation overhead and preserving per-core L1/L2 cache residency.
//   2. Primary & Secondary Basename Discriminators: Inverted index on process binary
//      basenames (Image, OriginalFileName, ParentImage), pruning candidate rules
//      to ~5-15 candidates in O(1) time without full table scans.
//   3. Canonical Field-Presence Bitmask: 64-bit mask of required canonical fields; rules
//      demanding fields absent from the event are skipped in 1 bitwise instruction.
//   4. Sub-256 Vectorized Bigram Bloom Filter: 256-bit SIMD/vectorized filter rejecting
//      substring non-matches in 4 bitwise AND instructions (<1 cycle).
//   5. Flat Register Decision Tape: Contiguous linear bytecode interpreter with
//      single-cycle MatchMode jump tables replacing recursive AST tree-walking.
// =============================================================================

use crate::bitset::RuleBitSet;
use crate::bloom::Bloom256;
use crate::condition::{
    compile_condition, CompileError, ConditionNode, DecisionTape, ResolvedConditionNode,
};
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
enum CompiledCondition {
    Single(usize),
    Tape(DecisionTape),
    MultiTape(Vec<DecisionTape>),
}

#[derive(Debug)]
struct CompiledRule {
    /// The original parsed Sigma rule.
    rule: SigmaRule,
    /// Parsed search identifiers from the detection block.
    identifiers: Vec<SearchIdentifier>,
    /// Compiled condition representation.
    condition: CompiledCondition,
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
    pub(crate) id_results: Vec<bool>,
    pub(crate) id_state: Vec<u8>,
    pub(crate) candidate_mask: RuleBitSet,
    pub(crate) discriminator_buf: String,
    pub(crate) image_base_buf: String,
    pub(crate) parent_image_base_buf: String,
    pub(crate) orig_file_base_buf: String,
    pub(crate) event_scratch: crate::event_view::EventScratch,
    pub(crate) matched_conditions: Vec<usize>,
}

impl EvalScratch {
    /// Create an empty scratch buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Resize and zero identifier results in an explicit buffer.
    #[inline]
    pub(crate) fn reset_vec_results(results: &mut Vec<bool>, ident_count: usize) {
        results.resize(ident_count, false);
        if ident_count > 0 {
            results[..ident_count].fill(false);
        }
    }

    /// Resize and zero identifier state (0 = uncomputed) in an explicit buffer.
    #[inline]
    pub(crate) fn reset_vec_state(state: &mut Vec<u8>, ident_count: usize) {
        state.resize(ident_count, 0);
        if ident_count > 0 {
            state[..ident_count].fill(0);
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

/// Compact 64-byte per-rule fields used exclusively by the hot candidate evaluation loop.
///
/// Only these fields are touched for candidate rules during prefiltering.
/// The full `CompiledRule` (200-500+ bytes) is only dereferenced when a rule passes
/// the logsource filter, the field-presence bitmask, and the mandatory needle bloom filter.
///
/// At 64 bytes/rule, each rule occupies exactly ONE cacheline (64 bytes).
/// 1000 rules = 64 KB — guaranteed to fit entirely in CPU cache.
#[derive(Debug, Clone, Copy)]
#[repr(C, align(64))]
struct RuleHotData {
    /// 64-bit mask of canonical fields that are strictly required for this rule to fire.
    required_fields_mask: u64,
    /// FNV-1a hash of the required logsource category (lowercased). 0 = wildcard.
    cat_hash: u32,
    /// FNV-1a hash of the required logsource product (lowercased). 0 = wildcard.
    prod_hash: u32,
    /// FNV-1a hash of the required logsource service (lowercased). 0 = wildcard.
    svc_hash: u32,
    /// Canonical field bit index for mandatory bloom (e.g. 0 for CommandLine, 255 = none).
    bloom_field: u8,
    /// Explicit padding to ensure 64-byte struct layout and 32-byte alignment for Bloom256.
    _pad: [u8; 11],
    /// 256-bit mandatory needle bloom filter. If non-empty, the event's field bloom
    /// MUST be a superset of this bloom, or the rule is rejected in 4 instructions.
    mandatory_bloom: Bloom256,
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
    /// Inverted index for basenames across any process field (Image, OriginalFileName, ParentImage).
    process_discriminator_index: HashMap<String, Vec<u32>>,
    /// Inverted index for loaded image basenames (Sysmon EID 7 / driver load).
    image_loaded_discriminator_index: HashMap<String, Vec<u32>>,
    /// Inverted index for EventID (Windows Security, Sysmon, PowerShell, etc.).
    event_id_discriminator_index: HashMap<u32, Vec<u32>>,
    /// Inverted index for pipe names (Sysmon EID 17/18).
    pipe_name_discriminator_index: HashMap<String, Vec<u32>>,
    /// Inverted index for DNS query names (Sysmon EID 22).
    query_name_discriminator_index: HashMap<String, Vec<u32>>,
    /// Inverted index for target filenames (File Events Sysmon EID 11).
    target_filename_discriminator_index: HashMap<String, Vec<u32>>,
    /// Inverted index for description metadata: lowercased description -> rule indices.
    description_discriminator_index: HashMap<String, Vec<u32>>,
    /// Inverted index for product metadata: lowercased product -> rule indices.
    product_discriminator_index: HashMap<String, Vec<u32>>,
    /// Inverted index for company metadata: lowercased company -> rule indices.
    company_discriminator_index: HashMap<String, Vec<u32>>,
    /// Hard Logsource Partitioning for unconstrained rules:
    /// Universal wildcard unconstrained rules (cat=0, prod=0, svc=0).
    wildcard_unconstrained: RuleBitSet,
    /// Unconstrained rules partitioned by logsource category hash.
    category_unconstrained: HashMap<u32, RuleBitSet>,
    /// Unconstrained rules partitioned by logsource service hash (when cat=0).
    service_unconstrained: HashMap<u32, RuleBitSet>,
    /// Unconstrained rules partitioned by logsource product hash (when cat=0, svc=0).
    product_unconstrained: HashMap<u32, RuleBitSet>,
    /// Candidate rules bitset without strict image or parent image basename constraints.
    unconstrained_mask: RuleBitSet,
    /// Sound prefilter branch feasibility checks for positive identifiers. Parallel to `rules`.
    rule_feasibility: Vec<crate::discriminator::RuleFeasibility>,
}

#[inline(always)]
fn eval_single_check(
    check: &crate::discriminator::SingleCheck,
    view: &mut EventView,
    event_fields_mask: u64,
    image_base_buf: &str,
    parent_image_base_buf: &str,
    orig_file_base_buf: &str,
) -> bool {
    match check {
        crate::discriminator::SingleCheck::ImageBasename(base) => {
            !image_base_buf.is_empty() && image_base_buf == base.as_str()
        }
        crate::discriminator::SingleCheck::ImageBasenameSet(bases) => {
            !image_base_buf.is_empty() && bases.iter().any(|b| b.as_str() == image_base_buf)
        }
        crate::discriminator::SingleCheck::ParentImageBasename(base) => {
            !parent_image_base_buf.is_empty() && parent_image_base_buf == base.as_str()
        }
        crate::discriminator::SingleCheck::ParentImageBasenameSet(bases) => {
            !parent_image_base_buf.is_empty()
                && bases.iter().any(|b| b.as_str() == parent_image_base_buf)
        }
        crate::discriminator::SingleCheck::OriginalFileBasename(base) => {
            !orig_file_base_buf.is_empty() && orig_file_base_buf == base.as_str()
        }
        crate::discriminator::SingleCheck::OriginalFileBasenameSet(bases) => {
            !orig_file_base_buf.is_empty() && bases.iter().any(|b| b.as_str() == orig_file_base_buf)
        }
        crate::discriminator::SingleCheck::FieldPresent(slot) => {
            (event_fields_mask & (1u64 << *slot)) != 0
        }
        crate::discriminator::SingleCheck::FieldNonAscii(slot) => {
            if (event_fields_mask & (1u64 << *slot)) == 0 {
                return false;
            }
            let idx = {
                let view_slot = view.canonical_slot(*slot);
                if view_slot != u32::MAX {
                    Some(view_slot as usize)
                } else {
                    crate::field_mask::bit_field(*slot)
                        .and_then(|field_name| view.first_index_for_folded_field(field_name))
                }
            };
            if let Some(i) = idx {
                !view.raw_at(i).is_ascii()
            } else {
                false
            }
        }
        crate::discriminator::SingleCheck::All(subchecks) => subchecks.iter().all(|sc| {
            eval_single_check(
                sc,
                view,
                event_fields_mask,
                image_base_buf,
                parent_image_base_buf,
                orig_file_base_buf,
            )
        }),
        crate::discriminator::SingleCheck::FieldBloom { slot, bloom } => {
            if (event_fields_mask & (1u64 << *slot)) == 0 {
                return false;
            }
            let idx = {
                let view_slot = view.canonical_slot(*slot);
                if view_slot != u32::MAX {
                    Some(view_slot as usize)
                } else {
                    crate::field_mask::bit_field(*slot)
                        .and_then(|field_name| view.first_index_for_folded_field(field_name))
                }
            };
            if let Some(i) = idx {
                view.ensure_bloom(i);
                bloom.is_subset_of(&view.bloom_at(i))
            } else {
                true
            }
        }
        crate::discriminator::SingleCheck::FieldBloomAny { slot, blooms } => {
            if (event_fields_mask & (1u64 << *slot)) == 0 {
                return false;
            }
            let idx = {
                let view_slot = view.canonical_slot(*slot);
                if view_slot != u32::MAX {
                    Some(view_slot as usize)
                } else {
                    crate::field_mask::bit_field(*slot)
                        .and_then(|field_name| view.first_index_for_folded_field(field_name))
                }
            };
            if let Some(i) = idx {
                view.ensure_bloom(i);
                let field_bloom = view.bloom_at(i);
                blooms.iter().any(|b| b.is_subset_of(&field_bloom))
            } else {
                true
            }
        }
    }
}

#[inline(always)]
fn eval_branch_check(
    check: &crate::discriminator::BranchCheck,
    view: &mut EventView,
    event_fields_mask: u64,
    image_base_buf: &str,
    parent_image_base_buf: &str,
    orig_file_base_buf: &str,
) -> bool {
    match check {
        crate::discriminator::BranchCheck::Single(c) => eval_single_check(
            c,
            view,
            event_fields_mask,
            image_base_buf,
            parent_image_base_buf,
            orig_file_base_buf,
        ),
        crate::discriminator::BranchCheck::Disjunction(checks) => checks.iter().any(|c| {
            eval_single_check(
                c,
                view,
                event_fields_mask,
                image_base_buf,
                parent_image_base_buf,
                orig_file_base_buf,
            )
        }),
        crate::discriminator::BranchCheck::Any => true,
    }
}

#[inline(always)]
fn rule_feasibility_passes(
    feas: &crate::discriminator::RuleFeasibility,
    possible_mask: u32,
) -> bool {
    if possible_mask == 0 {
        (feas.feasibility_bitmask & 1) != 0
    } else if feas.checks.len() <= 6 {
        (feas.feasibility_bitmask & (1u64 << possible_mask)) != 0
    } else {
        true
    }
}

#[inline(always)]
fn parse_ascii_u32(s: &str) -> Option<u32> {
    let bytes = s.trim().as_bytes();
    if bytes.is_empty() || bytes.len() > 10 {
        return None;
    }
    let mut val: u32 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        val = val.checked_mul(10)?.checked_add(u32::from(b - b'0'))?;
    }
    Some(val)
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
            process_discriminator_index: HashMap::new(),
            image_loaded_discriminator_index: HashMap::new(),
            event_id_discriminator_index: HashMap::new(),
            pipe_name_discriminator_index: HashMap::new(),
            query_name_discriminator_index: HashMap::new(),
            target_filename_discriminator_index: HashMap::new(),
            description_discriminator_index: HashMap::new(),
            product_discriminator_index: HashMap::new(),
            company_discriminator_index: HashMap::new(),
            wildcard_unconstrained: RuleBitSet::default(),
            category_unconstrained: HashMap::new(),
            service_unconstrained: HashMap::new(),
            product_unconstrained: HashMap::new(),
            unconstrained_mask: RuleBitSet::default(),
            rule_feasibility: Vec::new(),
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
            process_discriminator_index: HashMap::new(),
            image_loaded_discriminator_index: HashMap::new(),
            event_id_discriminator_index: HashMap::new(),
            pipe_name_discriminator_index: HashMap::new(),
            query_name_discriminator_index: HashMap::new(),
            target_filename_discriminator_index: HashMap::new(),
            description_discriminator_index: HashMap::new(),
            product_discriminator_index: HashMap::new(),
            company_discriminator_index: HashMap::new(),
            wildcard_unconstrained: RuleBitSet::default(),
            category_unconstrained: HashMap::new(),
            service_unconstrained: HashMap::new(),
            product_unconstrained: HashMap::new(),
            unconstrained_mask: RuleBitSet::default(),
            rule_feasibility: Vec::new(),
        }
    }

    /// Returns the counts of (image-indexed keys, parent-image-indexed keys, unconstrained rules).
    #[doc(hidden)]
    pub fn discriminator_stats(&self) -> (usize, usize, usize) {
        (
            self.image_discriminator_index.len(),
            self.parent_image_discriminator_index.len(),
            self.unconstrained_mask.count_ones(),
        )
    }

    /// Returns extended discriminator stats: (image, parent_image, image_loaded, event_id, pipe_name, query_name, target_filename, unconstrained).
    #[doc(hidden)]
    pub fn extended_discriminator_stats(
        &self,
    ) -> (usize, usize, usize, usize, usize, usize, usize, usize) {
        (
            self.image_discriminator_index.len(),
            self.parent_image_discriminator_index.len(),
            self.image_loaded_discriminator_index.len(),
            self.event_id_discriminator_index.len(),
            self.pipe_name_discriminator_index.len(),
            self.query_name_discriminator_index.len(),
            self.target_filename_discriminator_index.len(),
            self.unconstrained_mask.count_ones(),
        )
    }

    /// Returns the indices of rules currently in `unconstrained_mask`.
    #[doc(hidden)]
    pub fn unconstrained_rule_indices(&self) -> Vec<usize> {
        self.unconstrained_mask.iter_set_bits().collect()
    }

    /// Returns the identifiers of a compiled rule by index.
    #[doc(hidden)]
    pub fn rule_identifiers(&self, idx: usize) -> &[crate::types::SearchIdentifier] {
        &self.rules[idx].identifiers
    }

    /// Returns the logsource category of a compiled rule by index.
    #[doc(hidden)]
    pub fn rule_category(&self, idx: usize) -> Option<&str> {
        self.rules[idx].rule.logsource.category.as_deref()
    }

    /// Returns the logsource product of a compiled rule by index.
    #[doc(hidden)]
    pub fn rule_product(&self, idx: usize) -> Option<&str> {
        self.rules[idx].rule.logsource.product.as_deref()
    }

    /// Returns the logsource service of a compiled rule by index.
    #[doc(hidden)]
    pub fn rule_service(&self, idx: usize) -> Option<&str> {
        self.rules[idx].rule.logsource.service.as_deref()
    }

    /// Returns (title, bloom_field, mandatory_bloom.is_empty()) for rule at idx.
    #[doc(hidden)]
    pub fn rule_debug_info(&self, idx: usize) -> (&str, u8, bool) {
        (
            self.rules[idx].rule.title.as_str(),
            self.hot_data[idx].bloom_field,
            self.hot_data[idx].mandatory_bloom.is_empty(),
        )
    }

    /// Returns the precomputed branch checks for the rule at idx as strings.
    #[doc(hidden)]
    pub fn rule_branch_checks_debug(&self, idx: usize) -> Vec<String> {
        self.rule_feasibility[idx]
            .checks
            .iter()
            .map(|c| format!("{c:?}"))
            .collect()
    }

    #[doc(hidden)]
    pub fn debug_rule_feasibility(
        &self,
        rule_idx: usize,
        event: &HashMap<String, String>,
    ) -> (u32, u64, bool) {
        EVAL_SCRATCH.with(|cell| {
            let mut scratch = cell.borrow_mut();
            let EvalScratch {
                discriminator_buf,
                image_base_buf,
                parent_image_base_buf,
                orig_file_base_buf,
                event_scratch,
                ..
            } = &mut *scratch;

            image_base_buf.clear();
            parent_image_base_buf.clear();
            orig_file_base_buf.clear();

            let enriched = self.field_mapping.enrich_event_cow(event);
            let mut view = EventView::from_scratch_and_map(event_scratch, enriched.as_ref());
            let event_fields_mask = view.present_fields_mask();

            let image_idx = view.canonical_slot(1);
            if image_idx != u32::MAX {
                let s = view.raw_at(image_idx as usize).trim();
                let comp = match s.rfind(['\\', '/']) {
                    Some(pos) => &s[pos + 1..],
                    None => s,
                };
                discriminator_buf.clear();
                for b in comp.bytes() {
                    discriminator_buf.push(b.to_ascii_lowercase() as char);
                }
                image_base_buf.push_str(discriminator_buf.as_str());
            }

            let orig_idx = view.canonical_slot(4);
            if orig_idx != u32::MAX {
                let s = view.raw_at(orig_idx as usize).trim();
                let comp = match s.rfind(['\\', '/']) {
                    Some(pos) => &s[pos + 1..],
                    None => s,
                };
                discriminator_buf.clear();
                for b in comp.bytes() {
                    discriminator_buf.push(b.to_ascii_lowercase() as char);
                }
                orig_file_base_buf.push_str(discriminator_buf.as_str());
            }

            let feas = &self.rule_feasibility[rule_idx];
            let mut possible_mask = 0u32;
            for (bit, check) in feas.checks.iter().enumerate() {
                let p = eval_branch_check(
                    check,
                    &mut view,
                    event_fields_mask,
                    image_base_buf.as_str(),
                    parent_image_base_buf.as_str(),
                    orig_file_base_buf.as_str(),
                );
                if p {
                    possible_mask |= 1 << bit;
                }
            }
            let passes = rule_feasibility_passes(feas, possible_mask);
            (possible_mask, feas.feasibility_bitmask, passes)
        })
    }

    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    fn populate_candidate_mask(
        &self,
        view: &mut EventView,
        event_fields_mask: u64,
        event_cat_hash: u32,
        event_prod_hash: u32,
        event_svc_hash: u32,
        discriminator_buf: &mut String,
        image_base_buf: &mut String,
        parent_image_base_buf: &mut String,
        orig_file_base_buf: &mut String,
        candidate_mask: &mut RuleBitSet,
    ) {
        // 1. Logsource Partitioning for unconstrained rules
        if event_cat_hash != 0 || event_prod_hash != 0 || event_svc_hash != 0 {
            candidate_mask.copy_from(&self.wildcard_unconstrained);
            if event_cat_hash != 0 {
                if let Some(mask) = self.category_unconstrained.get(&event_cat_hash) {
                    candidate_mask.union_with(mask);
                }
            }
            if event_svc_hash != 0 {
                if let Some(mask) = self.service_unconstrained.get(&event_svc_hash) {
                    candidate_mask.union_with(mask);
                }
            }
            if event_prod_hash != 0 {
                if let Some(mask) = self.product_unconstrained.get(&event_prod_hash) {
                    candidate_mask.union_with(mask);
                }
            }
        } else {
            candidate_mask.copy_from(&self.unconstrained_mask);
        }

        // 2. Image / Process binary basename
        let image_idx = {
            let slot = view.canonical_slot(1);
            if slot != u32::MAX {
                Some(slot as usize)
            } else if (event_fields_mask & (1u64 << 1)) != 0 {
                view.first_index_for_folded_field("image")
            } else {
                None
            }
        };
        if let Some(idx) = image_idx {
            let raw = view.raw_at(idx);
            let s = raw.trim();
            let comp = match s.rfind(['\\', '/']) {
                Some(pos) => &s[pos + 1..],
                None => s,
            };
            if !comp.is_empty() {
                discriminator_buf.clear();
                for b in comp.bytes() {
                    discriminator_buf.push(b.to_ascii_lowercase() as char);
                }
                let key = discriminator_buf.as_str();
                image_base_buf.push_str(key);
                if let Some(rules) = self.image_discriminator_index.get(key) {
                    for &r in rules {
                        candidate_mask.set(r as usize);
                    }
                }
                if let Some(rules) = self.process_discriminator_index.get(key) {
                    for &r in rules {
                        candidate_mask.set(r as usize);
                    }
                }
            }
        }

        // 3. OriginalFileName
        let orig_idx = {
            let slot = view.canonical_slot(4);
            if slot != u32::MAX {
                Some(slot as usize)
            } else if (event_fields_mask & (1u64 << 4)) != 0 {
                view.first_index_for_folded_field("originalfilename")
            } else {
                None
            }
        };
        if let Some(idx) = orig_idx {
            let raw = view.raw_at(idx);
            let s = raw.trim();
            let comp = match s.rfind(['\\', '/']) {
                Some(pos) => &s[pos + 1..],
                None => s,
            };
            if !comp.is_empty() {
                discriminator_buf.clear();
                for b in comp.bytes() {
                    discriminator_buf.push(b.to_ascii_lowercase() as char);
                }
                let key = discriminator_buf.as_str();
                orig_file_base_buf.push_str(key);
                if image_base_buf.is_empty() {
                    image_base_buf.push_str(key);
                }
                if let Some(rules) = self.image_discriminator_index.get(key) {
                    for &r in rules {
                        candidate_mask.set(r as usize);
                    }
                }
                if let Some(rules) = self.process_discriminator_index.get(key) {
                    for &r in rules {
                        candidate_mask.set(r as usize);
                    }
                }
            }
        }

        // 4. ParentImage
        let pimg_idx = {
            let slot = view.canonical_slot(2);
            if slot != u32::MAX {
                Some(slot as usize)
            } else if (event_fields_mask & (1u64 << 2)) != 0 {
                view.first_index_for_folded_field("parentimage")
            } else {
                None
            }
        };
        if let Some(idx) = pimg_idx {
            let raw = view.raw_at(idx);
            let s = raw.trim();
            let comp = match s.rfind(['\\', '/']) {
                Some(pos) => &s[pos + 1..],
                None => s,
            };
            if !comp.is_empty() {
                discriminator_buf.clear();
                for b in comp.bytes() {
                    discriminator_buf.push(b.to_ascii_lowercase() as char);
                }
                let key = discriminator_buf.as_str();
                parent_image_base_buf.push_str(key);
                if let Some(rules) = self.parent_image_discriminator_index.get(key) {
                    for &r in rules {
                        candidate_mask.set(r as usize);
                    }
                }
                if let Some(rules) = self.process_discriminator_index.get(key) {
                    for &r in rules {
                        candidate_mask.set(r as usize);
                    }
                }
            }
        }

        // 5. ImageLoaded (slot 39)
        if !self.image_loaded_discriminator_index.is_empty() {
            let il_idx = {
                let slot = view.canonical_slot(39);
                if slot != u32::MAX {
                    Some(slot as usize)
                } else if (event_fields_mask & (1u64 << 39)) != 0 {
                    view.first_index_for_folded_field("imageloaded")
                } else {
                    None
                }
            };
            if let Some(idx) = il_idx {
                let raw = view.raw_at(idx);
                let s = raw.trim();
                let comp = match s.rfind(['\\', '/']) {
                    Some(pos) => &s[pos + 1..],
                    None => s,
                };
                if !comp.is_empty() {
                    discriminator_buf.clear();
                    for b in comp.bytes() {
                        discriminator_buf.push(b.to_ascii_lowercase() as char);
                    }
                    if let Some(rules) = self
                        .image_loaded_discriminator_index
                        .get(discriminator_buf.as_str())
                    {
                        for &r in rules {
                            candidate_mask.set(r as usize);
                        }
                    }
                }
            }
        }

        // 6. EventID
        if !self.event_id_discriminator_index.is_empty() {
            let eid_val = view
                .first_index_for_folded_field("eventid")
                .or_else(|| view.first_index_for_folded_field("event_id"))
                .and_then(|idx| parse_ascii_u32(view.raw_at(idx)));
            if let Some(eid) = eid_val {
                if let Some(rules) = self.event_id_discriminator_index.get(&eid) {
                    for &r in rules {
                        candidate_mask.set(r as usize);
                    }
                }
            }
        }

        // 7. PipeName (slot 28)
        if !self.pipe_name_discriminator_index.is_empty() {
            let pipe_idx = {
                let slot = view.canonical_slot(28);
                if slot != u32::MAX {
                    Some(slot as usize)
                } else if (event_fields_mask & (1u64 << 28)) != 0 {
                    view.first_index_for_folded_field("pipename")
                } else {
                    None
                }
            };
            if let Some(idx) = pipe_idx {
                let raw = view.raw_at(idx);
                let s = raw.trim();
                let comp = match s.rfind(['\\', '/']) {
                    Some(pos) => &s[pos + 1..],
                    None => s,
                };
                if !comp.is_empty() {
                    discriminator_buf.clear();
                    for b in comp.bytes() {
                        discriminator_buf.push(b.to_ascii_lowercase() as char);
                    }
                    if let Some(rules) = self
                        .pipe_name_discriminator_index
                        .get(discriminator_buf.as_str())
                    {
                        for &r in rules {
                            candidate_mask.set(r as usize);
                        }
                    }
                }
            }
        }

        // 8. QueryName (slot 27)
        if !self.query_name_discriminator_index.is_empty() {
            let qn_idx = {
                let slot = view.canonical_slot(27);
                if slot != u32::MAX {
                    Some(slot as usize)
                } else if (event_fields_mask & (1u64 << 27)) != 0 {
                    view.first_index_for_folded_field("queryname")
                } else {
                    None
                }
            };
            if let Some(idx) = qn_idx {
                let raw = view.raw_at(idx).trim();
                if !raw.is_empty() {
                    discriminator_buf.clear();
                    for b in raw.bytes() {
                        discriminator_buf.push(b.to_ascii_lowercase() as char);
                    }
                    if let Some(rules) = self
                        .query_name_discriminator_index
                        .get(discriminator_buf.as_str())
                    {
                        for &r in rules {
                            candidate_mask.set(r as usize);
                        }
                    }
                }
            }
        }

        // 9. TargetFilename (slot 18)
        if !self.target_filename_discriminator_index.is_empty() {
            let tfn_idx = {
                let slot = view.canonical_slot(18);
                if slot != u32::MAX {
                    Some(slot as usize)
                } else if (event_fields_mask & (1u64 << 18)) != 0 {
                    view.first_index_for_folded_field("targetfilename")
                } else {
                    None
                }
            };
            if let Some(idx) = tfn_idx {
                let raw = view.raw_at(idx);
                let s = raw.trim();
                let comp = match s.rfind(['\\', '/']) {
                    Some(pos) => &s[pos + 1..],
                    None => s,
                };
                if !comp.is_empty() {
                    discriminator_buf.clear();
                    for b in comp.bytes() {
                        discriminator_buf.push(b.to_ascii_lowercase() as char);
                    }
                    if let Some(rules) = self
                        .target_filename_discriminator_index
                        .get(discriminator_buf.as_str())
                    {
                        for &r in rules {
                            candidate_mask.set(r as usize);
                        }
                    }
                }
            }
        }

        // 9. Description (slot 16)
        if !self.description_discriminator_index.is_empty() {
            let desc_idx = {
                let slot = view.canonical_slot(16);
                if slot != u32::MAX {
                    Some(slot as usize)
                } else if (event_fields_mask & (1u64 << 16)) != 0 {
                    view.first_index_for_folded_field("description")
                } else {
                    None
                }
            };
            if let Some(idx) = desc_idx {
                let raw = view.raw_at(idx).trim();
                if !raw.is_empty() {
                    discriminator_buf.clear();
                    for b in raw.bytes() {
                        discriminator_buf.push(b.to_ascii_lowercase() as char);
                    }
                    if let Some(rules) = self
                        .description_discriminator_index
                        .get(discriminator_buf.as_str())
                    {
                        for &r in rules {
                            candidate_mask.set(r as usize);
                        }
                    }
                }
            }
        }

        // 10. Product (slot 15)
        if !self.product_discriminator_index.is_empty() {
            let prod_idx = {
                let slot = view.canonical_slot(15);
                if slot != u32::MAX {
                    Some(slot as usize)
                } else if (event_fields_mask & (1u64 << 15)) != 0 {
                    view.first_index_for_folded_field("product")
                } else {
                    None
                }
            };
            if let Some(idx) = prod_idx {
                let raw = view.raw_at(idx).trim();
                if !raw.is_empty() {
                    discriminator_buf.clear();
                    for b in raw.bytes() {
                        discriminator_buf.push(b.to_ascii_lowercase() as char);
                    }
                    if let Some(rules) = self
                        .product_discriminator_index
                        .get(discriminator_buf.as_str())
                    {
                        for &r in rules {
                            candidate_mask.set(r as usize);
                        }
                    }
                }
            }
        }

        // 11. Company (slot 14)
        if !self.company_discriminator_index.is_empty() {
            let comp_idx = {
                let slot = view.canonical_slot(14);
                if slot != u32::MAX {
                    Some(slot as usize)
                } else if (event_fields_mask & (1u64 << 14)) != 0 {
                    view.first_index_for_folded_field("company")
                } else {
                    None
                }
            };
            if let Some(idx) = comp_idx {
                let raw = view.raw_at(idx).trim();
                if !raw.is_empty() {
                    discriminator_buf.clear();
                    for b in raw.bytes() {
                        discriminator_buf.push(b.to_ascii_lowercase() as char);
                    }
                    if let Some(rules) = self
                        .company_discriminator_index
                        .get(discriminator_buf.as_str())
                    {
                        for &r in rules {
                            candidate_mask.set(r as usize);
                        }
                    }
                }
            }
        }
    }

    /// Returns `(candidates, passed_logsource, passed_fields, passed_bloom, passed_branches, passed_cold_logsource)` for diagnostic analysis.
    #[doc(hidden)]
    pub fn profile_candidate_funnel(
        &self,
        event: &HashMap<String, String>,
    ) -> (usize, usize, usize, usize, usize, usize) {
        EVAL_SCRATCH.with(|cell| {
            let mut scratch = cell.borrow_mut();
            let EvalScratch {
                candidate_mask,
                discriminator_buf,
                image_base_buf,
                parent_image_base_buf,
                orig_file_base_buf,
                event_scratch,
                ..
            } = &mut *scratch;

            image_base_buf.clear();
            parent_image_base_buf.clear();
            orig_file_base_buf.clear();

            let enriched = self.field_mapping.enrich_event_cow(event);
            let mut view = EventView::from_scratch_and_map(event_scratch, enriched.as_ref());
            let event_fields_mask = view.present_fields_mask();

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

            self.populate_candidate_mask(
                &mut view,
                event_fields_mask,
                event_cat_hash,
                event_prod_hash,
                event_svc_hash,
                discriminator_buf,
                image_base_buf,
                parent_image_base_buf,
                orig_file_base_buf,
                candidate_mask,
            );

            let mut candidates = 0usize;
            let mut passed_logsource = 0usize;
            let mut passed_fields = 0usize;
            let mut passed_bloom = 0usize;
            let mut passed_branches = 0usize;
            let mut passed_cold_logsource = 0usize;

            for rule_idx in candidate_mask.iter_set_bits() {
                candidates += 1;
                let hot = &self.hot_data[rule_idx];
                if !(logsource_ok(hot.cat_hash, event_cat_hash)
                    && logsource_ok(hot.prod_hash, event_prod_hash)
                    && logsource_ok(hot.svc_hash, event_svc_hash))
                {
                    continue;
                }
                passed_logsource += 1;

                if (hot.required_fields_mask & event_fields_mask) != hot.required_fields_mask {
                    continue;
                }
                passed_fields += 1;

                if hot.bloom_field != 255 && !hot.mandatory_bloom.is_empty() {
                    if (event_fields_mask & (1u64 << hot.bloom_field)) == 0 {
                        continue;
                    }
                    let slot = view.canonical_slot(hot.bloom_field);
                    if slot != u32::MAX {
                        view.ensure_bloom(slot as usize);
                        let field_bloom = view.bloom_at(slot as usize);
                        if !hot.mandatory_bloom.is_subset_of(&field_bloom) {
                            continue;
                        }
                    }
                }
                passed_bloom += 1;

                let feas = &self.rule_feasibility[rule_idx];
                if !feas.checks.is_empty() {
                    let mut possible_mask = 0u32;
                    for (bit, check) in feas.checks.iter().enumerate() {
                        if eval_branch_check(
                            check,
                            &mut view,
                            event_fields_mask,
                            image_base_buf.as_str(),
                            parent_image_base_buf.as_str(),
                            orig_file_base_buf.as_str(),
                        ) {
                            possible_mask |= 1 << bit;
                        }
                    }
                    if !rule_feasibility_passes(feas, possible_mask) {
                        continue;
                    }
                }
                passed_branches += 1;

                let compiled = &self.rules[rule_idx];
                if !compiled
                    .rule
                    .logsource
                    .matches(event_category, event_product, event_service)
                {
                    continue;
                }
                passed_cold_logsource += 1;
            }

            (
                candidates,
                passed_logsource,
                passed_fields,
                passed_bloom,
                passed_branches,
                passed_cold_logsource,
            )
        })
    }

    #[doc(hidden)]
    pub fn profile_surviving_rules(&self, event: &HashMap<String, String>) -> Vec<(u32, String)> {
        EVAL_SCRATCH.with(|cell| {
            let mut scratch = cell.borrow_mut();
            let EvalScratch {
                candidate_mask,
                discriminator_buf,
                image_base_buf,
                parent_image_base_buf,
                orig_file_base_buf,
                event_scratch,
                ..
            } = &mut *scratch;

            image_base_buf.clear();
            parent_image_base_buf.clear();
            orig_file_base_buf.clear();

            let enriched = self.field_mapping.enrich_event_cow(event);
            let mut view = EventView::from_scratch_and_map(event_scratch, enriched.as_ref());
            let event_fields_mask = view.present_fields_mask();

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

            self.populate_candidate_mask(
                &mut view,
                event_fields_mask,
                event_cat_hash,
                event_prod_hash,
                event_svc_hash,
                discriminator_buf,
                image_base_buf,
                parent_image_base_buf,
                orig_file_base_buf,
                candidate_mask,
            );

            let mut survivors = Vec::new();
            for rule_idx in candidate_mask.iter_set_bits() {
                let hot = &self.hot_data[rule_idx];
                if !(logsource_ok(hot.cat_hash, event_cat_hash)
                    && logsource_ok(hot.prod_hash, event_prod_hash)
                    && logsource_ok(hot.svc_hash, event_svc_hash))
                {
                    continue;
                }
                if (hot.required_fields_mask & event_fields_mask) != hot.required_fields_mask {
                    continue;
                }
                if hot.bloom_field != 255 && !hot.mandatory_bloom.is_empty() {
                    if (event_fields_mask & (1u64 << hot.bloom_field)) == 0 {
                        continue;
                    }
                    let slot = view.canonical_slot(hot.bloom_field);
                    if slot != u32::MAX {
                        view.ensure_bloom(slot as usize);
                        let field_bloom = view.bloom_at(slot as usize);
                        if !hot.mandatory_bloom.is_subset_of(&field_bloom) {
                            continue;
                        }
                    }
                }
                let feas = &self.rule_feasibility[rule_idx];
                if !feas.checks.is_empty() {
                    let mut possible_mask = 0u32;
                    for (bit, check) in feas.checks.iter().enumerate() {
                        if eval_branch_check(
                            check,
                            &mut view,
                            event_fields_mask,
                            image_base_buf.as_str(),
                            parent_image_base_buf.as_str(),
                            orig_file_base_buf.as_str(),
                        ) {
                            possible_mask |= 1 << bit;
                        }
                    }
                    if !rule_feasibility_passes(feas, possible_mask) {
                        continue;
                    }
                }
                survivors.push((rule_idx as u32, self.rules[rule_idx].rule.title.clone()));
            }
            survivors
        })
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
        let process_discriminators =
            if image_discriminators.is_none() && parent_image_discriminators.is_none() {
                crate::discriminator::compute_rule_process_discriminators(&conditions, &identifiers)
            } else {
                None
            };
        let multi_field_discriminators = if image_discriminators.is_none()
            && parent_image_discriminators.is_none()
            && process_discriminators.is_none()
        {
            crate::discriminator::compute_rule_multi_field_discriminators(&conditions, &identifiers)
        } else {
            None
        };
        let image_loaded_discriminators = if image_discriminators.is_none()
            && parent_image_discriminators.is_none()
            && process_discriminators.is_none()
            && multi_field_discriminators.is_none()
        {
            crate::discriminator::compute_rule_image_loaded_discriminators(
                &conditions,
                &identifiers,
            )
        } else {
            None
        };
        let event_id_discriminators = if image_discriminators.is_none()
            && parent_image_discriminators.is_none()
            && process_discriminators.is_none()
            && multi_field_discriminators.is_none()
            && image_loaded_discriminators.is_none()
        {
            crate::discriminator::compute_rule_event_id_discriminators(&conditions, &identifiers)
        } else {
            None
        };
        let pipe_name_discriminators = if image_discriminators.is_none()
            && parent_image_discriminators.is_none()
            && process_discriminators.is_none()
            && multi_field_discriminators.is_none()
            && image_loaded_discriminators.is_none()
            && event_id_discriminators.is_none()
        {
            crate::discriminator::compute_rule_pipe_name_discriminators(&conditions, &identifiers)
        } else {
            None
        };
        let query_name_discriminators = if image_discriminators.is_none()
            && parent_image_discriminators.is_none()
            && process_discriminators.is_none()
            && multi_field_discriminators.is_none()
            && image_loaded_discriminators.is_none()
            && event_id_discriminators.is_none()
            && pipe_name_discriminators.is_none()
        {
            crate::discriminator::compute_rule_query_name_discriminators(&conditions, &identifiers)
        } else {
            None
        };
        let target_filename_discriminators = if image_discriminators.is_none()
            && parent_image_discriminators.is_none()
            && process_discriminators.is_none()
            && multi_field_discriminators.is_none()
            && image_loaded_discriminators.is_none()
            && event_id_discriminators.is_none()
            && pipe_name_discriminators.is_none()
            && query_name_discriminators.is_none()
        {
            crate::discriminator::compute_rule_target_filename_discriminators(
                &conditions,
                &identifiers,
            )
        } else {
            None
        };
        let (bloom_field, mandatory_bloom) =
            crate::discriminator::compute_rule_mandatory_bloom(&conditions, &identifiers);
        let feasibility = crate::discriminator::compute_rule_feasibility(&conditions, &identifiers);

        let ident_index: HashMap<String, usize> = identifiers
            .iter()
            .enumerate()
            .map(|(idx, ident)| (ident.name.clone(), idx))
            .collect();

        let resolved_conditions: Vec<ResolvedConditionNode> = conditions
            .iter()
            .filter_map(|c| c.resolve_indices(&ident_index))
            .collect();

        let condition = if resolved_conditions.len() == 1 {
            if let Some(ResolvedConditionNode::Identifier(idx)) = resolved_conditions.first() {
                CompiledCondition::Single(*idx)
            } else {
                CompiledCondition::Tape(DecisionTape::compile(&resolved_conditions[0]))
            }
        } else {
            CompiledCondition::MultiTape(
                resolved_conditions
                    .iter()
                    .map(DecisionTape::compile)
                    .collect(),
            )
        };

        self.rules.push(CompiledRule {
            rule,
            identifiers,
            condition,
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
            bloom_field,
            _pad: [0; 11],
            mandatory_bloom,
        });
        self.rule_feasibility.push(feasibility);

        let rule_idx = self.rules.len() - 1;
        let rule_idx_u32 = u32::try_from(rule_idx).expect("rule count fits in u32");
        if let Some(basenames) = image_discriminators {
            for base in basenames {
                self.image_discriminator_index
                    .entry(base)
                    .or_default()
                    .push(rule_idx_u32);
            }
        } else if let Some(basenames) = parent_image_discriminators {
            for base in basenames {
                self.parent_image_discriminator_index
                    .entry(base)
                    .or_default()
                    .push(rule_idx_u32);
            }
        } else if let Some(basenames) = process_discriminators {
            for base in basenames {
                self.process_discriminator_index
                    .entry(base)
                    .or_default()
                    .push(rule_idx_u32);
            }
        } else if let Some(discs) = multi_field_discriminators {
            for disc in discs {
                match disc {
                    crate::discriminator::MultiFieldDiscriminator::Image(base) => {
                        self.image_discriminator_index
                            .entry(base)
                            .or_default()
                            .push(rule_idx_u32);
                    }
                    crate::discriminator::MultiFieldDiscriminator::ParentImage(base) => {
                        self.parent_image_discriminator_index
                            .entry(base)
                            .or_default()
                            .push(rule_idx_u32);
                    }
                    crate::discriminator::MultiFieldDiscriminator::Description(desc) => {
                        self.description_discriminator_index
                            .entry(desc)
                            .or_default()
                            .push(rule_idx_u32);
                    }
                    crate::discriminator::MultiFieldDiscriminator::Product(prod) => {
                        self.product_discriminator_index
                            .entry(prod)
                            .or_default()
                            .push(rule_idx_u32);
                    }
                    crate::discriminator::MultiFieldDiscriminator::Company(comp) => {
                        self.company_discriminator_index
                            .entry(comp)
                            .or_default()
                            .push(rule_idx_u32);
                    }
                }
            }
        } else if let Some(basenames) = image_loaded_discriminators {
            for base in basenames {
                self.image_loaded_discriminator_index
                    .entry(base)
                    .or_default()
                    .push(rule_idx_u32);
            }
        } else if let Some(eids) = event_id_discriminators {
            for eid in eids {
                self.event_id_discriminator_index
                    .entry(eid)
                    .or_default()
                    .push(rule_idx_u32);
            }
        } else if let Some(pipes) = pipe_name_discriminators {
            for pipe in pipes {
                self.pipe_name_discriminator_index
                    .entry(pipe)
                    .or_default()
                    .push(rule_idx_u32);
            }
        } else if let Some(queries) = query_name_discriminators {
            for query in queries {
                self.query_name_discriminator_index
                    .entry(query)
                    .or_default()
                    .push(rule_idx_u32);
            }
        } else if let Some(files) = target_filename_discriminators {
            for file in files {
                self.target_filename_discriminator_index
                    .entry(file)
                    .or_default()
                    .push(rule_idx_u32);
            }
        } else {
            self.unconstrained_mask.set(rule_idx);
            if cat_hash == 0 && prod_hash == 0 && svc_hash == 0 {
                self.wildcard_unconstrained.set(rule_idx);
            } else {
                if cat_hash != 0 {
                    self.category_unconstrained
                        .entry(cat_hash)
                        .or_default()
                        .set(rule_idx);
                }
                if svc_hash != 0 {
                    self.service_unconstrained
                        .entry(svc_hash)
                        .or_default()
                        .set(rule_idx);
                }
                if prod_hash != 0 && cat_hash == 0 && svc_hash == 0 {
                    self.product_unconstrained
                        .entry(prod_hash)
                        .or_default()
                        .set(rule_idx);
                }
            }
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
    pub fn evaluate_event<'a>(&'a self, event: &HashMap<String, String>) -> Vec<RuleMatch<'a>> {
        let mut matches = Vec::new();
        self.evaluate_event_into(event, &mut matches);
        matches
    }

    /// Evaluate a single event against all loaded rules, appending detections into an existing vector.
    ///
    /// This avoids vector allocation when reused across a hot evaluation loop,
    /// borrowing strings and metadata directly from the engine with zero allocations.
    pub fn evaluate_event_into<'a>(
        &'a self,
        event: &HashMap<String, String>,
        matches: &mut Vec<RuleMatch<'a>>,
    ) {
        EVAL_SCRATCH.with(|cell| {
            let mut scratch = cell.borrow_mut();
            self.evaluate_event_inner(
                event,
                false,
                &mut scratch,
                &mut |compiled, _id_results, _matched_conditions| {
                    matches.push(RuleMatch {
                        rule_id: &compiled.rule.id,
                        rule_title: &compiled.rule.title,
                        rule_level: compiled.rule.level,
                        tags: &compiled.rule.tags,
                        score: compiled.rule.level.to_score(),
                    });
                },
            );
        });
    }

    /// Shared single-event evaluation loop.
    ///
    /// When `collect_details` is false, skips `matched_conditions` accumulation
    /// and never invokes `on_match`.
    #[allow(clippy::type_complexity)]
    fn evaluate_event_inner<'a>(
        &'a self,
        event: &HashMap<String, String>,
        collect_details: bool,
        scratch: &mut EvalScratch,
        on_match: &mut dyn FnMut(&'a CompiledRule, &[bool], &[usize]),
    ) -> usize {
        let EvalScratch {
            id_results,
            id_state,
            candidate_mask,
            discriminator_buf,
            image_base_buf,
            parent_image_base_buf,
            orig_file_base_buf,
            event_scratch,
            matched_conditions,
        } = scratch;

        image_base_buf.clear();
        parent_image_base_buf.clear();
        orig_file_base_buf.clear();

        // Enrich the event with Sigma-canonical field names so rules can
        // match regardless of naming convention.
        // `enrich_event_cow` returns `Borrowed` (zero allocation) when the
        // event already uses Sigma field names, `Owned` only when application
        // canonical names are present and aliases need to be added.
        let enriched = self.field_mapping.enrich_event_cow(event);
        let mut view = EventView::from_scratch_and_map(event_scratch, enriched.as_ref());
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

        self.populate_candidate_mask(
            &mut view,
            event_fields_mask,
            event_cat_hash,
            event_prod_hash,
            event_svc_hash,
            discriminator_buf,
            image_base_buf,
            parent_image_base_buf,
            orig_file_base_buf,
            candidate_mask,
        );

        for rule_idx in candidate_mask.iter_set_bits() {
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

            // Mandatory Needle Bloom Filter: 4-instruction bitwise subset rejection
            if hot.bloom_field != 255 && !hot.mandatory_bloom.is_empty() {
                if (event_fields_mask & (1u64 << hot.bloom_field)) == 0 {
                    continue;
                }
                let slot = view.canonical_slot(hot.bloom_field);
                if slot != u32::MAX {
                    view.ensure_bloom(slot as usize);
                    let field_bloom = view.bloom_at(slot as usize);
                    if !hot.mandatory_bloom.is_subset_of(&field_bloom) {
                        continue;
                    }
                }
            }

            // Branch Feasibility Filter: skip rules where all positive branches are impossible
            let feas = &self.rule_feasibility[rule_idx];
            if !feas.checks.is_empty() {
                let mut possible_mask = 0u32;
                for (bit, check) in feas.checks.iter().enumerate() {
                    if eval_branch_check(
                        check,
                        &mut view,
                        event_fields_mask,
                        image_base_buf.as_str(),
                        parent_image_base_buf.as_str(),
                        orig_file_base_buf.as_str(),
                    ) {
                        possible_mask |= 1 << bit;
                    }
                }
                if !rule_feasibility_passes(feas, possible_mask) {
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

            // Lazy condition evaluation:
            // Evaluates identifiers on demand with caching, short-circuiting as soon
            // as boolean AST branches (AND/OR) are determined.
            if collect_details {
                match &compiled.condition {
                    CompiledCondition::Single(idx) => {
                        let matched = if compiled.has_regex {
                            match_identifier_with_cache_on_view(
                                &compiled.identifiers[*idx],
                                &mut view,
                                &self.rule_regex_maps[rule_idx],
                            )
                        } else {
                            match_identifier_on_view(&compiled.identifiers[*idx], &mut view)
                        };

                        if matched {
                            matches += 1;
                            EvalScratch::reset_vec_state(id_state, compiled.identifiers.len());
                            id_state[*idx] = 2;
                            EvalScratch::reset_vec_results(id_results, compiled.identifiers.len());
                            for i in 0..compiled.identifiers.len() {
                                id_results[i] = id_state[i] == 2;
                            }
                            on_match(compiled, id_results, &[0]);
                        }
                    }
                    CompiledCondition::Tape(tape) => {
                        EvalScratch::reset_vec_state(id_state, compiled.identifiers.len());
                        matched_conditions.clear();

                        {
                            let mut eval_ident = |idx: usize| -> bool {
                                let cached = id_state[idx];
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
                                        match_identifier_on_view(
                                            &compiled.identifiers[idx],
                                            &mut view,
                                        )
                                    };
                                    id_state[idx] = if res { 2 } else { 1 };
                                    res
                                }
                            };

                            if tape.evaluate(&mut eval_ident) {
                                matched_conditions.push(0);
                                // For matching rules only, ensure any remaining identifiers are evaluated
                                // so RuleMatch details contain all matched identifiers.
                                for idx in 0..compiled.identifiers.len() {
                                    let _ = eval_ident(idx);
                                }
                            }
                        }

                        if !matched_conditions.is_empty() {
                            matches += 1;
                            EvalScratch::reset_vec_results(id_results, compiled.identifiers.len());
                            for idx in 0..compiled.identifiers.len() {
                                id_results[idx] = id_state[idx] == 2;
                            }
                            on_match(compiled, id_results, matched_conditions);
                        }
                    }
                    CompiledCondition::MultiTape(tapes) => {
                        EvalScratch::reset_vec_state(id_state, compiled.identifiers.len());
                        matched_conditions.clear();

                        {
                            let mut eval_ident = |idx: usize| -> bool {
                                let cached = id_state[idx];
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
                                        match_identifier_on_view(
                                            &compiled.identifiers[idx],
                                            &mut view,
                                        )
                                    };
                                    id_state[idx] = if res { 2 } else { 1 };
                                    res
                                }
                            };

                            for (cond_idx, tape) in tapes.iter().enumerate() {
                                if tape.evaluate(&mut eval_ident) {
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
                            EvalScratch::reset_vec_results(id_results, compiled.identifiers.len());
                            for idx in 0..compiled.identifiers.len() {
                                id_results[idx] = id_state[idx] == 2;
                            }
                            on_match(compiled, id_results, matched_conditions);
                        }
                    }
                }
            } else {
                let rule_matched = match &compiled.condition {
                    CompiledCondition::Single(idx) => {
                        if compiled.has_regex {
                            match_identifier_with_cache_on_view(
                                &compiled.identifiers[*idx],
                                &mut view,
                                &self.rule_regex_maps[rule_idx],
                            )
                        } else {
                            match_identifier_on_view(&compiled.identifiers[*idx], &mut view)
                        }
                    }
                    CompiledCondition::Tape(tape) => {
                        EvalScratch::reset_vec_state(id_state, compiled.identifiers.len());
                        let mut eval_ident = |idx: usize| -> bool {
                            let cached = id_state[idx];
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
                                id_state[idx] = if res { 2 } else { 1 };
                                res
                            }
                        };

                        tape.evaluate(&mut eval_ident)
                    }
                    CompiledCondition::MultiTape(tapes) => {
                        EvalScratch::reset_vec_state(id_state, compiled.identifiers.len());
                        let mut eval_ident = |idx: usize| -> bool {
                            let cached = id_state[idx];
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
                                id_state[idx] = if res { 2 } else { 1 };
                                res
                            }
                        };

                        tapes.iter().any(|t| t.evaluate(&mut eval_ident))
                    }
                };

                if rule_matched {
                    matches += 1;
                    on_match(compiled, &[], &[]);
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
    pub fn evaluate_batch<'a>(&'a self, events: &[HashMap<String, String>]) -> Vec<EvalResult<'a>> {
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
                if cond.modifiers.iter().any(ValueModifier::is_transform) {
                    let transformed =
                        crate::matcher::apply_transforms(&cond.values, &cond.modifiers);
                    cond.values = transformed.into_owned();
                    cond.modifiers.retain(|m| !m.is_transform());
                }
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
                    .zip(cond.values.iter())
                    .map(|(folded, val)| {
                        if cond.modifiers.contains(&ValueModifier::Regex) {
                            let mut vmc = ValueMatchCache::default();
                            let pat = val.as_str_lossy();
                            let full =
                                crate::matcher::regex_pattern_with_flags(&pat, &cond.modifiers);
                            if let Ok(re) = regex::Regex::new(&full) {
                                vmc.regex = Some(re);
                            }
                            vmc
                        } else if cond.modifiers.iter().any(ValueModifier::is_transform) {
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

                // Information-Theoretic Literal Ordering: For conjunctions (|all),
                // test the longest / most selective value first to short-circuit immediately.
                if cond.require_all && cond.values.len() > 1 {
                    let mut zipped: Vec<_> = cond
                        .values
                        .drain(..)
                        .zip(cond.values_folded.drain(..))
                        .zip(cond.values_match_cache.drain(..))
                        .map(|((v, vf), vmc)| (v, vf, vmc))
                        .collect();
                    zipped.sort_by(|a, b| {
                        let len_a = a.1.as_deref().map_or(0, str::len);
                        let len_b = b.1.as_deref().map_or(0, str::len);
                        len_b.cmp(&len_a)
                    });
                    for (v, vf, vmc) in zipped {
                        cond.values.push(v);
                        cond.values_folded.push(vf);
                        cond.values_match_cache.push(vmc);
                    }
                }
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
    fn rule_hot_data_size_is_64_bytes_cacheline() {
        assert_eq!(
            std::mem::size_of::<RuleHotData>(),
            64,
            "RuleHotData must remain exactly 64 bytes (1 cache line) for optimal memory density"
        );
        assert_eq!(
            std::mem::align_of::<RuleHotData>(),
            64,
            "RuleHotData must be aligned to 64 bytes to eliminate cache line splits"
        );
    }
}
