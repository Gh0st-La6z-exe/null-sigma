// =============================================================================
// NuLLAI Sigma Rule Engine — Core Types
// =============================================================================
// These types represent the parsed Sigma rule structure. They closely follow
// the Sigma specification (https://sigmahq.io/docs/basics/rules.html) while
// being optimized for Rust's type system.
//
// KEY DESIGN DECISIONS:
// - All string fields own their data (String, not &str) because rules live
//   in memory for the lifetime of the engine. No borrow complexity.
// - Enums have FromStr/Display for YAML serde and Python bridge.
// - Detection values are typed (String, Integer, Float, Boolean, Null, List)
//   because Sigma conditions can compare against any type.
// =============================================================================

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// Sigma Rule — Top-level structure
// ─────────────────────────────────────────────────────────────────────────────

/// A fully parsed Sigma detection rule.
///
/// Sigma rules are the industry standard for generic log detection rules,
/// supported by 100+ SIEM platforms. Each rule describes:
///   - WHAT to detect (detection block with field conditions)
///   - WHERE to look (logsource: category, product, service)
///   - HOW SERIOUS it is (level + status)
///   - WHO wrote it and WHY (metadata)
///
/// Example Sigma rule (YAML):
/// ```yaml
/// title: Suspicious PowerShell Encoded Command
/// status: stable
/// level: high
/// logsource:
///     category: process_creation
///     product: windows
/// detection:
///     selection:
///         CommandLine|contains:
///             - '-enc '
///             - '-encodedcommand '
///         Image|endswith: '\powershell.exe'
///     condition: selection
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaRule {
    /// Unique identifier for this rule (UUID format recommended by spec).
    /// If not provided in YAML, we generate one from the title hash.
    #[serde(default)]
    pub id: String,

    /// Human-readable rule title. REQUIRED by Sigma spec.
    pub title: String,

    /// Detailed description of what this rule detects and why.
    #[serde(default)]
    pub description: String,

    /// Rule maturity status (experimental → test → stable → deprecated).
    #[serde(default)]
    pub status: RuleStatus,

    /// Severity level of the detection.
    #[serde(default)]
    pub level: SeverityLevel,

    /// Rule author(s).
    #[serde(default)]
    pub author: String,

    /// Creation/modification date (free-form string, e.g., "2024/01/15").
    #[serde(default)]
    pub date: String,

    /// Last modification date.
    #[serde(default)]
    pub modified: String,

    /// External references (URLs to blog posts, advisories, etc.).
    #[serde(default)]
    pub references: Vec<String>,

    /// MITRE ATT&CK tags (e.g., "attack.execution", "attack.t1059.001").
    #[serde(default)]
    pub tags: Vec<String>,

    /// Log source specification — WHERE to apply this rule.
    pub logsource: LogSource,

    /// Detection logic — WHAT to look for. Contains named search identifiers
    /// and a condition expression that combines them.
    pub detection: Detection,

    /// False positive guidance — known scenarios that trigger this rule benignly.
    #[serde(default, alias = "falsepositives")]
    pub falsepositives: Vec<String>,

    /// Custom fields that don't map to standard Sigma fields.
    /// Preserved for round-tripping and custom metadata.
    #[serde(flatten)]
    pub custom_fields: HashMap<String, serde_yaml::Value>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Log Source — WHERE to apply the rule
// ─────────────────────────────────────────────────────────────────────────────

/// Sigma logsource specification. Determines which log stream a rule applies to.
///
/// The logsource acts as a pre-filter: before evaluating detection conditions,
/// we check if the event's source matches. This is critical for performance —
/// a Windows Sysmon rule should never be evaluated against Linux auditd events.
///
/// Common categories:
///   - process_creation: New process started (Sysmon EID 1)
///   - network_connection: Outbound connection (Sysmon EID 3)
///   - file_event: File creation/modification (Sysmon EID 11)
///   - registry_event: Registry key/value changes (Sysmon EID 12-14)
///   - dns_query: DNS resolution (Sysmon EID 22)
///   - image_load: DLL/module loaded (Sysmon EID 7)
///   - pipe_created: Named pipe created (Sysmon EID 17)
///   - wmi_event: WMI activity (Sysmon EID 19-21)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogSource {
    /// Abstract log category (e.g., "process_creation", "network_connection").
    #[serde(default)]
    pub category: Option<String>,

    /// Product generating the logs (e.g., "windows", "linux", "macos").
    #[serde(default)]
    pub product: Option<String>,

    /// Specific service or log channel (e.g., "sysmon", "security", "auditd").
    #[serde(default)]
    pub service: Option<String>,
}

impl LogSource {
    /// Check if this logsource matches an event's metadata.
    /// None fields are treated as wildcards (match anything).
    pub fn matches(&self, event_category: Option<&str>, event_product: Option<&str>, event_service: Option<&str>) -> bool {
        let cat_ok = self.category.as_ref().map_or(true, |c| {
            event_category.is_some_and(|ec| ec.eq_ignore_ascii_case(c))
        });
        let prod_ok = self.product.as_ref().map_or(true, |p| {
            event_product.is_some_and(|ep| ep.eq_ignore_ascii_case(p))
        });
        let svc_ok = self.service.as_ref().map_or(true, |s| {
            event_service.is_some_and(|es| es.eq_ignore_ascii_case(s))
        });
        cat_ok && prod_ok && svc_ok
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Detection — WHAT to look for
// ─────────────────────────────────────────────────────────────────────────────

/// The detection block of a Sigma rule.
///
/// Contains named "search identifiers" (e.g., `selection`, `filter`) and a
/// `condition` expression that combines them with boolean logic.
///
/// The condition language supports:
///   - Identifier references: `selection`, `filter`
///   - Boolean operators: `and`, `or`, `not`
///   - Grouping: `( ... )`
///   - Quantifiers: `1 of selection*`, `all of them`, `1 of them`
///   - Pipe aggregation: `| count() > 5` (future)
///
/// Example detection block:
/// ```yaml
/// detection:
///     selection_process:
///         Image|endswith: '\powershell.exe'
///     selection_cmdline:
///         CommandLine|contains:
///             - '-enc '
///             - '-encodedcommand '
///     filter:
///         User: 'SYSTEM'
///     condition: (selection_process and selection_cmdline) and not filter
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    /// The condition expression string (e.g., "selection and not filter").
    pub condition: ConditionExpr,

    /// Named search identifiers mapped to their field conditions.
    /// Keys are identifier names (e.g., "selection", "filter").
    /// Values are lists of field matchers (OR within a list item, AND across fields).
    #[serde(flatten)]
    pub identifiers: HashMap<String, serde_yaml::Value>,
}

/// Condition can be a single string or a list of strings (multiple conditions).
/// When a list, each condition produces a separate detection — the rule fires
/// if ANY condition matches.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ConditionExpr {
    Single(String),
    Multiple(Vec<String>),
}

impl ConditionExpr {
    /// Get all condition strings as a slice-compatible iterator.
    pub fn conditions(&self) -> Vec<&str> {
        match self {
            ConditionExpr::Single(s) => vec![s.as_str()],
            ConditionExpr::Multiple(v) => v.iter().map(|s| s.as_str()).collect(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Search Identifier — Parsed field conditions
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed search identifier from the detection block.
///
/// A search identifier is a named set of field conditions. It can be:
///   - A map of field → value(s) (most common)
///   - A list of maps (OR across list items, AND within each map)
///
/// Field names can have modifiers appended with `|`:
///   - `CommandLine|contains` — substring match
///   - `Image|endswith` — suffix match
///   - `Image|startswith` — prefix match
///   - `CommandLine|re` — regex match
///   - `TargetFilename|contains|all` — ALL values must be substrings
///   - `Hashes|contains` — hash substring (for multi-hash fields)
///   - `field|base64` — value is base64-decoded before comparison
///   - `field|base64offset` — value at base64 boundary offsets
///   - `field|windash` — Windows dash variants (-, /)
///   - `field|wide` — UTF-16LE encoding
///   - `field|cidr` — CIDR IP range match
///   - `field|exists` — field exists (true) or doesn't (false)
///   - `field|gt`, `field|gte`, `field|lt`, `field|lte` — numeric comparison
#[derive(Debug, Clone)]
pub struct SearchIdentifier {
    /// The name of this identifier (e.g., "selection", "filter").
    pub name: String,

    /// List of field condition groups. Within a group, all conditions must match
    /// (AND). Across groups, any group matching is sufficient (OR).
    pub groups: Vec<FieldConditionGroup>,
}

/// A group of field conditions that are ANDed together.
/// A SearchIdentifier with multiple groups represents an OR:
///   group[0] AND-internal OR group[1] AND-internal OR ...
#[derive(Debug, Clone)]
pub struct FieldConditionGroup {
    pub conditions: Vec<FieldCondition>,
}

/// A single field condition: "does field X match value Y with modifier Z?"
#[derive(Debug, Clone)]
pub struct FieldCondition {
    /// The field name to check (e.g., "CommandLine", "Image").
    pub field: String,

    /// Value(s) to match against. Multiple values are OR'd by default,
    /// unless the `all` modifier is set.
    pub values: Vec<SigmaValue>,

    /// Modifiers applied to this field check.
    pub modifiers: Vec<ValueModifier>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Sigma Values — What to match against
// ─────────────────────────────────────────────────────────────────────────────

/// A typed value from a Sigma rule. Sigma YAML can contain strings, integers,
/// floats, booleans, null, or wildcards (strings with * or ?).
#[derive(Debug, Clone, PartialEq)]
pub enum SigmaValue {
    /// String value — may contain wildcards (* = any chars, ? = single char).
    String(String),

    /// Integer value (for numeric comparisons like `|gt`, `|lt`).
    Integer(i64),

    /// Float value.
    Float(f64),

    /// Boolean value (true/false).
    Boolean(bool),

    /// Null — field must not exist or be empty.
    Null,
}

impl SigmaValue {
    /// Convert to a string representation for pattern matching.
    pub fn as_str_lossy(&self) -> String {
        match self {
            SigmaValue::String(s) => s.clone(),
            SigmaValue::Integer(i) => i.to_string(),
            SigmaValue::Float(f) => f.to_string(),
            SigmaValue::Boolean(b) => b.to_string(),
            SigmaValue::Null => String::new(),
        }
    }

    /// Check if this value contains wildcards (* or ?).
    pub fn has_wildcards(&self) -> bool {
        match self {
            SigmaValue::String(s) => s.contains('*') || s.contains('?'),
            _ => false,
        }
    }

    /// Parse a serde_yaml::Value into a SigmaValue.
    pub fn from_yaml(value: &serde_yaml::Value) -> Self {
        match value {
            serde_yaml::Value::String(s) => SigmaValue::String(s.clone()),
            serde_yaml::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    SigmaValue::Integer(i)
                } else if let Some(f) = n.as_f64() {
                    SigmaValue::Float(f)
                } else {
                    SigmaValue::String(n.to_string())
                }
            }
            serde_yaml::Value::Bool(b) => SigmaValue::Boolean(*b),
            serde_yaml::Value::Null => SigmaValue::Null,
            // Sequences and mappings shouldn't appear as leaf values,
            // but handle gracefully
            _ => SigmaValue::String(format!("{value:?}")),
        }
    }
}

impl fmt::Display for SigmaValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SigmaValue::String(s) => write!(f, "{s}"),
            SigmaValue::Integer(i) => write!(f, "{i}"),
            SigmaValue::Float(v) => write!(f, "{v}"),
            SigmaValue::Boolean(b) => write!(f, "{b}"),
            SigmaValue::Null => write!(f, "null"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Value Modifiers — HOW to match
// ─────────────────────────────────────────────────────────────────────────────

/// Sigma value modifiers control how field values are compared.
///
/// Modifiers are appended to field names with `|` in the YAML:
///   `CommandLine|contains|all` → Contains modifier + All modifier
///
/// The order matters:
///   1. Transformation modifiers (base64, wide, windash) transform the VALUE
///   2. Match modifiers (contains, endswith, startswith, re, cidr) control HOW to compare
///   3. The `all` modifier changes OR (any value matches) to AND (all values must match)
///   4. Comparison modifiers (gt, gte, lt, lte) for numeric fields
///   5. The `exists` modifier checks field presence, not value
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ValueModifier {
    // ── Match modifiers ──
    /// Substring match (case-insensitive by default in Sigma).
    Contains,
    /// Field value ends with this string.
    EndsWith,
    /// Field value starts with this string.
    StartsWith,
    /// Full regex match.
    Regex,
    /// CIDR IP range match (e.g., "10.0.0.0/8").
    Cidr,

    // ── Quantifier modifiers ──
    /// ALL values must match (default is ANY).
    All,

    // ── Transformation modifiers ──
    /// Base64-encode the value before matching (for obfuscated payloads).
    Base64,
    /// Base64 with offset variants (matches at 0, 1, 2 byte offsets).
    Base64Offset,
    /// UTF-16LE encoding (Windows "wide" strings).
    Wide,
    /// Windows dash normalization: `-` also matches `/` (common evasion).
    Windash,

    // ── Comparison modifiers ──
    /// Greater than (numeric).
    Gt,
    /// Greater than or equal (numeric).
    Gte,
    /// Less than (numeric).
    Lt,
    /// Less than or equal (numeric).
    Lte,

    // ── Existence modifier ──
    /// Check if field exists (true) or doesn't (false).
    Exists,
}

impl ValueModifier {
    /// Parse a modifier string from the field name.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "contains" => Some(ValueModifier::Contains),
            "endswith" => Some(ValueModifier::EndsWith),
            "startswith" => Some(ValueModifier::StartsWith),
            "re" => Some(ValueModifier::Regex),
            "cidr" => Some(ValueModifier::Cidr),
            "all" => Some(ValueModifier::All),
            "base64" => Some(ValueModifier::Base64),
            "base64offset" => Some(ValueModifier::Base64Offset),
            "wide" => Some(ValueModifier::Wide),
            "windash" => Some(ValueModifier::Windash),
            "gt" => Some(ValueModifier::Gt),
            "gte" => Some(ValueModifier::Gte),
            "lt" => Some(ValueModifier::Lt),
            "lte" => Some(ValueModifier::Lte),
            "exists" => Some(ValueModifier::Exists),
            _ => None,
        }
    }

    /// Check if this is a transformation modifier (applied to the VALUE before matching).
    pub fn is_transform(&self) -> bool {
        matches!(self, ValueModifier::Base64 | ValueModifier::Base64Offset | ValueModifier::Wide | ValueModifier::Windash)
    }

    /// Check if this is a match modifier (controls HOW the comparison works).
    pub fn is_match_type(&self) -> bool {
        matches!(self, ValueModifier::Contains | ValueModifier::EndsWith | ValueModifier::StartsWith | ValueModifier::Regex | ValueModifier::Cidr)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Enums — Rule metadata
// ─────────────────────────────────────────────────────────────────────────────

/// Sigma rule severity level.
///
/// Maps directly to incident response priority:
///   - Critical: Immediate automated response (NuLLAI Brain autonomous action)
///   - High: Alert + analyst notification within minutes
///   - Medium: Standard alert queue
///   - Low: Informational, correlation enrichment
///   - Informational: Context only, no alert
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SeverityLevel {
    Informational,
    Low,
    #[default]
    Medium,
    High,
    Critical,
}

impl SeverityLevel {
    /// Convert to a numeric score (0.0 - 1.0) for NuLLAI threat scoring.
    pub fn to_score(&self) -> f64 {
        match self {
            SeverityLevel::Informational => 0.1,
            SeverityLevel::Low => 0.3,
            SeverityLevel::Medium => 0.5,
            SeverityLevel::High => 0.7,
            SeverityLevel::Critical => 0.9,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SeverityLevel::Informational => "informational",
            SeverityLevel::Low => "low",
            SeverityLevel::Medium => "medium",
            SeverityLevel::High => "high",
            SeverityLevel::Critical => "critical",
        }
    }
}

impl fmt::Display for SeverityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Sigma rule maturity status.
///
/// Rules progress through: experimental → test → stable
/// Deprecated rules should not be used but are kept for reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RuleStatus {
    /// New rule, may have false positives. Use with caution.
    Experimental,
    /// Tested in production, some tuning may be needed.
    #[default]
    Test,
    /// Production-ready, low false positive rate.
    Stable,
    /// No longer recommended, kept for historical reference.
    Deprecated,
    /// Not officially part of Sigma spec but used by some rule sets.
    Unsupported,
}

impl RuleStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            RuleStatus::Experimental => "experimental",
            RuleStatus::Test => "test",
            RuleStatus::Stable => "stable",
            RuleStatus::Deprecated => "deprecated",
            RuleStatus::Unsupported => "unsupported",
        }
    }
}

impl fmt::Display for RuleStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Match Result — Output from the engine
// ─────────────────────────────────────────────────────────────────────────────

/// Result of evaluating a single event against a single rule.
#[derive(Debug, Clone)]
pub struct RuleMatch {
    /// The rule that matched.
    pub rule_id: String,
    pub rule_title: String,
    pub rule_level: SeverityLevel,

    /// Which condition(s) matched (index into ConditionExpr::Multiple).
    pub matched_conditions: Vec<usize>,

    /// Which search identifiers evaluated to true.
    pub matched_identifiers: Vec<String>,

    /// MITRE ATT&CK tags from the rule.
    pub tags: Vec<String>,

    /// Numeric threat score derived from rule level.
    pub score: f64,
}

/// Result of evaluating a single event against the full rule set.
#[derive(Debug, Clone)]
pub struct EvalResult {
    /// Index of the event in the input batch.
    pub event_index: usize,

    /// All rules that matched this event.
    pub matches: Vec<RuleMatch>,

    /// Total number of rules evaluated (for stats).
    pub rules_evaluated: usize,
}
