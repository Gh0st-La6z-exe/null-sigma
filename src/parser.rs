// =============================================================================
// Sigma Rule Engine — YAML Parser
// =============================================================================
// Parses Sigma rule YAML into typed SigmaRule structs with full validation.
//
// The parser handles:
//   1. Standard YAML deserialization via serde_yaml
//   2. Detection block parsing: named identifiers → FieldConditions
//   3. Field modifier extraction (CommandLine|contains|all → field + modifiers)
//   4. Value normalization (YAML strings, ints, floats, bools, null, lists)
//   5. ID generation for rules without explicit IDs
//
// Error handling is explicit — we return descriptive ParseError variants
// rather than panicking. A malformed rule should NEVER crash the engine.
// =============================================================================

use crate::types::{
    SigmaRule, SearchIdentifier, Detection, SigmaValue,
    FieldConditionGroup, FieldCondition, ValueModifier, ConditionExpr,
};

// ─────────────────────────────────────────────────────────────────────────────
// Parse Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors that can occur during Sigma rule parsing.
#[derive(Debug, Clone)]
pub enum ParseError {
    /// YAML syntax error (invalid YAML).
    YamlError(String),
    /// Missing required field in the rule.
    MissingField(String),
    /// Invalid field modifier.
    InvalidModifier {
        /// The field name that carries the invalid modifier.
        field: String,
        /// The modifier token that was not recognised (e.g. `"typo"`).
        modifier: String,
    },
    /// Empty detection block.
    EmptyDetection,
    /// Invalid condition expression.
    InvalidCondition(String),
    /// Generic validation error.
    ValidationError(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::YamlError(e) => write!(f, "YAML parse error: {e}"),
            ParseError::MissingField(field) => write!(f, "Missing required field: {field}"),
            ParseError::InvalidModifier { field, modifier } => {
                write!(f, "Invalid modifier '{modifier}' on field '{field}'")
            }
            ParseError::EmptyDetection => write!(f, "Detection block is empty"),
            ParseError::InvalidCondition(c) => write!(f, "Invalid condition: {c}"),
            ParseError::ValidationError(e) => write!(f, "Validation error: {e}"),
        }
    }
}

impl std::error::Error for ParseError {}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a single Sigma rule from a YAML string.
///
/// This is the main entry point for rule parsing. It:
///   1. Deserializes the YAML into a `SigmaRule`
///   2. Validates required fields (title, logsource, detection)
///   3. Generates an ID if not provided
///   4. Parses the detection block into `SearchIdentifiers`
///
/// Returns the parsed rule and its extracted search identifiers.
///
/// # Errors
///
/// Returns [`ParseError::YamlError`] if `yaml` is not valid YAML.
///
/// Returns [`ParseError::MissingField`] if a required field (`title`,
/// `logsource`, or `detection`) is absent.
///
/// Returns [`ParseError::EmptyDetection`] if the detection block contains
/// no search identifiers.
///
/// Returns [`ParseError::ValidationError`] or [`ParseError::InvalidModifier`]
/// if the rule structure is malformed.
pub fn parse_rule(yaml: &str) -> Result<(SigmaRule, Vec<SearchIdentifier>), ParseError> {
    // Step 1: YAML → SigmaRule struct
    let mut rule: SigmaRule = serde_yaml::from_str(yaml)
        .map_err(|e| ParseError::YamlError(e.to_string()))?;

    // Step 2: Validate required fields
    if rule.title.is_empty() {
        return Err(ParseError::MissingField("title".to_string()));
    }

    // Step 3: Generate ID if not provided
    if rule.id.is_empty() {
        rule.id = generate_rule_id(&rule.title);
    }

    // Step 4: Parse detection identifiers
    let identifiers = parse_detection(&rule.detection)?;

    // Step 5: Validate that conditions reference valid identifiers
    validate_conditions(&rule.detection.condition, &identifiers)?;

    Ok((rule, identifiers))
}

/// Parse multiple Sigma rules from a YAML string containing multiple documents
/// (separated by `---`).
#[must_use]
pub fn parse_rules(yaml: &str) -> Vec<Result<(SigmaRule, Vec<SearchIdentifier>), ParseError>> {
    // Normalize Windows (\r\n) and classic Mac (\r) line endings so the
    // document separator "\n---" reliably splits regardless of source platform.
    let owned_buf;
    let yaml = if yaml.contains('\r') {
        owned_buf = yaml.replace("\r\n", "\n").replace('\r', "\n");
        owned_buf.as_str()
    } else {
        yaml
    };

    let documents: Vec<&str> = yaml.split("\n---").collect();
    documents
        .iter()
        .map(|doc| {
            let trimmed = doc.trim();
            if trimmed.is_empty() || trimmed == "---" {
                return Err(ParseError::YamlError("Empty document".to_string()));
            }
            parse_rule(trimmed)
        })
        .filter(|r| !matches!(r, Err(ParseError::YamlError(e)) if e == "Empty document"))
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Detection Block Parsing
// ─────────────────────────────────────────────────────────────────────────────

/// Parse the detection block into a list of `SearchIdentifiers`.
///
/// The detection block contains:
///   - `condition`: The boolean expression (handled separately by condition.rs)
///   - Named identifiers (e.g., "selection", "filter"): field conditions
///
/// Each named identifier can be:
///   - A mapping: `{field: value, field2: value2}` → all conditions `ANDed`
///   - A list of mappings: `[{field: val}, {field2: val2}]` → groups `ORed`, within each AND
///   - A list of values: `["val1", "val2"]` → keyword search (match against any field)
fn parse_detection(detection: &Detection) -> Result<Vec<SearchIdentifier>, ParseError> {
    let mut identifiers = Vec::new();

    for (name, value) in &detection.identifiers {
        // Skip the "condition" key — it's handled separately
        if name == "condition" {
            continue;
        }

        let search_id = parse_search_identifier(name, value)?;
        identifiers.push(search_id);
    }

    if identifiers.is_empty() {
        return Err(ParseError::EmptyDetection);
    }

    Ok(identifiers)
}

/// Parse a single search identifier from its YAML value.
///
/// Sigma search identifiers can have three forms:
///   1. Map form: `{CommandLine|contains: '-enc'}` → single group with AND
///   2. List-of-maps form: `[{Image: 'cmd.exe'}, {Image: 'powershell.exe'}]` → `ORed` groups
///   3. List-of-values form: `['keyword1', 'keyword2']` → keyword match (fieldless)
fn parse_search_identifier(name: &str, value: &serde_yaml::Value) -> Result<SearchIdentifier, ParseError> {
    let groups = match value {
        // Form 1: Single map — one AND-group
        serde_yaml::Value::Mapping(map) => {
            vec![parse_field_map(name, map)?]
        }

        // Form 2 or 3: List
        serde_yaml::Value::Sequence(seq) => {
            if seq.is_empty() {
                return Err(ParseError::EmptyDetection);
            }

            // Check if it's a list of maps (Form 2) or list of values (Form 3)
            if seq.iter().all(serde_yaml::Value::is_mapping) {
                // Form 2: List of maps — each map is an OR-group
                seq.iter()
                    .map(|item| {
                        let map = item.as_mapping()
                            .ok_or_else(|| ParseError::ValidationError(
                                format!("Expected mapping in list for identifier '{name}'")
                            ))?;
                        parse_field_map(name, map)
                    })
                    .collect::<Result<Vec<_>, _>>()?
            } else {
                // Form 3: List of values — keyword search (no specific field)
                let values: Vec<SigmaValue> = seq.iter()
                    .map(SigmaValue::from_yaml)
                    .collect();
                vec![FieldConditionGroup {
                    conditions: vec![FieldCondition {
                        field: String::new(), // Empty field = keyword match (match any field)
                        values,
                        modifiers: vec![ValueModifier::Contains],
                    }],
                }]
            }
        }

        // Single scalar value — treated as a single keyword
        _ => {
            vec![FieldConditionGroup {
                conditions: vec![FieldCondition {
                    field: String::new(),
                    values: vec![SigmaValue::from_yaml(value)],
                    modifiers: vec![ValueModifier::Contains],
                }],
            }]
        }
    };

    Ok(SearchIdentifier {
        name: name.to_string(),
        groups,
    })
}

/// Parse a YAML mapping into a `FieldConditionGroup`.
///
/// Each key in the map is a field name (possibly with modifiers), and the value
/// is the pattern to match. Multiple keys in the same map are `ANDed` together.
///
/// Examples:
///   `{CommandLine|contains: '-enc'}` → field="CommandLine", modifier=Contains, value="-enc"
///   `{Image|endswith: ['\cmd.exe', '\powershell.exe']}` → 2 values `ORed`
///   `{User: 'SYSTEM'}` → exact match (no modifier)
fn parse_field_map(
    identifier_name: &str,
    map: &serde_yaml::Mapping,
) -> Result<FieldConditionGroup, ParseError> {
    let mut conditions = Vec::with_capacity(map.len());

    for (key, value) in map {
        let key_str = key.as_str().ok_or_else(|| {
            ParseError::ValidationError(format!(
                "Non-string key in identifier '{identifier_name}'"
            ))
        })?;

        // Parse field name and modifiers: "CommandLine|contains|all" → ("CommandLine", [Contains, All])
        let (field, modifiers) = parse_field_modifiers(key_str, identifier_name)?;

        // Parse value(s)
        let values = parse_field_values(value);

        conditions.push(FieldCondition {
            field,
            values,
            modifiers,
        });
    }

    Ok(FieldConditionGroup { conditions })
}

/// Parse a field key string into the field name and modifiers.
///
/// Input: "CommandLine|contains|all"
/// Output: ("`CommandLine`", [Contains, All])
fn parse_field_modifiers(
    key: &str,
    identifier_name: &str,
) -> Result<(String, Vec<ValueModifier>), ParseError> {
    let parts: Vec<&str> = key.split('|').collect();
    let field = parts[0].to_string();
    let mut modifiers = Vec::new();

    for &part in &parts[1..] {
        let modifier = ValueModifier::from_str(part).ok_or_else(|| ParseError::InvalidModifier {
            field: format!("{identifier_name}.{field}"),
            modifier: part.to_string(),
        })?;
        modifiers.push(modifier);
    }

    Ok((field, modifiers))
}

/// Parse a YAML value into a list of `SigmaValues`.
///
/// Handles:
///   - Single scalar: `"value"` → vec![`SigmaValue::String("value`")]
///   - List: `["val1", "val2"]` → vec![`SigmaValue::String("val1`"), `SigmaValue::String("val2`")]
///   - Null: `~` → vec![`SigmaValue::Null`]
fn parse_field_values(value: &serde_yaml::Value) -> Vec<SigmaValue> {
    match value {
        serde_yaml::Value::Sequence(seq) => {
            seq.iter().map(SigmaValue::from_yaml).collect()
        }
        _ => vec![SigmaValue::from_yaml(value)],
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Condition Validation
// ─────────────────────────────────────────────────────────────────────────────

/// Validate that all identifiers referenced in conditions actually exist.
///
/// This catches typos like `condition: selection and filtr` where "filtr"
/// should be "filter". Without this check, the rule would silently never match
/// because a non-existent identifier always evaluates to false.
fn validate_conditions(
    condition: &ConditionExpr,
    identifiers: &[SearchIdentifier],
) -> Result<(), ParseError> {
    let id_names: Vec<&str> = identifiers.iter().map(|id| id.name.as_str()).collect();

    for cond in condition.conditions() {
        // BUG-6: Pipe aggregation (e.g., `selection | count() > 5`) is not yet
        // supported. Fail fast with a clear error rather than allowing
        // compile_condition to silently strip the aggregate clause — a stripped
        // rule would fire on ANY single match, ignoring the count threshold and
        // producing false positives for security rules that rely on thresholds.
        if cond.contains('|') {
            return Err(ParseError::ValidationError(format!(
                "Pipe aggregation conditions are not yet supported: \"{cond}\". \
                 Use a non-aggregate condition expression."
            )));
        }

        // Tokenize and check each word-like token against known identifiers.
        let tokens = tokenize_condition(cond);
        for token in &tokens {
            if is_identifier_token(token) && !id_names.iter().any(|name| {
                // Support wildcard references: "selection*" matches "selection_process", etc.
                if token.ends_with('*') {
                    let prefix = &token[..token.len() - 1];
                    name.starts_with(prefix)
                } else {
                    *name == *token
                }
            }) {
                return Err(ParseError::InvalidCondition(format!(
                    "Identifier '{token}' referenced in condition but not defined in detection block"
                )));
            }
        }
    }

    Ok(())
}

/// Quick tokenizer for condition validation.
/// Only collects characters that can form valid Sigma identifier names:
/// alphanumeric, `_`, `-`, `.`, `*`. All other characters — including comparison
/// operators (`>`, `<`, `=`, `!`), pipes (`|`), and punctuation — are treated
/// as delimiters and discarded.
///
/// BUG-5 fix: prevents comparison-operator tokens like `>` and `5` from being
/// mistaken for undefined identifier references in rules that use aggregation
/// or other non-identifier constructs.
fn tokenize_condition(condition: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();

    for ch in condition.chars() {
        if ch.is_alphanumeric() || ch == '_' || ch == '-' || ch == '*' || ch == '.' {
            current.push(ch);
        } else if !current.is_empty() {
            tokens.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

/// Check if a token is an identifier reference (not a keyword or number).
fn is_identifier_token(token: &str) -> bool {
    // Language keywords and aggregation function names used in Sigma conditions.
    // Note: `tokenize_condition` splits on `|` so it never produces `|` as a token;
    // numeric literals of any value are caught by the `parse::<u64>()` check below.
    const KEYWORDS: &[&str] = &[
        "and", "or", "not", "all", "of", "them",
        "count", "near", "by", "avg", "sum", "min", "max",
    ];
    if KEYWORDS.contains(&token.to_lowercase().as_str()) {
        return false;
    }
    // Covers all numeric quantifiers: 1, 2, 3, …  (`1 of`, `2 of`, …)
    if token.parse::<u64>().is_ok() {
        return false;
    }
    true
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Generate a deterministic rule ID from the title in RFC 4122 UUID format.
///
/// Uses two independent FNV-1a passes (forward + reverse) to produce 128 bits
/// of deterministic data, then formats them as UUID v4 with the standard
/// version (4) and variant (10xx) bits set. The result is lowercase hyphenated:
/// `xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx`
///
/// This satisfies the Sigma spec recommendation for UUID IDs and ensures
/// compatibility with SIEM import tooling and sigmahq.io converters.
fn generate_rule_id(title: &str) -> String {
    // Forward pass — FNV-1a 64-bit
    let mut h1: u64 = 0xcbf2_9ce4_8422_2325;
    for b in title.bytes() {
        h1 ^= u64::from(b);
        h1 = h1.wrapping_mul(0x0000_0100_0000_01b3);
    }
    // Reverse pass — different byte order for independent 64-bit block
    let mut h2: u64 = 0x1465_0fb0_739d_0383;
    for b in title.bytes().rev() {
        h2 ^= u64::from(b);
        h2 = h2.wrapping_mul(0x0000_0100_0000_01b3);
    }

    // UUID v4 layout: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
    // Set version bits: top nibble of field 3 = 0x4
    // Set variant bits: top 2 bits of field 4 = 0b10
    let hi32          = (h1 >> 32) as u32;
    let mid16         = ((h1 >> 16) & 0xffff) as u16;
    let ver_nibble    = ((h1 & 0x0fff) as u16) | 0x4000;          // version 4
    let var_bits      = ((h2 >> 48) & 0x3fff) as u16 | 0x8000;    // variant 10xx
    let tail_bits     =   h2 & 0x0000_ffff_ffff_ffff;

    format!("{hi32:08x}-{mid16:04x}-{ver_nibble:04x}-{var_bits:04x}-{tail_bits:012x}")
}
