// =============================================================================
// NuLLAI Sigma Rule Engine — YAML Parser
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

use crate::types::*;

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
    InvalidModifier { field: String, modifier: String },
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
///   1. Deserializes the YAML into a SigmaRule
///   2. Validates required fields (title, logsource, detection)
///   3. Generates an ID if not provided
///   4. Parses the detection block into SearchIdentifiers
///
/// Returns the parsed rule and its extracted search identifiers.
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
pub fn parse_rules(yaml: &str) -> Vec<Result<(SigmaRule, Vec<SearchIdentifier>), ParseError>> {
    // Split on YAML document separators
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

/// Parse the detection block into a list of SearchIdentifiers.
///
/// The detection block contains:
///   - `condition`: The boolean expression (handled separately by condition.rs)
///   - Named identifiers (e.g., "selection", "filter"): field conditions
///
/// Each named identifier can be:
///   - A mapping: `{field: value, field2: value2}` → all conditions ANDed
///   - A list of mappings: `[{field: val}, {field2: val2}]` → groups ORed, within each AND
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
///   2. List-of-maps form: `[{Image: 'cmd.exe'}, {Image: 'powershell.exe'}]` → ORed groups
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
            if seq.iter().all(|item| item.is_mapping()) {
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

/// Parse a YAML mapping into a FieldConditionGroup.
///
/// Each key in the map is a field name (possibly with modifiers), and the value
/// is the pattern to match. Multiple keys in the same map are ANDed together.
///
/// Examples:
///   `{CommandLine|contains: '-enc'}` → field="CommandLine", modifier=Contains, value="-enc"
///   `{Image|endswith: ['\cmd.exe', '\powershell.exe']}` → 2 values ORed
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
/// Output: ("CommandLine", [Contains, All])
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

/// Parse a YAML value into a list of SigmaValues.
///
/// Handles:
///   - Single scalar: `"value"` → vec![SigmaValue::String("value")]
///   - List: `["val1", "val2"]` → vec![SigmaValue::String("val1"), SigmaValue::String("val2")]
///   - Null: `~` → vec![SigmaValue::Null]
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
        // Tokenize and check each word-like token against known identifiers.
        // Skip keywords: and, or, not, (, ), 1, all, of, them, |, pipe tokens
        let tokens = tokenize_condition(cond);
        for token in &tokens {
            if is_identifier_token(token) && !id_names.iter().any(|name| {
                // Support wildcard references: "selection*" matches "selection_process", "selection_cmdline"
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

/// Quick tokenizer for condition validation — splits on whitespace and parens.
fn tokenize_condition(condition: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();

    for ch in condition.chars() {
        if ch == '(' || ch == ')' || ch.is_whitespace() {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            // Don't add parens or whitespace as tokens
        } else {
            current.push(ch);
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

/// Check if a token is an identifier reference (not a keyword or number).
fn is_identifier_token(token: &str) -> bool {
    // Keywords in the Sigma condition language
    let keywords = ["and", "or", "not", "1", "all", "of", "them", "|", "count", "near", "by",
                     "avg", "sum", "min", "max", "0"];
    if keywords.contains(&token.to_lowercase().as_str()) {
        return false;
    }
    // Numbers (for "1 of" quantifiers)
    if token.parse::<u64>().is_ok() {
        return false;
    }
    // Pipe aggregation tokens
    if token.starts_with('|') {
        return false;
    }
    true
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Generate a deterministic rule ID from the title.
/// Uses a simple hash to create a UUID-like string.
fn generate_rule_id(title: &str) -> String {
    // Simple FNV-1a hash for deterministic ID generation
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in title.bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}
