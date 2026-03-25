// =============================================================================
// NuLLAI Sigma Rule Engine — Event Matcher
// =============================================================================
// Matches event data against parsed Sigma search identifiers. This is where
// every ValueModifier becomes real: contains, endswith, startswith, regex,
// cidr, base64, wide, windash, numeric comparisons, and existence checks.
//
// SIGMA MATCHING SEMANTICS:
//   - Within a FieldConditionGroup, conditions are ANDed (all must match)
//   - Across FieldConditionGroups, groups are ORed (any group match = identifier match)
//   - Within a FieldCondition's values, values are ORed (any value match = condition match)
//     UNLESS the `all` modifier is present, then values are ANDed
//   - Matching is CASE-INSENSITIVE by default (Sigma spec requirement)
//   - Empty field name = keyword search (match value against any event field)
//   - Wildcards in values: `*` → match any, `?` → match single char
//
// PERFORMANCE NOTES:
//   - Regex patterns are compiled once per rule load, not per event
//   - Wildcard→regex conversion caches compiled patterns via the engine layer
//   - CIDR matching uses our existing ioc_matcher crate (via direct implementation)
// =============================================================================

use crate::types::{FieldCondition, FieldConditionGroup, SearchIdentifier, SigmaValue, ValueModifier};
use std::collections::HashMap;
use std::net::IpAddr;

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Check if a search identifier matches against an event.
///
/// An identifier matches if ANY of its field condition groups match.
/// Within each group, ALL field conditions must match (AND logic).
///
/// This is the core matching logic that the engine calls for each identifier
/// referenced in the condition expression.
pub fn match_identifier(
    identifier: &SearchIdentifier,
    event: &HashMap<String, String>,
) -> bool {
    // OR across groups — any group matching means the identifier matches
    identifier.groups.iter().any(|group| match_group(group, event))
}

/// Check if a field condition group matches against an event.
/// ALL conditions in the group must match (AND logic within a group).
fn match_group(group: &FieldConditionGroup, event: &HashMap<String, String>) -> bool {
    group.conditions.iter().all(|cond| match_field_condition(cond, event))
}

/// Check if a single field condition matches against an event.
///
/// This is where the modifier pipeline executes:
/// 1. Resolve target fields (specific field or all fields for keywords)
/// 2. Apply transform modifiers to values (base64, wide, windash)
/// 3. Apply match modifiers against field values
pub fn match_field_condition(
    condition: &FieldCondition,
    event: &HashMap<String, String>,
) -> bool {
    // Special case: `exists` modifier checks field presence
    if condition.modifiers.contains(&ValueModifier::Exists) {
        return handle_exists(condition, event);
    }

    // Determine which event fields to check
    let target_fields: Vec<(&str, &str)> = if condition.field.is_empty() {
        // Empty field = keyword search — check ALL event values
        event.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
    } else {
        // Specific field — look it up (case-insensitive key match)
        let field_lower = condition.field.to_lowercase();
        event.iter()
            .filter(|(k, _)| k.to_lowercase() == field_lower)
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect()
    };

    // If no matching fields found and this isn't a negation context,
    // the condition doesn't match
    if target_fields.is_empty() {
        return false;
    }

    // Pre-process values through transform modifiers (base64, wide, windash)
    let transformed_values = apply_transforms(&condition.values, &condition.modifiers);

    // Determine if "all" modifier is present (changes OR to AND for values)
    let require_all = condition.modifiers.contains(&ValueModifier::All);

    // Check each target field
    for (_field_name, field_value) in &target_fields {
        if require_all {
            // ALL values must match this field
            let all_match = transformed_values.iter().all(|val| {
                value_matches(val, field_value, &condition.modifiers)
            });
            if all_match {
                return true;
            }
        } else {
            // ANY value matching this field is enough
            let any_match = transformed_values.iter().any(|val| {
                value_matches(val, field_value, &condition.modifiers)
            });
            if any_match {
                return true;
            }
        }
    }

    false
}

// ─────────────────────────────────────────────────────────────────────────────
// Exists modifier
// ─────────────────────────────────────────────────────────────────────────────

fn handle_exists(condition: &FieldCondition, event: &HashMap<String, String>) -> bool {
    let field_lower = condition.field.to_lowercase();
    let field_present = event.keys().any(|k| k.to_lowercase() == field_lower);

    // The `exists` modifier checks: does the field exist?
    // The value in the condition determines the expected state:
    //   exists: true → field must be present
    //   exists: false → field must NOT be present (NOTE: this is outside normal 
    //                    Sigma spec but some community rules use it)
    // Default behavior (no explicit true/false): field must exist
    let expect_exists = condition.values.first()
        .map(|v| match v {
            SigmaValue::Boolean(b) => *b,
            SigmaValue::String(s) => s != "false" && s != "0",
            SigmaValue::Integer(i) => *i != 0,
            _ => true,
        })
        .unwrap_or(true);

    field_present == expect_exists
}

// ─────────────────────────────────────────────────────────────────────────────
// Value Transformation Pipeline
// ─────────────────────────────────────────────────────────────────────────────

/// Apply transform modifiers to values BEFORE matching. These modify the values
/// we're searching for, not the event data itself.
///
/// Transform order matters (Sigma spec): base64offset → base64 → wide → windash
fn apply_transforms(
    values: &[SigmaValue],
    modifiers: &[ValueModifier],
) -> Vec<SigmaValue> {
    let mut result: Vec<SigmaValue> = values.to_vec();

    // Each transform modifier expands the value set:
    // - base64: adds base64-encoded variant
    // - base64offset: adds all 3 offset variants
    // - wide: adds UTF-16LE variant
    // - windash: adds dash-variant alternatives

    for modifier in modifiers {
        match modifier {
            ValueModifier::Base64 => {
                result = result.into_iter().flat_map(|v| {
                    let s = v.as_str_lossy();
                    let mut variants = vec![v];
                    if !s.is_empty() {
                        variants.push(SigmaValue::String(base64_encode(&s)));
                    }
                    variants
                }).collect();
            }

            ValueModifier::Base64Offset => {
                // Base64offset generates 3 variants to catch base64 at any
                // alignment boundary. This defeats naive base64 obfuscation
                // where the encoded string starts at different offsets.
                result = result.into_iter().flat_map(|v| {
                    let s = v.as_str_lossy();
                    let mut variants = vec![v];
                    if !s.is_empty() {
                        for offset in 0..3 {
                            let padded = " ".repeat(offset) + &s;
                            let encoded = base64_encode(&padded);
                            // Trim the padding artifact from the encoded string
                            let trimmed = if offset > 0 {
                                // Skip first encoded char(s) that represent padding
                                let skip = ((offset * 4) + 2) / 3;
                                encoded.get(skip..).unwrap_or(&encoded).to_string()
                            } else {
                                encoded.clone()
                            };
                            variants.push(SigmaValue::String(trimmed));
                        }
                    }
                    variants
                }).collect();
            }

            ValueModifier::Wide => {
                // Wide transforms: "cmd" → "c\x00m\x00d\x00" (UTF-16LE encoding)
                // This catches strings encoded as wide chars in memory/processes.
                result = result.into_iter().flat_map(|v| {
                    let s = v.as_str_lossy();
                    let mut variants = vec![v];
                    if !s.is_empty() {
                        let wide: String = s.chars()
                            .map(|c| format!("{c}\x00"))
                            .collect();
                        variants.push(SigmaValue::String(wide));
                    }
                    variants
                }).collect();
            }

            ValueModifier::Windash => {
                // Windash: for each value, add variant with `-` replaced by `/`
                // Catches Windows command obfuscation: `cmd -c` → `cmd /c`
                result = result.into_iter().flat_map(|v| {
                    let s = v.as_str_lossy();
                    let mut variants = vec![v];
                    if s.contains('-') {
                        variants.push(SigmaValue::String(s.replace('-', "/")));
                    }
                    if s.contains('/') {
                        variants.push(SigmaValue::String(s.replace('/', "-")));
                    }
                    variants
                }).collect();
            }

            _ => {} // Non-transform modifiers handled in value_matches()
        }
    }

    result
}

/// Inline base64 encoding (avoid external dependency for this simple operation)
fn base64_encode(input: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut result = String::with_capacity((bytes.len() + 2) / 3 * 4);
    
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        result.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            result.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(ALPHABET[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }

    result
}

// ─────────────────────────────────────────────────────────────────────────────
// Value Matching — Per-modifier logic
// ─────────────────────────────────────────────────────────────────────────────

/// Does a single Sigma value match an event field value, given the modifiers?
///
/// Modifiers change HOW the comparison works:
/// - No modifiers → exact match (with wildcard support)
/// - `contains` → substring match
/// - `startswith` → prefix match
/// - `endswith` → suffix match
/// - `regex` → regex pattern match
/// - `cidr` → CIDR network range match for IP addresses
/// - `gt`/`gte`/`lt`/`lte` → numeric comparison
fn value_matches(
    sigma_value: &SigmaValue,
    field_value: &str,
    modifiers: &[ValueModifier],
) -> bool {
    // Null matches empty/missing fields only
    if *sigma_value == SigmaValue::Null {
        return field_value.is_empty();
    }

    let sigma_str = sigma_value.as_str_lossy();

    // Determine the matching mode from modifiers
    let has_contains = modifiers.contains(&ValueModifier::Contains);
    let has_startswith = modifiers.contains(&ValueModifier::StartsWith);
    let has_endswith = modifiers.contains(&ValueModifier::EndsWith);
    let has_regex = modifiers.contains(&ValueModifier::Regex);
    let has_cidr = modifiers.contains(&ValueModifier::Cidr);

    // Numeric comparisons
    if let Some(result) = try_numeric_comparison(sigma_value, field_value, modifiers) {
        return result;
    }

    // CIDR match — IP address must fall within the network range
    if has_cidr {
        return cidr_matches(&sigma_str, field_value);
    }

    // Regex match — value is a regex pattern
    if has_regex {
        return regex_matches(&sigma_str, field_value);
    }

    // Case-insensitive fields for string matching (Sigma default behavior)
    let field_lower = field_value.to_lowercase();
    let sigma_lower = sigma_str.to_lowercase();

    // String matching with modifier-determined mode
    if has_contains {
        // Substring match (with wildcard support within the pattern)
        return wildcard_contains(&sigma_lower, &field_lower);
    }

    if has_startswith {
        return wildcard_startswith(&sigma_lower, &field_lower);
    }

    if has_endswith {
        return wildcard_endswith(&sigma_lower, &field_lower);
    }

    // Default: full match with wildcard support
    // If the sigma value has wildcards (* or ?), convert to pattern match
    if sigma_value.has_wildcards() {
        wildcard_match(&sigma_lower, &field_lower)
    } else {
        sigma_lower == field_lower
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Wildcard Matching
// ─────────────────────────────────────────────────────────────────────────────

/// Full wildcard match: `*` matches any sequence, `?` matches single char.
/// Uses a two-pointer algorithm — O(m*n) worst case but fast for typical patterns.
fn wildcard_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    wildcard_match_impl(pattern.as_slice(), text.as_slice())
}

/// Two-pointer wildcard matching implementation.
fn wildcard_match_impl(pattern: &[char], text: &[char]) -> bool {
    let mut pi = 0usize;
    let mut ti = 0usize;
    let mut star_pi = usize::MAX; // Position after last '*' in pattern
    let mut star_ti = 0usize;     // Position in text when we last matched '*'

    let plen = pattern.len();
    let tlen = text.len();

    while ti < tlen {
        if pi < plen && (pattern[pi] == '?' || pattern[pi] == text[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < plen && pattern[pi] == '*' {
            star_pi = pi;
            star_ti = ti;
            pi += 1;
            // Don't advance ti — '*' can match zero chars
        } else if star_pi != usize::MAX {
            // Backtrack: the last '*' matches one more char
            pi = star_pi + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }

    // Consume trailing wildcards
    while pi < plen && pattern[pi] == '*' {
        pi += 1;
    }

    pi == plen
}

/// Contains with wildcard support in the pattern.
fn wildcard_contains(pattern: &str, text: &str) -> bool {
    if !pattern.contains('*') && !pattern.contains('?') {
        // Simple substring check
        return text.contains(pattern);
    }
    // Use wildcard match with surrounding wildcards
    let wrapped = format!("*{pattern}*");
    let wrapped_chars: Vec<char> = wrapped.chars().collect();
    let text_chars: Vec<char> = text.chars().collect();
    wildcard_match_impl(&wrapped_chars, &text_chars)
}

/// Starts-with with wildcard support.
fn wildcard_startswith(pattern: &str, text: &str) -> bool {
    if !pattern.contains('*') && !pattern.contains('?') {
        return text.starts_with(pattern);
    }
    let wrapped = format!("{pattern}*");
    let wrapped_chars: Vec<char> = wrapped.chars().collect();
    let text_chars: Vec<char> = text.chars().collect();
    wildcard_match_impl(&wrapped_chars, &text_chars)
}

/// Ends-with with wildcard support.
fn wildcard_endswith(pattern: &str, text: &str) -> bool {
    if !pattern.contains('*') && !pattern.contains('?') {
        return text.ends_with(pattern);
    }
    let wrapped = format!("*{pattern}");
    let wrapped_chars: Vec<char> = wrapped.chars().collect();
    let text_chars: Vec<char> = text.chars().collect();
    wildcard_match_impl(&wrapped_chars, &text_chars)
}

// ─────────────────────────────────────────────────────────────────────────────
// CIDR Matching
// ─────────────────────────────────────────────────────────────────────────────

/// Check if an IP address falls within a CIDR range.
/// E.g., does "192.168.1.50" match "192.168.1.0/24"?
fn cidr_matches(cidr: &str, ip_str: &str) -> bool {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return false;
    }

    let network: IpAddr = match parts[0].parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    let prefix_len: u8 = match parts[1].parse() {
        Ok(p) => p,
        Err(_) => return false,
    };

    let target: IpAddr = match ip_str.trim().parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };

    match (network, target) {
        (IpAddr::V4(net), IpAddr::V4(tgt)) => {
            if prefix_len > 32 {
                return false;
            }
            if prefix_len == 0 {
                return true;
            }
            let mask = u32::MAX << (32 - prefix_len);
            (u32::from(net) & mask) == (u32::from(tgt) & mask)
        }
        (IpAddr::V6(net), IpAddr::V6(tgt)) => {
            if prefix_len > 128 {
                return false;
            }
            if prefix_len == 0 {
                return true;
            }
            let net_bits = u128::from(net);
            let tgt_bits = u128::from(tgt);
            let mask = u128::MAX << (128 - prefix_len);
            (net_bits & mask) == (tgt_bits & mask)
        }
        _ => false, // Mismatched IP versions
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Regex Matching
// ─────────────────────────────────────────────────────────────────────────────

/// Match using the `re` modifier — the sigma value is a regex pattern.
/// Case-insensitive by default per Sigma spec.
fn regex_matches(pattern: &str, text: &str) -> bool {
    // Prepend case-insensitive flag if not already present
    let pattern = if pattern.starts_with("(?") {
        pattern.to_string()
    } else {
        format!("(?i){pattern}")
    };

    match regex::Regex::new(&pattern) {
        Ok(re) => re.is_match(text),
        Err(_) => false, // Invalid regex → no match (don't crash)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Numeric Comparison
// ─────────────────────────────────────────────────────────────────────────────

/// Try numeric comparison modifiers (gt, gte, lt, lte).
/// Returns None if no numeric modifier is present.
fn try_numeric_comparison(
    sigma_value: &SigmaValue,
    field_value: &str,
    modifiers: &[ValueModifier],
) -> Option<bool> {
    let has_gt = modifiers.contains(&ValueModifier::Gt);
    let has_gte = modifiers.contains(&ValueModifier::Gte);
    let has_lt = modifiers.contains(&ValueModifier::Lt);
    let has_lte = modifiers.contains(&ValueModifier::Lte);

    if !has_gt && !has_gte && !has_lt && !has_lte {
        return None;
    }

    let sigma_num = match sigma_value {
        SigmaValue::Integer(n) => *n as f64,
        SigmaValue::Float(f) => *f,
        SigmaValue::String(s) => s.parse::<f64>().ok()?,
        _ => return Some(false),
    };

    let field_num = match field_value.parse::<f64>() {
        Ok(n) => n,
        Err(_) => return Some(false),
    };

    let result = if has_gt {
        field_num > sigma_num
    } else if has_gte {
        field_num >= sigma_num
    } else if has_lt {
        field_num < sigma_num
    } else {
        // has_lte
        field_num <= sigma_num
    };

    Some(result)
}

// ─────────────────────────────────────────────────────────────────────────────
// Batch matching for Aho-Corasick optimization (used by engine.rs)
// ─────────────────────────────────────────────────────────────────────────────

/// Pre-extracted string patterns from rules for Aho-Corasick batch matching.
/// The engine builds one AC automaton across all rules' string patterns, runs
/// it once over each event field, and uses the results to short-circuit
/// individual rule evaluation.
#[derive(Debug)]
pub struct PatternMatch {
    /// Index into the global pattern list
    pub pattern_index: usize,
    /// Which event field it was found in
    pub field_name: String,
}
