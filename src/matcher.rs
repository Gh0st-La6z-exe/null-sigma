// =============================================================================
// Sigma Rule Engine — Event Matcher
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

use crate::event_view::EventView;
use crate::fold::fold_key;
use crate::types::{
    FieldCondition, FieldConditionGroup, PatToken, SearchIdentifier, SigmaValue, ValueMatchCache,
    ValueModifier,
};
use regex::Regex;
use std::borrow::Cow;
use std::collections::HashMap;
use std::hash::BuildHasher;
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
#[must_use]
pub fn match_identifier<S: BuildHasher>(
    identifier: &SearchIdentifier,
    event: &HashMap<String, String, S>,
) -> bool {
    let mut view = EventView::from_map(event);
    match_identifier_on_view(identifier, &mut view)
}

/// Check if a field condition group matches against an event.
/// ALL conditions in the group must match (AND logic within a group).
fn match_group_on_view(group: &FieldConditionGroup, view: &mut EventView<'_>) -> bool {
    group
        .conditions
        .iter()
        .all(|cond| match_field_condition_on_view(cond, view))
}

/// Check if a single field condition matches against an event.
///
/// This is where the modifier pipeline executes:
/// 1. Resolve target fields (specific field or all fields for keywords)
/// 2. Apply transform modifiers to values (base64, wide, windash)
/// 3. Apply match modifiers against field values
#[must_use]
pub fn match_field_condition<S: BuildHasher>(
    condition: &FieldCondition,
    event: &HashMap<String, String, S>,
) -> bool {
    let mut view = EventView::from_map(event);
    match_field_condition_on_view(condition, &mut view)
}

/// Internal fast path that evaluates an identifier against a pre-built
/// case-insensitive event view.
#[must_use]
pub(crate) fn match_identifier_on_view(
    identifier: &SearchIdentifier,
    view: &mut EventView<'_>,
) -> bool {
    identifier
        .groups
        .iter()
        .any(|group| match_group_on_view(group, view))
}

/// Internal fast path that evaluates one field condition against a pre-built
/// case-insensitive event view.
#[must_use]
pub(crate) fn match_field_condition_on_view(
    condition: &FieldCondition,
    view: &mut EventView<'_>,
) -> bool {
    let field_folded = condition_field_folded(condition);
    // Special case: `exists` modifier checks field presence
    if condition.modifiers.contains(&ValueModifier::Exists) {
        return handle_exists_on_view(condition, &field_folded, view);
    }

    // Special case: `fieldref` compares against another event field's value
    if condition.modifiers.contains(&ValueModifier::FieldRef) {
        return handle_fieldref_on_view(condition, view);
    }

    // Pre-process values through transform modifiers (base64, wide, windash)
    let transformed_values = apply_transforms(&condition.values, &condition.modifiers);
    let use_precomputed_folds = !condition.modifiers.iter().any(ValueModifier::is_transform)
        && transformed_values.len() == condition.values_folded.len();

    // Determine if "all" modifier is present (changes OR to AND for values)
    let require_all = condition.modifiers.contains(&ValueModifier::All);

    let mut matched_any_field = false;
    let eval_field = |field_value: &str| -> bool {
        let field_lower = field_value.to_lowercase();
        if require_all {
            transformed_values.iter().enumerate().all(|(idx, val)| {
                let sigma_folded = if use_precomputed_folds {
                    condition.values_folded.get(idx).and_then(|v| v.as_deref())
                } else {
                    None
                };
                value_matches(
                    val,
                    sigma_folded,
                    condition
                        .values_match_cache
                        .get(idx)
                        .filter(|c| c.is_populated()),
                    field_value,
                    &field_lower,
                    &condition.modifiers,
                )
            })
        } else {
            transformed_values.iter().enumerate().any(|(idx, val)| {
                let sigma_folded = if use_precomputed_folds {
                    condition.values_folded.get(idx).and_then(|v| v.as_deref())
                } else {
                    None
                };
                value_matches(
                    val,
                    sigma_folded,
                    condition
                        .values_match_cache
                        .get(idx)
                        .filter(|c| c.is_populated()),
                    field_value,
                    &field_lower,
                    &condition.modifiers,
                )
            })
        }
    };

    if condition.field.is_empty() {
        for (_, field_value) in view.values_all() {
            matched_any_field = true;
            if eval_field(field_value) {
                return true;
            }
        }
    } else {
        for (_, field_value) in view.values_for_field(&field_folded) {
            matched_any_field = true;
            if eval_field(field_value) {
                return true;
            }
        }
    }

    if !matched_any_field {
        return false;
    }

    false
}

// ─────────────────────────────────────────────────────────────────────────────
// Exists modifier
// ─────────────────────────────────────────────────────────────────────────────

#[allow(dead_code)]
fn handle_exists<S: BuildHasher>(
    condition: &FieldCondition,
    event: &HashMap<String, String, S>,
) -> bool {
    let mut view = EventView::from_map(event);
    let field_folded = condition_field_folded(condition);
    handle_exists_on_view(condition, &field_folded, &mut view)
}

fn handle_exists_on_view(
    condition: &FieldCondition,
    field_folded: &str,
    view: &mut EventView<'_>,
) -> bool {
    let field_present = view.has_field_folded(field_folded);

    // The `exists` modifier checks: does the field exist?
    // The value in the condition determines the expected state:
    //   exists: true → field must be present
    //   exists: false → field must NOT be present (NOTE: this is outside normal
    //                    Sigma spec but some community rules use it)
    // Default behavior (no explicit true/false): field must exist
    let expect_exists = condition.values.first().is_none_or(|v| match v {
        SigmaValue::Boolean(b) => *b,
        SigmaValue::String(s) => s != "false" && s != "0",
        SigmaValue::Integer(i) => *i != 0,
        _ => true,
    });

    field_present == expect_exists
}

// ─────────────────────────────────────────────────────────────────────────────
// FieldRef modifier
// ─────────────────────────────────────────────────────────────────────────────

/// Handle the `fieldref` modifier: the condition value names ANOTHER event
/// field, and the comparison runs between the two event fields' values
/// (Sigma v2 spec). Match-type modifiers apply to the comparison:
///
/// ```yaml
/// Image|fieldref: ParentImage              # Image == ParentImage
/// CommandLine|fieldref|contains: Image     # CommandLine contains Image's value
/// ```
///
/// Missing fields never match: if either the subject field or the referenced
/// field is absent from the event, the condition is false.
#[allow(dead_code)]
fn handle_fieldref<S: BuildHasher>(
    condition: &FieldCondition,
    event: &HashMap<String, String, S>,
) -> bool {
    let mut view = EventView::from_map(event);
    handle_fieldref_on_view(condition, &mut view)
}

fn handle_fieldref_on_view(condition: &FieldCondition, view: &mut EventView<'_>) -> bool {
    // Case-insensitive lookup of a field's value, matching the engine's
    // field-name semantics elsewhere.
    let lookup = |name: &str| -> Option<&str> {
        let name_lower = fold_key(name);
        view.first_value_for_folded_field(&name_lower)
    };

    let Some(subject) = lookup(condition_field_folded(condition).as_ref()) else {
        return false;
    };

    let has_contains = condition.modifiers.contains(&ValueModifier::Contains);
    let has_startswith = condition.modifiers.contains(&ValueModifier::StartsWith);
    let has_endswith = condition.modifiers.contains(&ValueModifier::EndsWith);
    let require_all = condition.modifiers.contains(&ValueModifier::All);

    let subject_lower = subject.to_lowercase();
    let check = |value: &SigmaValue| -> bool {
        let referenced_field = value.as_str_lossy();
        let Some(referenced) = lookup(&referenced_field) else {
            return false;
        };
        // The referenced value is DATA, not a pattern — wildcards in event
        // values must compare literally, so plain string ops are correct.
        let referenced_lower = referenced.to_lowercase();
        if has_contains {
            subject_lower.contains(&referenced_lower)
        } else if has_startswith {
            subject_lower.starts_with(&referenced_lower)
        } else if has_endswith {
            subject_lower.ends_with(&referenced_lower)
        } else {
            subject_lower == referenced_lower
        }
    };

    if require_all {
        condition.values.iter().all(check)
    } else {
        condition.values.iter().any(check)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Value Transformation Pipeline
// ─────────────────────────────────────────────────────────────────────────────

/// Apply transform modifiers to values BEFORE matching. These modify the values
/// we're searching for, not the event data itself.
///
/// Transform order matters (Sigma spec): base64offset → base64 → wide → windash
fn apply_transforms(values: &[SigmaValue], modifiers: &[ValueModifier]) -> Vec<SigmaValue> {
    let mut result: Vec<SigmaValue> = values.to_vec();

    // Each transform modifier expands the value set:
    // - base64: adds base64-encoded variant
    // - base64offset: adds all 3 offset variants
    // - wide: adds UTF-16LE variant
    // - windash: adds dash-variant alternatives

    for modifier in modifiers {
        match modifier {
            ValueModifier::Base64 => {
                // Base64 REPLACES the original value with its base64-encoded form.
                result = result
                    .into_iter()
                    .flat_map(|v| {
                        let s = v.as_str_lossy();
                        if s.is_empty() {
                            vec![v]
                        } else {
                            vec![SigmaValue::String(base64_encode(&s))]
                        }
                    })
                    .collect();
            }

            ValueModifier::Base64Offset => {
                // Base64Offset REPLACES the original with the 3 offset variants.
                // Each variant is the base64 encoding of the value at byte
                // offset 0/1/2 within the stream, with unstable characters
                // trimmed from BOTH ends:
                //   - leading chars that mix bits from the unknown preceding
                //     bytes (simulated by space padding) are stripped;
                //   - trailing chars that mix bits from the unknown following
                //     bytes — plus `=` padding — are stripped when the padded
                //     length is not a multiple of 3.
                result = result
                    .into_iter()
                    .flat_map(|v| {
                        let s = v.as_str_lossy();
                        if s.is_empty() {
                            return vec![v];
                        }

                        (0..3usize)
                            .map(|offset| {
                                let padded = " ".repeat(offset) + &s;
                                let encoded = base64_encode(&padded);

                                // Leading trim: chars containing padding bits.
                                let skip = (offset * 4).div_ceil(3);
                                // Trailing trim: chars whose bits depend on the
                                // bytes that follow the value in real data.
                                //   len % 3 == 0 → last group complete, keep all
                                //   len % 3 == 1 → strip partial char + "==" (3)
                                //   len % 3 == 2 → strip partial char + "=" (2)
                                let tail = match padded.len() % 3 {
                                    1 => 3,
                                    2 => 2,
                                    _ => 0,
                                };

                                let end = encoded.len().saturating_sub(tail);
                                let trimmed = encoded.get(skip..end).unwrap_or("").to_string();
                                SigmaValue::String(trimmed)
                            })
                            .filter(|v| !v.as_str_lossy().is_empty())
                            .collect::<Vec<_>>()
                    })
                    .collect();
            }

            ValueModifier::Wide => {
                // Wide REPLACES the original with UTF-16LE null-byte interleaving.
                result = result
                    .into_iter()
                    .flat_map(|v| {
                        let s = v.as_str_lossy();
                        if s.is_empty() {
                            vec![v]
                        } else {
                            // flat_map avoids per-char String allocation from format!
                            let wide: String = s.chars().flat_map(|c| [c, '\x00']).collect();
                            vec![SigmaValue::String(wide)]
                        }
                    })
                    .collect();
            }

            ValueModifier::Windash => {
                // Windash: expand each value into variants for every dash
                // character Windows accepts as a parameter prefix. Catches
                // command obfuscation like `cmd /c` vs `cmd -c` vs `cmd –c`.
                //
                // Per the Sigma spec the variant set is: `-`, `/`,
                // `–` (en dash U+2013), `—` (em dash U+2014), and
                // `―` (horizontal bar U+2015). All dash occurrences in the
                // value are replaced uniformly per variant.
                const DASH_VARIANTS: [char; 5] = ['-', '/', '\u{2013}', '\u{2014}', '\u{2015}'];
                result = result
                    .into_iter()
                    .flat_map(|v| {
                        let s = v.as_str_lossy();
                        let mut variants = vec![v];
                        if s.contains(DASH_VARIANTS) {
                            for replacement in DASH_VARIANTS {
                                let variant = s.replace(DASH_VARIANTS, &replacement.to_string());
                                if variant != s
                                    && !variants
                                        .iter()
                                        .any(|existing| existing.as_str_lossy() == variant)
                                {
                                    variants.push(SigmaValue::String(variant));
                                }
                            }
                        }
                        variants
                    })
                    .collect();
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
    let mut result = String::with_capacity(bytes.len().div_ceil(3) * 4);

    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
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

/// Build a load-time match cache from a case-folded pattern string.
///
/// The input must already be lowercased (`fold_value`) so cached tokens and
/// literals align with the runtime `field_lower` comparison path.
#[must_use]
pub(crate) fn build_value_match_cache(folded: &str) -> ValueMatchCache {
    if let Some(literal) = pattern_literal(folded) {
        ValueMatchCache {
            literal: Some(literal),
            tokens: None,
        }
    } else {
        ValueMatchCache {
            literal: None,
            tokens: Some(tokenize_pattern(folded)),
        }
    }
}

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
    sigma_folded: Option<&str>,
    match_cache: Option<&ValueMatchCache>,
    field_value: &str,
    field_lower: &str,
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
        return regex_matches(&sigma_str, field_value, modifiers);
    }

    // Case-insensitive fields for string matching (Sigma default behavior)
    let sigma_lower_owned;
    let sigma_lower = if let Some(folded) = sigma_folded {
        folded
    } else {
        sigma_lower_owned = sigma_str.to_lowercase();
        sigma_lower_owned.as_str()
    };

    // String matching with modifier-determined mode
    if has_contains {
        return value_matches_contains(sigma_lower, match_cache, field_lower);
    }

    if has_startswith {
        return value_matches_startswith(sigma_lower, match_cache, field_lower);
    }

    if has_endswith {
        return value_matches_endswith(sigma_lower, match_cache, field_lower);
    }

    // Default: full match with wildcard support.
    // Route through the tokenizer whenever the value contains wildcard or
    // escape characters so `\*` / `\\` sequences compare by their unescaped
    // literal form, per the Sigma escaping rules.
    if sigma_value.has_wildcards() || sigma_lower.contains('\\') {
        value_matches_wildcard(sigma_lower, match_cache, field_lower)
    } else {
        sigma_lower == field_lower
    }
}

fn value_matches_contains(
    sigma_lower: &str,
    match_cache: Option<&ValueMatchCache>,
    field_lower: &str,
) -> bool {
    if let Some(cache) = match_cache {
        if let Some(literal) = &cache.literal {
            return field_lower.contains(literal.as_str());
        }
        if let Some(tokens) = &cache.tokens {
            return wildcard_match_wrapped_tokens(tokens, field_lower, true, true);
        }
    }
    wildcard_contains(sigma_lower, field_lower)
}

fn value_matches_startswith(
    sigma_lower: &str,
    match_cache: Option<&ValueMatchCache>,
    field_lower: &str,
) -> bool {
    if let Some(cache) = match_cache {
        if let Some(literal) = &cache.literal {
            return field_lower.starts_with(literal.as_str());
        }
        if let Some(tokens) = &cache.tokens {
            return wildcard_match_wrapped_tokens(tokens, field_lower, false, true);
        }
    }
    wildcard_startswith(sigma_lower, field_lower)
}

fn value_matches_endswith(
    sigma_lower: &str,
    match_cache: Option<&ValueMatchCache>,
    field_lower: &str,
) -> bool {
    if let Some(cache) = match_cache {
        if let Some(literal) = &cache.literal {
            return field_lower.ends_with(literal.as_str());
        }
        if let Some(tokens) = &cache.tokens {
            return wildcard_match_wrapped_tokens(tokens, field_lower, true, false);
        }
    }
    wildcard_endswith(sigma_lower, field_lower)
}

fn value_matches_wildcard(
    sigma_lower: &str,
    match_cache: Option<&ValueMatchCache>,
    field_lower: &str,
) -> bool {
    if let Some(cache) = match_cache {
        if let Some(literal) = &cache.literal {
            return literal == field_lower;
        }
        if let Some(tokens) = &cache.tokens {
            return wildcard_match_tokens(tokens, field_lower);
        }
    }
    wildcard_match(sigma_lower, field_lower)
}

// ─────────────────────────────────────────────────────────────────────────────
// Wildcard Matching
// ─────────────────────────────────────────────────────────────────────────────
//
// Sigma escaping rules (specification §"Escaping"):
//   `*`  → wildcard: any sequence (including empty)
//   `?`  → wildcard: exactly one character
//   `\*` → literal asterisk
//   `\?` → literal question mark
//   `\\` → literal backslash
//   `\x` (any other char) → plain backslash followed by `x` — single
//         backslashes before non-wildcards need no escaping, so Windows
//         paths like `\cmd.exe` keep their backslash.

/// Tokenize a Sigma pattern, resolving escape sequences per the spec above.
fn tokenize_pattern(pattern: &str) -> Vec<PatToken> {
    let mut tokens = Vec::with_capacity(pattern.len());
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.peek() {
                Some('*') => {
                    tokens.push(PatToken::Lit('*'));
                    chars.next();
                }
                Some('?') => {
                    tokens.push(PatToken::Lit('?'));
                    chars.next();
                }
                Some('\\') => {
                    tokens.push(PatToken::Lit('\\'));
                    chars.next();
                }
                // Lone backslash (before a normal char or at end of pattern)
                // is a plain backslash — no escaping required by the spec.
                _ => tokens.push(PatToken::Lit('\\')),
            },
            '*' => tokens.push(PatToken::Star),
            '?' => tokens.push(PatToken::Question),
            _ => tokens.push(PatToken::Lit(c)),
        }
    }
    tokens
}

/// If the pattern contains no active wildcards, return its unescaped literal
/// form (`\*` → `*`, `\\` → `\`). Returns `None` when the pattern has a real
/// `*` or `?` wildcard. Used by the engine to decide Aho-Corasick eligibility
/// and to register the correct literal bytes in the automaton.
pub(crate) fn pattern_literal(pattern: &str) -> Option<String> {
    let tokens = tokenize_pattern(pattern);
    let mut literal = String::with_capacity(pattern.len());
    for token in tokens {
        match token {
            PatToken::Star | PatToken::Question => return None,
            PatToken::Lit(c) => literal.push(c),
        }
    }
    Some(literal)
}

/// Full wildcard match: `*` matches any sequence, `?` matches single char.
fn wildcard_match(pattern: &str, text: &str) -> bool {
    wildcard_match_tokens(&tokenize_pattern(pattern), text)
}

fn wildcard_match_tokens(tokens: &[PatToken], text: &str) -> bool {
    let text_chars: Vec<char> = text.chars().collect();
    wildcard_match_impl(tokens, &text_chars)
}

/// Two-pointer wildcard matching over tokenized patterns.
fn wildcard_match_impl(pattern: &[PatToken], text: &[char]) -> bool {
    let mut pi = 0usize;
    let mut ti = 0usize;
    let mut star_pat_idx = usize::MAX; // Position of last '*' in pattern
    let mut star_txt_idx = 0usize; // Position in text when we last matched '*'

    let plen = pattern.len();
    let tlen = text.len();

    while ti < tlen {
        if pi < plen
            && (matches!(pattern[pi], PatToken::Question)
                || matches!(pattern[pi], PatToken::Lit(c) if c == text[ti]))
        {
            pi += 1;
            ti += 1;
        } else if pi < plen && pattern[pi] == PatToken::Star {
            star_pat_idx = pi;
            star_txt_idx = ti;
            pi += 1;
            // Don't advance ti — '*' can match zero chars
        } else if star_pat_idx != usize::MAX {
            // Backtrack: the last '*' matches one more char
            pi = star_pat_idx + 1;
            star_txt_idx += 1;
            ti = star_txt_idx;
        } else {
            return false;
        }
    }

    // Consume trailing wildcards
    while pi < plen && pattern[pi] == PatToken::Star {
        pi += 1;
    }

    pi == plen
}

/// Match tokenized pattern against text with implicit `*` anchors.
/// `star_before`/`star_after` add unanchored ends for contains/startswith/endswith.
fn wildcard_match_wrapped(pattern: &str, text: &str, star_before: bool, star_after: bool) -> bool {
    // Fast path: pure literal after unescaping → plain substring operations.
    if let Some(literal) = pattern_literal(pattern) {
        return match (star_before, star_after) {
            (true, true) => text.contains(&literal),
            (false, true) => text.starts_with(&literal),
            (true, false) => text.ends_with(&literal),
            (false, false) => text == literal,
        };
    }

    let mut tokens = Vec::new();
    if star_before {
        tokens.push(PatToken::Star);
    }
    tokens.extend(tokenize_pattern(pattern));
    if star_after {
        tokens.push(PatToken::Star);
    }
    wildcard_match_tokens(&tokens, text)
}

fn wildcard_match_wrapped_tokens(
    tokens: &[PatToken],
    text: &str,
    star_before: bool,
    star_after: bool,
) -> bool {
    let mut wrapped = Vec::with_capacity(tokens.len() + 2);
    if star_before {
        wrapped.push(PatToken::Star);
    }
    wrapped.extend_from_slice(tokens);
    if star_after {
        wrapped.push(PatToken::Star);
    }
    wildcard_match_tokens(&wrapped, text)
}

/// Contains with wildcard support in the pattern.
fn wildcard_contains(pattern: &str, text: &str) -> bool {
    wildcard_match_wrapped(pattern, text, true, true)
}

/// Starts-with with wildcard support.
fn wildcard_startswith(pattern: &str, text: &str) -> bool {
    wildcard_match_wrapped(pattern, text, false, true)
}

/// Ends-with with wildcard support.
fn wildcard_endswith(pattern: &str, text: &str) -> bool {
    wildcard_match_wrapped(pattern, text, true, false)
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

/// True when the condition carries `|m` or `|s` regex flag sub-modifiers that
/// change the compiled pattern relative to the plain `|re` default. (`|i` is
/// a no-op: the engine is already case-insensitive by default for `|re`.)
pub(crate) fn has_regex_flag_modifiers(modifiers: &[ValueModifier]) -> bool {
    modifiers
        .iter()
        .any(|m| matches!(m, ValueModifier::RegexM | ValueModifier::RegexS))
}

/// Build the final regex pattern string for a `|re` condition, applying the
/// engine's case-insensitive default plus any `|m`/`|s` flag sub-modifiers.
/// Used by BOTH load-time compilation and match-time cache lookup so the
/// cache key is always the same string.
pub(crate) fn regex_pattern_with_flags(pattern: &str, modifiers: &[ValueModifier]) -> String {
    let mut flags = String::from("i");
    if modifiers.contains(&ValueModifier::RegexM) {
        flags.push('m');
    }
    if modifiers.contains(&ValueModifier::RegexS) {
        flags.push('s');
    }
    // Back-compat: with no extra flags, a pattern carrying its own inline
    // flags is left untouched (pre-existing behavior).
    if flags == "i" && pattern.starts_with("(?") {
        return pattern.to_string();
    }
    format!("(?{flags}){pattern}")
}

/// Match using the `re` modifier — the sigma value is a regex pattern.
/// Case-insensitive by default per Sigma spec; `|m`/`|s` flag sub-modifiers
/// enable multi-line and dot-all modes.
fn regex_matches(pattern: &str, text: &str, modifiers: &[ValueModifier]) -> bool {
    let full = regex_pattern_with_flags(pattern, modifiers);
    match regex::Regex::new(&full) {
        Ok(re) => re.is_match(text),
        Err(_) => false, // Invalid regex → no match (don't crash)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Numeric Comparison
// ─────────────────────────────────────────────────────────────────────────────

/// Try numeric comparison modifiers (gt, gte, lt, lte).
/// Returns None if no numeric modifier is present.
// `*n as f64` in the fallback branch is only reached when `field_value` has
// a decimal component (couldn't parse as i64). Real-world integer fields
// that compare against Sigma Integer values are always < 2^53, so precision
// loss cannot occur on this code path.
// `has_gt`/`has_gte` and `has_lt`/`has_lte` are the natural names for boolean
// modifier flags — renaming them would reduce clarity, not improve it.
#[allow(clippy::cast_precision_loss, clippy::similar_names)]
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

    // Integer precision guard: i64 → f64 loses precision above 2^53
    // (f64 mantissa is 52 bits). When the Sigma value is an integer AND the
    // field parses as a whole number, compare in the integer domain to avoid
    // silent rounding of large counters, timestamps, or port numbers.
    if let SigmaValue::Integer(n) = sigma_value {
        if let Ok(field_int) = field_value.trim().parse::<i64>() {
            let result = if has_gt {
                field_int > *n
            } else if has_gte {
                field_int >= *n
            } else if has_lt {
                field_int < *n
            } else {
                field_int <= *n
            };
            return Some(result);
        }
        // Field has a decimal component — fall through to f64 comparison.
        // At this point the sigma integer is small enough that the f64 cast
        // is exact (real-world counters compared against floats are < 2^53).
    }

    let sigma_num = match sigma_value {
        SigmaValue::Integer(n) => *n as f64,
        SigmaValue::Float(f) => *f,
        SigmaValue::String(s) => s.parse::<f64>().ok()?,
        _ => return Some(false),
    };

    let Ok(field_num) = field_value.parse::<f64>() else {
        return Some(false);
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
// Cache-aware matching (used by engine.rs for |re rules)
// ─────────────────────────────────────────────────────────────────────────────

/// Evaluate a search identifier against an event using pre-compiled regexes.
///
/// Identical semantics to [`match_identifier`], but `|re` conditions use
/// the compiled [`Regex`] objects from `regex_cache` (keyed by raw pattern
/// string) instead of compiling the pattern fresh on every call.  This is the
/// primary hot path for rules that contain `|re` modifiers.
#[must_use]
pub fn match_identifier_with_cache<S1: BuildHasher, S2: BuildHasher>(
    identifier: &SearchIdentifier,
    event: &HashMap<String, String, S1>,
    regex_cache: &HashMap<String, Regex, S2>,
) -> bool {
    let mut view = EventView::from_map(event);
    match_identifier_with_cache_on_view(identifier, &mut view, regex_cache)
}

#[must_use]
pub(crate) fn match_identifier_with_cache_on_view<S2: BuildHasher>(
    identifier: &SearchIdentifier,
    view: &mut EventView<'_>,
    regex_cache: &HashMap<String, Regex, S2>,
) -> bool {
    identifier.groups.iter().any(|group| {
        group
            .conditions
            .iter()
            .all(|cond| match_field_condition_with_cache_on_view(cond, view, regex_cache))
    })
}

/// Like [`match_field_condition`] but uses a pre-compiled regex cache for `|re`
/// conditions instead of compiling the pattern on each invocation.
#[allow(dead_code)]
fn match_field_condition_with_cache<S1: BuildHasher, S2: BuildHasher>(
    condition: &FieldCondition,
    event: &HashMap<String, String, S1>,
    regex_cache: &HashMap<String, Regex, S2>,
) -> bool {
    let mut view = EventView::from_map(event);
    match_field_condition_with_cache_on_view(condition, &mut view, regex_cache)
}

fn match_field_condition_with_cache_on_view<S2: BuildHasher>(
    condition: &FieldCondition,
    view: &mut EventView<'_>,
    regex_cache: &HashMap<String, Regex, S2>,
) -> bool {
    let field_folded = condition_field_folded(condition);
    // `exists` and `fieldref` never involve regex.
    if condition.modifiers.contains(&ValueModifier::Exists) {
        return handle_exists_on_view(condition, &field_folded, view);
    }
    if condition.modifiers.contains(&ValueModifier::FieldRef) {
        return handle_fieldref_on_view(condition, view);
    }

    let transformed_values = apply_transforms(&condition.values, &condition.modifiers);
    let require_all = condition.modifiers.contains(&ValueModifier::All);
    let has_regex = condition.modifiers.contains(&ValueModifier::Regex);
    let use_precomputed_folds = !condition.modifiers.iter().any(ValueModifier::is_transform)
        && transformed_values.len() == condition.values_folded.len();

    let mut matched_any_field = false;
    let eval_field = |field_value: &str| {
        let field_lower = field_value.to_lowercase();
        let check = |val: &SigmaValue| -> bool {
            if has_regex {
                // Look up the pre-compiled Regex; fall back to on-demand compile
                // only if the cache is missing the pattern (should not happen in
                // normal operation — indicates a bug in collect_compiled_regexes).
                // Cache key mirrors collect_compiled_regexes: raw pattern for
                // plain |re (zero-allocation hot path), full flagged pattern
                // only when |m/|s sub-modifiers are present.
                let pattern = val.as_str_lossy();
                let cached = if has_regex_flag_modifiers(&condition.modifiers) {
                    regex_cache.get(&regex_pattern_with_flags(&pattern, &condition.modifiers))
                } else {
                    regex_cache.get(&pattern)
                };
                match cached {
                    Some(re) => re.is_match(field_value),
                    None => regex_matches(&pattern, field_value, &condition.modifiers),
                }
            } else {
                let value_idx = condition
                    .values
                    .iter()
                    .position(|candidate| candidate == val);
                let sigma_folded = if use_precomputed_folds {
                    value_idx
                        .and_then(|idx| condition.values_folded.get(idx))
                        .and_then(|v| v.as_deref())
                } else {
                    None
                };
                let match_cache = value_idx
                    .and_then(|idx| condition.values_match_cache.get(idx))
                    .filter(|c| c.is_populated());
                value_matches(
                    val,
                    sigma_folded,
                    match_cache,
                    field_value,
                    &field_lower,
                    &condition.modifiers,
                )
            }
        };

        if require_all {
            transformed_values.iter().all(check)
        } else {
            transformed_values.iter().any(check)
        }
    };

    if condition.field.is_empty() {
        for (_, field_value) in view.values_all() {
            matched_any_field = true;
            if eval_field(field_value) {
                return true;
            }
        }
    } else {
        for (_, field_value) in view.values_for_field(&field_folded) {
            matched_any_field = true;
            if eval_field(field_value) {
                return true;
            }
        }
    }

    if !matched_any_field {
        return false;
    }

    false
}

fn condition_field_folded(condition: &FieldCondition) -> Cow<'_, str> {
    if condition.field_folded.is_empty() {
        Cow::Owned(fold_key(&condition.field))
    } else {
        Cow::Borrowed(condition.field_folded.as_str())
    }
}
