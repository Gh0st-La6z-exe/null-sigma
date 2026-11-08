// =============================================================================
// Sigma Rule Engine — Primary Discriminator Index (Binary Basename)
// =============================================================================
// In process event telemetry (Sysmon EID 1, Windows Security 4688, Linux auditd),
// detection rules overwhelmingly filter on the process image or binary name
// (Image, OriginalFileName).
//
// This module extracts the target binary basename from rules that strictly
// require it, enabling O(1) inverted dispatch: when an event for "chrome.exe"
// arrives, rules requiring "powershell.exe" or "cmd.exe" are never evaluated.
// =============================================================================

use crate::condition::ConditionNode;
use crate::matcher::pattern_literal;
use crate::types::{SearchIdentifier, ValueModifier};
use std::collections::HashMap;

/// Extract a literal binary basename from a Sigma field pattern and its modifiers, if valid.
///
/// Rules:
/// - Only exact match (no modifier) or `|endswith` can constrain the basename.
/// - `|contains` and `|startswith` match arbitrary substrings/prefixes (e.g. directory names)
///   and cannot soundly constrain the file basename.
/// - The extracted basename must not contain active wildcards (`*` or `?`).
pub(crate) fn extract_image_basename(val: &str, modifiers: &[ValueModifier]) -> Option<String> {
    // Only exact or endswith matching can anchor the final path component.
    let is_endswith = modifiers.contains(&ValueModifier::EndsWith);
    let has_unsupported_modifier = modifiers.iter().any(|m| {
        matches!(
            m,
            ValueModifier::Contains
                | ValueModifier::StartsWith
                | ValueModifier::Regex
                | ValueModifier::Cidr
                | ValueModifier::FieldRef
                | ValueModifier::Exists
                | ValueModifier::Gt
                | ValueModifier::Gte
                | ValueModifier::Lt
                | ValueModifier::Lte
        )
    });

    if has_unsupported_modifier {
        return None;
    }

    let s = val.trim();
    if s.is_empty() {
        return None;
    }

    // Find the last path separator (`\` or `/`).
    let component = match s.rfind(['\\', '/']) {
        Some(pos) => {
            let rest = &s[pos + 1..];
            if rest.is_empty() {
                return None; // Trailing slash, e.g. "C:\dir\"
            }
            rest
        }
        None => {
            // No separator: valid if exact match or if endswith.
            // But if it has a leading `*` without a slash (e.g. `*cmd.exe`), that could match `anythingcmd.exe`.
            if is_endswith && s.starts_with('*') {
                return None;
            }
            s
        }
    };

    // Ensure the final component has NO active wildcards and unescape any `\*` or `\?`.
    let literal = pattern_literal(component)?;
    let folded = literal.to_lowercase();
    if folded.is_empty() {
        None
    } else {
        Some(folded)
    }
}

/// Helper to compute required basenames for a specific set of field names.
fn compute_rule_discriminators_for_field(
    conditions: &[ConditionNode],
    identifiers: &[SearchIdentifier],
    field_names: &[&str],
) -> Option<Vec<String>> {
    const MAX_UNCONSTRAINED: usize = 12;
    if identifiers.len() > MAX_UNCONSTRAINED {
        return None;
    }

    // 1. For each identifier, determine if it strictly requires a set of image basenames.
    // An identifier requires basenames B if EVERY one of its OR-groups requires basenames B.
    let mut ident_basenames: Vec<Option<Vec<String>>> = Vec::with_capacity(identifiers.len());

    for ident in identifiers {
        if ident.groups.is_empty() {
            ident_basenames.push(None);
            continue;
        }

        let mut group_allowed_sets: Vec<Vec<String>> = Vec::with_capacity(ident.groups.len());
        let mut all_groups_have_image_cond = true;

        for group in &ident.groups {
            let mut group_basenames: Vec<String> = Vec::new();
            let mut group_has_image_cond = false;

            for cond in &group.conditions {
                if !field_names.contains(&cond.field_folded.as_str()) {
                    continue;
                }

                // If condition has Exists modifier, it doesn't specify a binary value
                if cond.modifiers.contains(&ValueModifier::Exists) {
                    continue;
                }

                // Try to extract basenames from all values in this condition
                let mut cond_literals = Vec::with_capacity(cond.values.len());
                let mut all_values_valid = !cond.values.is_empty();

                for val in &cond.values {
                    let s = val.as_str_lossy();
                    if let Some(base) = extract_image_basename(&s, &cond.modifiers) {
                        cond_literals.push(base);
                    } else {
                        all_values_valid = false;
                        break;
                    }
                }

                if all_values_valid && !cond_literals.is_empty() {
                    group_has_image_cond = true;
                    group_basenames.extend(cond_literals);
                }
            }

            if group_has_image_cond {
                group_basenames.sort_unstable();
                group_basenames.dedup();
                group_allowed_sets.push(group_basenames);
            } else {
                all_groups_have_image_cond = false;
                break;
            }
        }

        if all_groups_have_image_cond && !group_allowed_sets.is_empty() {
            // Identifier is satisfied if ANY group matches, so allowed basenames are the UNION across groups.
            let mut union_basenames: Vec<String> = Vec::new();
            for g_set in group_allowed_sets {
                union_basenames.extend(g_set);
            }
            union_basenames.sort_unstable();
            union_basenames.dedup();
            ident_basenames.push(Some(union_basenames));
        } else {
            ident_basenames.push(None);
        }
    }

    // 2. Identify which identifiers are strictly required by the condition AST.
    // An identifier I is strictly required if pinning I = false causes the condition
    // to evaluate to false under ALL truth assignments of the other identifiers.
    let mut results: HashMap<String, bool> = identifiers
        .iter()
        .map(|ident| (ident.name.clone(), false))
        .collect();

    let mut required_rule_basenames: Option<Vec<String>> = None;

    for (idx, _) in identifiers.iter().enumerate() {
        let Some(ref basenames) = ident_basenames[idx] else {
            continue;
        };

        // Check if ident is strictly required by testing all assignments of others with ident = false.
        let other_idents: Vec<&str> = identifiers
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != idx)
            .map(|(_, id)| id.name.as_str())
            .collect();

        let mut can_fire_without_ident = false;
        for assignment in 0u32..(1u32 << other_idents.len()) {
            for id in identifiers {
                *results.get_mut(&id.name).expect("name present") = false;
            }
            for (bit, name) in other_idents.iter().enumerate() {
                *results.get_mut(*name).expect("name present") = (assignment >> bit) & 1 == 1;
            }
            // ident stays false
            if conditions.iter().any(|cond| cond.evaluate(&results)) {
                can_fire_without_ident = true;
                break;
            }
        }

        if !can_fire_without_ident {
            // This identifier is strictly required!
            match required_rule_basenames {
                None => {
                    required_rule_basenames = Some(basenames.clone());
                }
                Some(existing) => {
                    // Intersection of required basenames
                    let mut inter: Vec<String> = existing
                        .into_iter()
                        .filter(|b| basenames.contains(b))
                        .collect();
                    inter.sort_unstable();
                    inter.dedup();
                    required_rule_basenames = Some(inter);
                }
            }
        }
    }

    required_rule_basenames.filter(|v| !v.is_empty())
}

/// Compute the set of binary basenames strictly required for this rule to fire.
///
/// Returns `Some(vec)` if the rule provably CANNOT fire unless the event's process binary
/// (`Image` or `OriginalFileName`) matches one of the basenames in `vec`.
/// Returns `None` if the rule has no binary constraint (or is unconstrained on image).
pub(crate) fn compute_rule_image_discriminators(
    conditions: &[ConditionNode],
    identifiers: &[SearchIdentifier],
) -> Option<Vec<String>> {
    compute_rule_discriminators_for_field(conditions, identifiers, &["image", "originalfilename"])
}

/// Compute the set of parent process binary basenames strictly required for this rule to fire.
///
/// Returns `Some(vec)` if the rule provably CANNOT fire unless the event's parent process binary
/// (`ParentImage`) matches one of the basenames in `vec`.
pub(crate) fn compute_rule_parent_image_discriminators(
    conditions: &[ConditionNode],
    identifiers: &[SearchIdentifier],
) -> Option<Vec<String>> {
    compute_rule_discriminators_for_field(conditions, identifiers, &["parentimage"])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::condition::compile_condition;
    use crate::parser::parse_rule;

    #[test]
    fn test_extract_image_basename_various_patterns() {
        // Windows backslash suffix
        assert_eq!(
            extract_image_basename(r"\powershell.exe", &[ValueModifier::EndsWith]),
            Some("powershell.exe".to_string())
        );
        // Wildcard prefix with backslash
        assert_eq!(
            extract_image_basename(r"*\cmd.exe", &[]),
            Some("cmd.exe".to_string())
        );
        // Full path
        assert_eq!(
            extract_image_basename(r"C:\Windows\System32\whoami.exe", &[]),
            Some("whoami.exe".to_string())
        );
        // Unix path
        assert_eq!(
            extract_image_basename("/bin/sh", &[ValueModifier::EndsWith]),
            Some("sh".to_string())
        );
        // Bare binary name
        assert_eq!(
            extract_image_basename("certutil.exe", &[]),
            Some("certutil.exe".to_string())
        );
        // Wildcard inside filename component must return None
        assert_eq!(
            extract_image_basename(r"\python*.exe", &[ValueModifier::EndsWith]),
            None
        );
        assert_eq!(extract_image_basename("*.exe", &[]), None);
        // Contains modifier must return None (could match directory path)
        assert_eq!(
            extract_image_basename("powershell", &[ValueModifier::Contains]),
            None
        );
        // Startswith modifier must return None
        assert_eq!(
            extract_image_basename(r"C:\Windows\", &[ValueModifier::StartsWith]),
            None
        );
    }

    #[test]
    fn test_compute_rule_image_discriminators_simple_rule() {
        let yaml = r#"
title: Test Powershell Rule
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains: '-enc'
    condition: selection
"#;
        let (_rule, identifiers) = parse_rule(yaml).unwrap();
        let conditions = vec![compile_condition("selection", &identifiers).unwrap()];
        let discriminators = compute_rule_image_discriminators(&conditions, &identifiers);
        assert_eq!(discriminators, Some(vec!["powershell.exe".to_string()]));
    }

    #[test]
    fn test_compute_rule_image_discriminators_multiple_values() {
        let yaml = r#"
title: Test Multi-Binary Rule
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
    condition: selection
"#;
        let (_rule, identifiers) = parse_rule(yaml).unwrap();
        let conditions = vec![compile_condition("selection", &identifiers).unwrap()];
        let discriminators = compute_rule_image_discriminators(&conditions, &identifiers);
        assert_eq!(
            discriminators,
            Some(vec!["cmd.exe".to_string(), "powershell.exe".to_string()])
        );
    }

    #[test]
    fn test_compute_rule_image_discriminators_negation_is_unconstrained() {
        let yaml = r#"
title: Test Negated Rule
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
    condition: not selection
"#;
        let (_rule, identifiers) = parse_rule(yaml).unwrap();
        let conditions = vec![compile_condition("not selection", &identifiers).unwrap()];
        let discriminators = compute_rule_image_discriminators(&conditions, &identifiers);
        assert_eq!(discriminators, None);
    }

    #[test]
    fn test_compute_rule_image_discriminators_or_condition_is_unconstrained() {
        let yaml = r#"
title: Test Disjunction Rule
logsource:
    category: process_creation
    product: windows
detection:
    sel1:
        Image|endswith: '\powershell.exe'
    sel2:
        CommandLine|contains: 'powershell'
    condition: sel1 or sel2
"#;
        let (_rule, identifiers) = parse_rule(yaml).unwrap();
        let conditions = vec![compile_condition("sel1 or sel2", &identifiers).unwrap()];
        let discriminators = compute_rule_image_discriminators(&conditions, &identifiers);
        assert_eq!(discriminators, None);
    }

    #[test]
    fn test_compute_rule_parent_image_discriminators() {
        let yaml = r#"
title: Test Parent Rule
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\cmd.exe'
        CommandLine|contains: 'whoami'
    condition: selection
"#;
        let (_rule, identifiers) = parse_rule(yaml).unwrap();
        let conditions = vec![compile_condition("selection", &identifiers).unwrap()];
        let image_disc = compute_rule_image_discriminators(&conditions, &identifiers);
        assert_eq!(image_disc, None);
        let parent_disc = compute_rule_parent_image_discriminators(&conditions, &identifiers);
        assert_eq!(parent_disc, Some(vec!["cmd.exe".to_string()]));
    }
}
