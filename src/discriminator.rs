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

use crate::bloom::Bloom256;
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
#[doc(hidden)]
pub fn extract_image_basename(val: &str, modifiers: &[ValueModifier]) -> Option<String> {
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

/// Extract a literal EventID integer from a Sigma field pattern and its modifiers.
#[doc(hidden)]
pub fn extract_event_id(val: &str, modifiers: &[ValueModifier]) -> Option<u32> {
    if !modifiers.is_empty() {
        return None;
    }
    val.trim().parse::<u32>().ok()
}

/// Extract a literal pipe name from a Sigma field pattern and its modifiers.
#[doc(hidden)]
pub fn extract_pipe_name(val: &str, modifiers: &[ValueModifier]) -> Option<String> {
    extract_image_basename(val, modifiers)
}

/// Extract a literal DNS query name from a Sigma field pattern and its modifiers.
#[doc(hidden)]
pub fn extract_query_name(val: &str, modifiers: &[ValueModifier]) -> Option<String> {
    if modifiers.contains(&ValueModifier::Regex) || modifiers.contains(&ValueModifier::Cidr) {
        return None;
    }
    let s = val.trim();
    if s.is_empty() || s.contains('*') || s.contains('?') {
        None
    } else {
        Some(s.to_lowercase())
    }
}

/// Helper to compute required discriminators for a specific set of field names.
fn compute_rule_discriminators_custom<T: Ord + Clone>(
    conditions: &[ConditionNode],
    identifiers: &[SearchIdentifier],
    field_names: &[&str],
    extract_fn: &dyn Fn(&str, &[ValueModifier]) -> Option<T>,
) -> Option<Vec<T>> {
    const MAX_UNCONSTRAINED: usize = 12;
    if identifiers.len() > MAX_UNCONSTRAINED {
        return None;
    }

    // 1. For each identifier, determine if it strictly requires a set of discriminators.
    let mut ident_values: Vec<Option<Vec<T>>> = Vec::with_capacity(identifiers.len());

    for ident in identifiers {
        if ident.groups.is_empty() {
            ident_values.push(None);
            continue;
        }

        let mut group_allowed_sets: Vec<Vec<T>> = Vec::with_capacity(ident.groups.len());
        let mut all_groups_have_cond = true;

        for group in &ident.groups {
            let mut group_values: Vec<T> = Vec::new();
            let mut group_has_cond = false;

            for cond in &group.conditions {
                if !field_names.contains(&cond.field_folded.as_str()) {
                    continue;
                }

                if cond.modifiers.contains(&ValueModifier::Exists) {
                    continue;
                }

                let mut cond_literals = Vec::with_capacity(cond.values.len());
                let mut all_values_valid = !cond.values.is_empty();

                for val in &cond.values {
                    let s = val.as_str_lossy();
                    if let Some(v) = extract_fn(&s, &cond.modifiers) {
                        cond_literals.push(v);
                    } else {
                        all_values_valid = false;
                        break;
                    }
                }

                if all_values_valid && !cond_literals.is_empty() {
                    group_has_cond = true;
                    group_values.extend(cond_literals);
                }
            }

            if group_has_cond {
                group_values.sort_unstable();
                group_values.dedup();
                group_allowed_sets.push(group_values);
            } else {
                all_groups_have_cond = false;
                break;
            }
        }

        if all_groups_have_cond && !group_allowed_sets.is_empty() {
            let mut union_values: Vec<T> = Vec::new();
            for g_set in group_allowed_sets {
                union_values.extend(g_set);
            }
            union_values.sort_unstable();
            union_values.dedup();
            ident_values.push(Some(union_values));
        } else {
            ident_values.push(None);
        }
    }

    // 2. Collect candidate values across all identifiers.
    let mut candidate_values: Vec<T> = Vec::new();
    let mut has_any_constrained_ident = false;
    for vals in ident_values.iter().flatten() {
        has_any_constrained_ident = true;
        candidate_values.extend(vals.clone());
    }
    candidate_values.sort_unstable();
    candidate_values.dedup();

    if !has_any_constrained_ident || candidate_values.is_empty() || candidate_values.len() > 64 {
        return None;
    }

    // 3. Verify that the rule CANNOT fire when ALL constrained identifiers are false.
    let unconstrained_idents: Vec<&str> = identifiers
        .iter()
        .enumerate()
        .filter(|(idx, _)| ident_values[*idx].is_none())
        .map(|(_, id)| id.name.as_str())
        .collect();

    let mut results: HashMap<String, bool> = identifiers
        .iter()
        .map(|ident| (ident.name.clone(), false))
        .collect();

    let mut can_fire_with_no_match = false;
    for assignment in 0u32..(1u32 << unconstrained_idents.len()) {
        for id in identifiers {
            *results.get_mut(&id.name).expect("name present") = false;
        }
        for (bit, name) in unconstrained_idents.iter().enumerate() {
            *results.get_mut(*name).expect("name present") = (assignment >> bit) & 1 == 1;
        }
        if conditions.iter().any(|cond| cond.evaluate(&results)) {
            can_fire_with_no_match = true;
            break;
        }
    }

    if can_fire_with_no_match {
        return None;
    }

    // 4. Prune candidate values
    let mut valid_values = Vec::with_capacity(candidate_values.len());
    for val in candidate_values {
        let active_idents: Vec<&str> = identifiers
            .iter()
            .enumerate()
            .filter(|(idx, _)| match &ident_values[*idx] {
                Some(vals) => vals.contains(&val),
                None => true,
            })
            .map(|(_, id)| id.name.as_str())
            .collect();

        let mut can_fire_with_val = false;
        for assignment in 0u32..(1u32 << active_idents.len()) {
            for id in identifiers {
                *results.get_mut(&id.name).expect("name present") = false;
            }
            for (bit, name) in active_idents.iter().enumerate() {
                *results.get_mut(*name).expect("name present") = (assignment >> bit) & 1 == 1;
            }
            if conditions.iter().any(|cond| cond.evaluate(&results)) {
                can_fire_with_val = true;
                break;
            }
        }

        if can_fire_with_val {
            valid_values.push(val);
        }
    }

    if valid_values.is_empty() {
        None
    } else {
        Some(valid_values)
    }
}

/// Compute the set of binary basenames strictly required for this rule to fire.
pub(crate) fn compute_rule_image_discriminators(
    conditions: &[ConditionNode],
    identifiers: &[SearchIdentifier],
) -> Option<Vec<String>> {
    compute_rule_discriminators_custom(
        conditions,
        identifiers,
        &["image", "originalfilename"],
        &extract_image_basename,
    )
}

/// Compute the set of parent process binary basenames strictly required for this rule to fire.
pub(crate) fn compute_rule_parent_image_discriminators(
    conditions: &[ConditionNode],
    identifiers: &[SearchIdentifier],
) -> Option<Vec<String>> {
    compute_rule_discriminators_custom(
        conditions,
        identifiers,
        &["parentimage"],
        &extract_image_basename,
    )
}

/// Compute the set of loaded image basenames strictly required for this rule to fire.
pub(crate) fn compute_rule_image_loaded_discriminators(
    conditions: &[ConditionNode],
    identifiers: &[SearchIdentifier],
) -> Option<Vec<String>> {
    compute_rule_discriminators_custom(
        conditions,
        identifiers,
        &["imageloaded"],
        &extract_image_basename,
    )
}

/// Compute the set of EventID values strictly required for this rule to fire.
pub(crate) fn compute_rule_event_id_discriminators(
    conditions: &[ConditionNode],
    identifiers: &[SearchIdentifier],
) -> Option<Vec<u32>> {
    compute_rule_discriminators_custom(
        conditions,
        identifiers,
        &["eventid", "event_id"],
        &extract_event_id,
    )
}

/// Compute the set of PipeName basenames strictly required for this rule to fire.
pub(crate) fn compute_rule_pipe_name_discriminators(
    conditions: &[ConditionNode],
    identifiers: &[SearchIdentifier],
) -> Option<Vec<String>> {
    compute_rule_discriminators_custom(
        conditions,
        identifiers,
        &["pipename", "pipe_name"],
        &extract_pipe_name,
    )
}

/// Compute the set of QueryName values strictly required for this rule to fire.
pub(crate) fn compute_rule_query_name_discriminators(
    conditions: &[ConditionNode],
    identifiers: &[SearchIdentifier],
) -> Option<Vec<String>> {
    compute_rule_discriminators_custom(
        conditions,
        identifiers,
        &["queryname", "query_name"],
        &extract_query_name,
    )
}

/// Compute the set of target filename basenames strictly required for this rule to fire.
pub(crate) fn compute_rule_target_filename_discriminators(
    conditions: &[ConditionNode],
    identifiers: &[SearchIdentifier],
) -> Option<Vec<String>> {
    compute_rule_discriminators_custom(
        conditions,
        identifiers,
        &["targetfilename", "target_filename"],
        &extract_image_basename,
    )
}

/// Compute the set of binary basenames required across ANY process field (`Image`, `OriginalFileName`, or `ParentImage`).
pub(crate) fn compute_rule_process_discriminators(
    conditions: &[ConditionNode],
    identifiers: &[SearchIdentifier],
) -> Option<Vec<String>> {
    compute_rule_discriminators_custom(
        conditions,
        identifiers,
        &["image", "originalfilename", "parentimage"],
        &extract_image_basename,
    )
}

/// A target field key extracted from a multi-field process or metadata disjunction.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum MultiFieldDiscriminator {
    Image(String),
    ParentImage(String),
    Description(String),
    Product(String),
    Company(String),
}

/// Compute required discriminators across process and PE metadata fields.
///
/// Handles rules specifying OR-groups across multiple fields (e.g. `selection_img: [- Image: '...', - Description: '...', - OriginalFileName: '...']`).
pub(crate) fn compute_rule_multi_field_discriminators(
    conditions: &[ConditionNode],
    identifiers: &[SearchIdentifier],
) -> Option<Vec<MultiFieldDiscriminator>> {
    const MAX_UNCONSTRAINED: usize = 12;
    if identifiers.len() > MAX_UNCONSTRAINED {
        return None;
    }

    let mut ident_discriminators: Vec<Option<Vec<MultiFieldDiscriminator>>> =
        Vec::with_capacity(identifiers.len());

    for ident in identifiers {
        if ident.groups.is_empty() {
            ident_discriminators.push(None);
            continue;
        }

        let mut group_allowed_sets: Vec<Vec<MultiFieldDiscriminator>> =
            Vec::with_capacity(ident.groups.len());
        let mut all_groups_have_cond = true;

        for group in &ident.groups {
            let mut group_discs: Vec<MultiFieldDiscriminator> = Vec::new();
            let mut group_has_cond = false;

            for cond in &group.conditions {
                if cond.modifiers.contains(&ValueModifier::Exists) {
                    continue;
                }

                match cond.field_folded.as_str() {
                    "image" | "originalfilename" => {
                        let mut valid = !cond.values.is_empty();
                        let mut lits = Vec::with_capacity(cond.values.len());
                        for val in &cond.values {
                            let s = val.as_str_lossy();
                            if let Some(base) = extract_image_basename(&s, &cond.modifiers) {
                                lits.push(MultiFieldDiscriminator::Image(base));
                            } else {
                                valid = false;
                                break;
                            }
                        }
                        if valid && !lits.is_empty() {
                            group_has_cond = true;
                            group_discs.extend(lits);
                        }
                    }
                    "parentimage" => {
                        let mut valid = !cond.values.is_empty();
                        let mut lits = Vec::with_capacity(cond.values.len());
                        for val in &cond.values {
                            let s = val.as_str_lossy();
                            if let Some(base) = extract_image_basename(&s, &cond.modifiers) {
                                lits.push(MultiFieldDiscriminator::ParentImage(base));
                            } else {
                                valid = false;
                                break;
                            }
                        }
                        if valid && !lits.is_empty() {
                            group_has_cond = true;
                            group_discs.extend(lits);
                        }
                    }
                    "description" if cond.modifiers.is_empty() => {
                        let mut valid = !cond.values.is_empty();
                        let mut lits = Vec::with_capacity(cond.values.len());
                        for val in &cond.values {
                            let s = val.as_str_lossy();
                            if let Some(lit) = pattern_literal(&s) {
                                let folded = lit.trim().to_lowercase();
                                if !folded.is_empty() {
                                    lits.push(MultiFieldDiscriminator::Description(folded));
                                } else {
                                    valid = false;
                                    break;
                                }
                            } else {
                                valid = false;
                                break;
                            }
                        }
                        if valid && !lits.is_empty() {
                            group_has_cond = true;
                            group_discs.extend(lits);
                        }
                    }
                    "product" if cond.modifiers.is_empty() => {
                        let mut valid = !cond.values.is_empty();
                        let mut lits = Vec::with_capacity(cond.values.len());
                        for val in &cond.values {
                            let s = val.as_str_lossy();
                            if let Some(lit) = pattern_literal(&s) {
                                let folded = lit.trim().to_lowercase();
                                if !folded.is_empty() {
                                    lits.push(MultiFieldDiscriminator::Product(folded));
                                } else {
                                    valid = false;
                                    break;
                                }
                            } else {
                                valid = false;
                                break;
                            }
                        }
                        if valid && !lits.is_empty() {
                            group_has_cond = true;
                            group_discs.extend(lits);
                        }
                    }
                    "company" if cond.modifiers.is_empty() => {
                        let mut valid = !cond.values.is_empty();
                        let mut lits = Vec::with_capacity(cond.values.len());
                        for val in &cond.values {
                            let s = val.as_str_lossy();
                            if let Some(lit) = pattern_literal(&s) {
                                let folded = lit.trim().to_lowercase();
                                if !folded.is_empty() {
                                    lits.push(MultiFieldDiscriminator::Company(folded));
                                } else {
                                    valid = false;
                                    break;
                                }
                            } else {
                                valid = false;
                                break;
                            }
                        }
                        if valid && !lits.is_empty() {
                            group_has_cond = true;
                            group_discs.extend(lits);
                        }
                    }
                    _ => {}
                }
            }

            if group_has_cond {
                group_discs.sort_unstable();
                group_discs.dedup();
                group_allowed_sets.push(group_discs);
            } else {
                all_groups_have_cond = false;
                break;
            }
        }

        if all_groups_have_cond && !group_allowed_sets.is_empty() {
            let mut union_discs: Vec<MultiFieldDiscriminator> = Vec::new();
            for g_set in group_allowed_sets {
                union_discs.extend(g_set);
            }
            union_discs.sort_unstable();
            union_discs.dedup();
            ident_discriminators.push(Some(union_discs));
        } else {
            ident_discriminators.push(None);
        }
    }

    let mut candidate_discs: Vec<MultiFieldDiscriminator> = Vec::new();
    let mut has_any_constrained_ident = false;
    for discs in ident_discriminators.iter().flatten() {
        has_any_constrained_ident = true;
        candidate_discs.extend(discs.clone());
    }
    candidate_discs.sort_unstable();
    candidate_discs.dedup();

    if !has_any_constrained_ident || candidate_discs.is_empty() {
        return None;
    }

    if candidate_discs.len() > 64 {
        return None;
    }

    let unconstrained_idents: Vec<&str> = identifiers
        .iter()
        .enumerate()
        .filter(|(idx, _)| ident_discriminators[*idx].is_none())
        .map(|(_, id)| id.name.as_str())
        .collect();

    let mut results: HashMap<String, bool> = identifiers
        .iter()
        .map(|ident| (ident.name.clone(), false))
        .collect();

    let mut can_fire_with_no_match = false;
    for assignment in 0u32..(1u32 << unconstrained_idents.len()) {
        for id in identifiers {
            *results.get_mut(&id.name).expect("name present") = false;
        }
        for (bit, name) in unconstrained_idents.iter().enumerate() {
            *results.get_mut(*name).expect("name present") = (assignment >> bit) & 1 == 1;
        }
        if conditions.iter().any(|cond| cond.evaluate(&results)) {
            can_fire_with_no_match = true;
            break;
        }
    }

    if can_fire_with_no_match {
        return None;
    }

    let mut valid_discs = Vec::with_capacity(candidate_discs.len());
    for disc in candidate_discs {
        let active_idents: Vec<&str> = identifiers
            .iter()
            .enumerate()
            .filter(|(idx, _)| match &ident_discriminators[*idx] {
                Some(discs) => discs.contains(&disc),
                None => true,
            })
            .map(|(_, id)| id.name.as_str())
            .collect();

        let mut can_fire_with_disc = false;
        for assignment in 0u32..(1u32 << active_idents.len()) {
            for id in identifiers {
                *results.get_mut(&id.name).expect("name present") = false;
            }
            for (bit, name) in active_idents.iter().enumerate() {
                *results.get_mut(*name).expect("name present") = (assignment >> bit) & 1 == 1;
            }
            if conditions.iter().any(|cond| cond.evaluate(&results)) {
                can_fire_with_disc = true;
                break;
            }
        }

        if can_fire_with_disc {
            valid_discs.push(disc);
        }
    }

    if valid_discs.is_empty() {
        None
    } else {
        Some(valid_discs)
    }
}

/// Find indices of search identifiers that are strictly necessary for the rule to fire.
///
/// An identifier is mandatory if pinning it to `false` prevents the rule's conditions
/// from evaluating to `true` under ANY boolean assignment of the other identifiers.
pub(crate) fn find_mandatory_identifiers(
    conditions: &[ConditionNode],
    identifiers: &[SearchIdentifier],
) -> Vec<usize> {
    const MAX_IDENTS: usize = 12;
    if identifiers.is_empty() || identifiers.len() > MAX_IDENTS {
        return Vec::new();
    }

    if identifiers.len() == 1 {
        let mut results = HashMap::new();
        results.insert(identifiers[0].name.clone(), false);
        if !conditions.iter().any(|cond| cond.evaluate(&results)) {
            return vec![0];
        }
        return Vec::new();
    }

    let mut mandatory = Vec::new();
    let n = identifiers.len();
    let num_assignments = 1usize << (n - 1);

    for (target_idx, target_id) in identifiers.iter().enumerate() {
        let other_idents: Vec<&str> = identifiers
            .iter()
            .enumerate()
            .filter(|(idx, _)| *idx != target_idx)
            .map(|(_, id)| id.name.as_str())
            .collect();

        let mut results: HashMap<String, bool> = identifiers
            .iter()
            .map(|id| (id.name.clone(), false))
            .collect();

        let mut can_fire_when_false = false;
        for assignment in 0..num_assignments {
            *results.get_mut(&target_id.name).expect("present") = false;
            for (bit, name) in other_idents.iter().enumerate() {
                *results.get_mut(*name).expect("present") = (assignment >> bit) & 1 == 1;
            }
            if conditions.iter().any(|cond| cond.evaluate(&results)) {
                can_fire_when_false = true;
                break;
            }
        }

        if !can_fire_when_false {
            mandatory.push(target_idx);
        }
    }

    mandatory
}

fn get_cond_value_bloom(cond: &crate::types::FieldCondition, idx: usize) -> Bloom256 {
    if idx < cond.values_match_cache.len() {
        cond.values_match_cache[idx].bloom_mask
    } else {
        let s = cond.values[idx].as_str_lossy().to_lowercase();
        crate::matcher::build_value_match_cache(&s).bloom_mask
    }
}

/// Compute the mandatory Sub-256 rolling bigram bloom filter for an identifier on a field.
///
/// Returns `Bloom256::ZERO` if the identifier does not soundly require bigrams on this field.
pub(crate) fn compute_ident_bloom(ident: &SearchIdentifier, field_folded: &str) -> Bloom256 {
    if ident.groups.is_empty() {
        return Bloom256::ZERO;
    }

    let mut group_blooms: Vec<Bloom256> = Vec::with_capacity(ident.groups.len());

    for group in &ident.groups {
        let mut g_bloom = Bloom256::ZERO;
        let mut group_has_field = false;

        for cond in &group.conditions {
            if cond.field_folded != field_folded {
                continue;
            }

            // Exists, FieldRef, Wide modifiers do not constrain ASCII literal substrings
            if cond.modifiers.contains(&ValueModifier::Exists)
                || cond.modifiers.contains(&ValueModifier::FieldRef)
                || cond.modifiers.contains(&ValueModifier::Wide)
                || cond.modifiers.contains(&ValueModifier::Cidr)
                || cond.modifiers.contains(&ValueModifier::Gt)
                || cond.modifiers.contains(&ValueModifier::Gte)
                || cond.modifiers.contains(&ValueModifier::Lt)
                || cond.modifiers.contains(&ValueModifier::Lte)
            {
                continue;
            }

            if cond.modifiers.contains(&ValueModifier::Regex) {
                if cond.values.len() == 1 {
                    let pat = cond.values[0].as_str_lossy();
                    if let Some(b) = extract_regex_mandatory_bloom(&pat) {
                        g_bloom = g_bloom.union(&b);
                        group_has_field = true;
                    }
                } else if !cond.values.is_empty() {
                    let mut intersect: Option<Bloom256> = None;
                    for val in &cond.values {
                        let pat = val.as_str_lossy();
                        if let Some(b) = extract_regex_mandatory_bloom(&pat) {
                            intersect = Some(match intersect {
                                None => b,
                                Some(prev) => prev.intersect(&b),
                            });
                        } else {
                            intersect = None;
                            break;
                        }
                    }
                    if let Some(ib) = intersect {
                        if !ib.is_empty() {
                            g_bloom = g_bloom.union(&ib);
                            group_has_field = true;
                        }
                    }
                }
                continue;
            }

            let transformed_values = if cond.modifiers.iter().any(ValueModifier::is_transform) {
                crate::matcher::apply_transforms(&cond.values, &cond.modifiers)
            } else {
                std::borrow::Cow::Borrowed(&cond.values[..])
            };

            let get_b = |idx: usize, val: &crate::types::SigmaValue| -> Bloom256 {
                if cond.modifiers.iter().any(ValueModifier::is_transform) {
                    crate::bloom::compute_bloom256(&val.as_str_lossy().to_lowercase())
                } else {
                    get_cond_value_bloom(cond, idx)
                }
            };

            let is_all = cond.modifiers.contains(&ValueModifier::All);
            if is_all {
                let mut c_bloom = Bloom256::ZERO;
                for (v_idx, val) in transformed_values.iter().enumerate() {
                    let b = get_b(v_idx, val);
                    if !b.is_empty() {
                        c_bloom = c_bloom.union(&b);
                    }
                }
                if !c_bloom.is_empty() {
                    group_has_field = true;
                    g_bloom = g_bloom.union(&c_bloom);
                }
            } else {
                let mut c_bloom: Option<Bloom256> = None;
                for (v_idx, val) in transformed_values.iter().enumerate() {
                    let b = get_b(v_idx, val);
                    if b.is_empty() {
                        c_bloom = Some(Bloom256::ZERO);
                        break;
                    }
                    c_bloom = Some(match c_bloom {
                        None => b,
                        Some(prev) => prev.intersect(&b),
                    });
                }
                if let Some(b) = c_bloom {
                    if !b.is_empty() {
                        group_has_field = true;
                        g_bloom = g_bloom.union(&b);
                    }
                }
            }
        }

        if group_has_field && !g_bloom.is_empty() {
            group_blooms.push(g_bloom);
        } else {
            return Bloom256::ZERO;
        }
    }

    let mut total_bloom: Option<Bloom256> = None;
    for gb in group_blooms {
        total_bloom = Some(match total_bloom {
            None => gb,
            Some(prev) => prev.intersect(&gb),
        });
    }

    total_bloom.unwrap_or(Bloom256::ZERO)
}

/// Compute a mandatory needle bloom filter for a rule.
///
/// Checks canonical fields in order of selectivity (`CommandLine`, `ParentCommandLine`, `Description`, `Image`).
/// Returns `(bloom_field_bit, bloom)` where `bloom_field_bit` is the canonical slot index (0..64)
/// or `255` if no mandatory bloom filter could be soundly computed.
pub(crate) fn compute_rule_mandatory_bloom(
    conditions: &[ConditionNode],
    identifiers: &[SearchIdentifier],
) -> (u8, Bloom256) {
    const TARGET_FIELDS: [(&str, u8); 11] = [
        ("commandline", 0),
        ("parentcommandline", 3),
        ("targetobject", 19),
        ("scriptblocktext", 29),
        ("targetfilename", 18),
        ("imageloaded", 39),
        ("description", 16),
        ("queryname", 27),
        ("pipename", 28),
        ("details", 20),
        ("image", 1),
    ];

    let mandatory_idents = find_mandatory_identifiers(conditions, identifiers);
    if !mandatory_idents.is_empty() {
        for &(field_name, bit) in &TARGET_FIELDS {
            let mut field_bloom = Bloom256::ZERO;
            for &idx in &mandatory_idents {
                let b = compute_ident_bloom(&identifiers[idx], field_name);
                if !b.is_empty() {
                    field_bloom = field_bloom.union(&b);
                }
            }
            if !field_bloom.is_empty() {
                return (bit, field_bloom);
            }
        }
    }

    // Disjunctive branch intersection:
    // If no single identifier is mandatory (e.g. `1 of selection*` or `selection_1 or selection_2`),
    // check if all positive selection identifiers require the target field with shared needle bigrams.
    let non_filter_indices: Vec<usize> = identifiers
        .iter()
        .enumerate()
        .filter(|(_, id)| !id.name.starts_with("filter"))
        .map(|(idx, _)| idx)
        .collect();

    if !non_filter_indices.is_empty() {
        let results: HashMap<String, bool> = identifiers
            .iter()
            .map(|id| (id.name.clone(), false))
            .collect();

        // Soundness check: confirm with truth table evaluation that setting all non-filter
        // identifiers to false ensures no rule condition can evaluate to true.
        if !conditions.iter().any(|cond| cond.evaluate(&results)) {
            for &(field_name, bit) in &TARGET_FIELDS {
                let mut disj_bloom: Option<Bloom256> = None;
                let mut all_branches_have_field = true;

                for &idx in &non_filter_indices {
                    let b = compute_ident_bloom(&identifiers[idx], field_name);
                    if b.is_empty() {
                        all_branches_have_field = false;
                        break;
                    }
                    disj_bloom = Some(match disj_bloom {
                        None => b,
                        Some(prev) => prev.intersect(&b),
                    });
                }

                if all_branches_have_field {
                    if let Some(b) = disj_bloom {
                        if !b.is_empty() {
                            return (bit, b);
                        }
                    }
                }
            }
        }
    }

    (255, Bloom256::ZERO)
}

/// Extract a sound mandatory Sub-256 Bloom filter for unquantified literals in a regex pattern.
#[doc(hidden)]
pub fn extract_regex_mandatory_bloom(pat: &str) -> Option<Bloom256> {
    use regex_syntax::ast::parse::Parser;
    use regex_syntax::ast::Ast;

    let ast = Parser::new().parse(pat).ok()?;

    fn walk_concat(asts: &[Ast]) -> Bloom256 {
        let mut cur_run = String::new();
        let mut union_bloom = Bloom256::ZERO;

        for ast in asts {
            match ast {
                Ast::Literal(lit) => {
                    cur_run.push(lit.c);
                }
                Ast::Flags(_) => {}
                _ => {
                    if cur_run.len() >= 2 {
                        let b = crate::bloom::compute_bloom256(&cur_run.to_lowercase());
                        union_bloom = union_bloom.union(&b);
                    }
                    cur_run.clear();

                    if let Ast::Group(group) = ast {
                        let gb = walk_ast(&group.ast);
                        if !gb.is_empty() {
                            union_bloom = union_bloom.union(&gb);
                        }
                    }
                }
            }
        }

        if cur_run.len() >= 2 {
            let b = crate::bloom::compute_bloom256(&cur_run.to_lowercase());
            union_bloom = union_bloom.union(&b);
        }

        union_bloom
    }

    fn walk_ast(ast: &Ast) -> Bloom256 {
        match ast {
            Ast::Literal(lit) => {
                let s = lit.c.to_string();
                if s.len() >= 2 {
                    crate::bloom::compute_bloom256(&s.to_lowercase())
                } else {
                    Bloom256::ZERO
                }
            }
            Ast::Concat(concat) => walk_concat(&concat.asts),
            Ast::Group(group) => walk_ast(&group.ast),
            Ast::Alternation(alt) => {
                let mut intersect: Option<Bloom256> = None;
                for branch in &alt.asts {
                    let b = walk_ast(branch);
                    if b.is_empty() {
                        return Bloom256::ZERO;
                    }
                    intersect = Some(match intersect {
                        None => b,
                        Some(prev) => prev.intersect(&b),
                    });
                }
                intersect.unwrap_or(Bloom256::ZERO)
            }
            _ => Bloom256::ZERO,
        }
    }

    let b = walk_ast(&ast);
    if !b.is_empty() {
        Some(b)
    } else {
        None
    }
}

/// Check if a field condition strictly requires non-ASCII characters.
fn cond_requires_non_ascii(cond: &crate::types::FieldCondition) -> bool {
    if cond.modifiers.contains(&ValueModifier::Exists)
        || cond.modifiers.contains(&ValueModifier::Wide)
        || cond.modifiers.contains(&ValueModifier::Regex)
        || cond.values.is_empty()
    {
        return false;
    }
    cond.values.iter().all(|v| {
        let s = v.as_str_lossy();
        !s.is_empty() && !s.is_ascii()
    })
}

/// A sound single check on a field or basename.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SingleCheck {
    /// Canonical field (0..63) must contain this needle bloom.
    FieldBloom { slot: u8, bloom: Bloom256 },
    /// Canonical field (0..63) must contain at least one of these needle blooms.
    FieldBloomAny { slot: u8, blooms: Vec<Bloom256> },
    /// Canonical field (0..63) must be present in the event.
    FieldPresent(u8),
    /// Canonical field (0..63) must contain at least one non-ASCII byte.
    FieldNonAscii(u8),
    /// Event binary basename (lowercased) must match this exact name.
    ImageBasename(String),
    /// Event binary basename (lowercased) must match one of these names.
    ImageBasenameSet(Vec<String>),
    /// Event parent binary basename (lowercased) must match this exact name.
    ParentImageBasename(String),
    /// Event parent binary basename (lowercased) must match one of these names.
    ParentImageBasenameSet(Vec<String>),
    /// Event OriginalFileName basename (lowercased) must match this exact name.
    OriginalFileBasename(String),
    /// Event OriginalFileName basename (lowercased) must match one of these names.
    OriginalFileBasenameSet(Vec<String>),
    /// All of these single checks must pass (conjunction).
    All(Vec<SingleCheck>),
}

/// A sound prefilter check for a single positive branch/identifier in a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BranchCheck {
    /// Single sound check.
    Single(SingleCheck),
    /// Disjunction of checks (one per group in the identifier).
    /// All groups must have a sound check; the identifier is possible if ANY group's check passes.
    Disjunction(Vec<SingleCheck>),
    /// Branch has no sound simple prefilter (always passes).
    Any,
}

fn compute_condition_check(cond: &crate::types::FieldCondition) -> Option<SingleCheck> {
    if cond.modifiers.contains(&ValueModifier::Exists) {
        return None;
    }

    // 1. Image basename
    if cond.field_folded == "image" {
        let mut bases = Vec::with_capacity(cond.values.len());
        let mut all_valid = !cond.values.is_empty();
        for val in &cond.values {
            let s = val.as_str_lossy();
            if let Some(base) = extract_image_basename(&s, &cond.modifiers) {
                bases.push(base);
            } else {
                all_valid = false;
                break;
            }
        }
        if all_valid && !bases.is_empty() {
            bases.sort_unstable();
            bases.dedup();
            if bases.len() == 1 {
                return Some(SingleCheck::ImageBasename(bases.swap_remove(0)));
            } else {
                return Some(SingleCheck::ImageBasenameSet(bases));
            }
        }
    }

    // 2. OriginalFileName basename
    if cond.field_folded == "originalfilename" {
        let mut bases = Vec::with_capacity(cond.values.len());
        let mut all_valid = !cond.values.is_empty();
        for val in &cond.values {
            let s = val.as_str_lossy();
            if let Some(base) = extract_image_basename(&s, &cond.modifiers) {
                bases.push(base);
            } else {
                all_valid = false;
                break;
            }
        }
        if all_valid && !bases.is_empty() {
            bases.sort_unstable();
            bases.dedup();
            if bases.len() == 1 {
                return Some(SingleCheck::OriginalFileBasename(bases.swap_remove(0)));
            } else {
                return Some(SingleCheck::OriginalFileBasenameSet(bases));
            }
        }
    }

    // 3. ParentImage basename
    if cond.field_folded == "parentimage" {
        let mut bases = Vec::with_capacity(cond.values.len());
        let mut all_valid = !cond.values.is_empty();
        for val in &cond.values {
            let s = val.as_str_lossy();
            if let Some(base) = extract_image_basename(&s, &cond.modifiers) {
                bases.push(base);
            } else {
                all_valid = false;
                break;
            }
        }
        if all_valid && !bases.is_empty() {
            bases.sort_unstable();
            bases.dedup();
            if bases.len() == 1 {
                return Some(SingleCheck::ParentImageBasename(bases.swap_remove(0)));
            } else {
                return Some(SingleCheck::ParentImageBasenameSet(bases));
            }
        }
    }

    let slot = crate::field_mask::field_bit(&cond.field_folded)?;

    // 4. Non-ASCII check
    if cond_requires_non_ascii(cond) {
        return Some(SingleCheck::FieldNonAscii(slot));
    }

    // 5. Regex mandatory bloom extraction
    if cond.modifiers.contains(&ValueModifier::Regex)
        && !cond.modifiers.contains(&ValueModifier::Wide)
        && !cond.modifiers.contains(&ValueModifier::FieldRef)
    {
        if cond.values.len() == 1 {
            let pat = cond.values[0].as_str_lossy();
            if let Some(b) = extract_regex_mandatory_bloom(&pat) {
                return Some(SingleCheck::FieldBloom { slot, bloom: b });
            }
        } else if !cond.values.is_empty() {
            let mut blooms = Vec::with_capacity(cond.values.len());
            let mut all_have = true;
            let mut intersect: Option<Bloom256> = None;
            for val in &cond.values {
                let pat = val.as_str_lossy();
                if let Some(b) = extract_regex_mandatory_bloom(&pat) {
                    blooms.push(b);
                    intersect = Some(match intersect {
                        None => b,
                        Some(prev) => prev.intersect(&b),
                    });
                } else {
                    all_have = false;
                    break;
                }
            }
            if let Some(ib) = intersect {
                if !ib.is_empty() {
                    return Some(SingleCheck::FieldBloom { slot, bloom: ib });
                }
            }
            if all_have && blooms.len() <= 256 {
                return Some(SingleCheck::FieldBloomAny { slot, blooms });
            }
        }
    }

    // 6. FieldBloom on canonical fields (non-regex)
    if !cond.modifiers.contains(&ValueModifier::Regex)
        && !cond.modifiers.contains(&ValueModifier::FieldRef)
        && !cond.modifiers.contains(&ValueModifier::Wide)
        && !cond.modifiers.contains(&ValueModifier::Cidr)
        && !cond.modifiers.contains(&ValueModifier::Gt)
        && !cond.modifiers.contains(&ValueModifier::Gte)
        && !cond.modifiers.contains(&ValueModifier::Lt)
        && !cond.modifiers.contains(&ValueModifier::Lte)
    {
        let transformed_values = if cond.modifiers.iter().any(ValueModifier::is_transform) {
            crate::matcher::apply_transforms(&cond.values, &cond.modifiers)
        } else {
            std::borrow::Cow::Borrowed(&cond.values[..])
        };

        let get_b = |idx: usize, val: &crate::types::SigmaValue| -> Bloom256 {
            if cond.modifiers.iter().any(ValueModifier::is_transform) {
                crate::bloom::compute_bloom256(&val.as_str_lossy().to_lowercase())
            } else {
                get_cond_value_bloom(cond, idx)
            }
        };

        let is_all = cond.modifiers.contains(&ValueModifier::All);
        if is_all {
            let mut c_bloom = Bloom256::ZERO;
            for (v_idx, val) in transformed_values.iter().enumerate() {
                let b = get_b(v_idx, val);
                if !b.is_empty() {
                    c_bloom = c_bloom.union(&b);
                }
            }
            if !c_bloom.is_empty() {
                return Some(SingleCheck::FieldBloom {
                    slot,
                    bloom: c_bloom,
                });
            }
        } else if transformed_values.len() == 1 {
            let b = get_b(0, &transformed_values[0]);
            if !b.is_empty() {
                return Some(SingleCheck::FieldBloom { slot, bloom: b });
            }
        } else if !transformed_values.is_empty() {
            let mut intersect: Option<Bloom256> = None;
            let mut all_have_blooms = true;
            let mut blooms = Vec::with_capacity(transformed_values.len());
            for (v_idx, val) in transformed_values.iter().enumerate() {
                let b = get_b(v_idx, val);
                if b.is_empty() {
                    all_have_blooms = false;
                } else {
                    blooms.push(b);
                }
                intersect = Some(match intersect {
                    None => b,
                    Some(prev) => prev.intersect(&b),
                });
            }
            if let Some(ib) = intersect {
                if ib.count_ones() >= 3 {
                    return Some(SingleCheck::FieldBloom { slot, bloom: ib });
                }
            }
            if all_have_blooms && blooms.len() <= 256 {
                return Some(SingleCheck::FieldBloomAny { slot, blooms });
            }
        }
    }

    // 7. Field presence check on any canonical field that does not have Exists modifier
    if !cond
        .values
        .iter()
        .any(|v| matches!(v, crate::types::SigmaValue::Null))
    {
        return Some(SingleCheck::FieldPresent(slot));
    }

    None
}

fn compute_group_check(group: &crate::types::FieldConditionGroup) -> Option<SingleCheck> {
    let mut checks: Vec<SingleCheck> = Vec::with_capacity(group.conditions.len());
    for cond in &group.conditions {
        if let Some(c) = compute_condition_check(cond) {
            if !checks.contains(&c) {
                checks.push(c);
            }
        }
    }

    // Remove redundant FieldPresent checks if a stronger check on the same slot exists
    let mut covered_slots = 0u64;
    for c in &checks {
        match c {
            SingleCheck::FieldBloom { slot, .. }
            | SingleCheck::FieldBloomAny { slot, .. }
            | SingleCheck::FieldNonAscii(slot) => {
                covered_slots |= 1u64 << *slot;
            }
            SingleCheck::ImageBasename(_) | SingleCheck::ImageBasenameSet(_) => {
                covered_slots |= 1u64 << 1;
            }
            SingleCheck::ParentImageBasename(_) | SingleCheck::ParentImageBasenameSet(_) => {
                covered_slots |= 1u64 << 2;
            }
            SingleCheck::OriginalFileBasename(_) | SingleCheck::OriginalFileBasenameSet(_) => {
                covered_slots |= 1u64 << 4;
            }
            _ => {}
        }
    }
    checks.retain(|c| {
        if let SingleCheck::FieldPresent(slot) = c {
            (covered_slots & (1u64 << *slot)) == 0
        } else {
            true
        }
    });

    if checks.is_empty() {
        None
    } else if checks.len() == 1 {
        Some(checks.swap_remove(0))
    } else {
        checks.sort_by_key(|c| match c {
            SingleCheck::ImageBasename(_) => 0,
            SingleCheck::ParentImageBasename(_) => 1,
            SingleCheck::OriginalFileBasename(_) => 2,
            SingleCheck::ImageBasenameSet(_) => 3,
            SingleCheck::ParentImageBasenameSet(_) => 4,
            SingleCheck::OriginalFileBasenameSet(_) => 5,
            SingleCheck::FieldNonAscii(_) => 6,
            SingleCheck::FieldPresent(_) => 7,
            SingleCheck::FieldBloom { .. } => 8,
            SingleCheck::FieldBloomAny { .. } => 9,
            SingleCheck::All(_) => 10,
        });
        Some(SingleCheck::All(checks))
    }
}

fn compute_ident_branch_check(ident: &SearchIdentifier) -> BranchCheck {
    if ident.groups.is_empty() {
        return BranchCheck::Any;
    }

    if ident.groups.len() == 1 {
        match compute_group_check(&ident.groups[0]) {
            Some(check) => BranchCheck::Single(check),
            None => BranchCheck::Any,
        }
    } else {
        let mut checks = Vec::with_capacity(ident.groups.len());
        for group in &ident.groups {
            match compute_group_check(group) {
                Some(check) => checks.push(check),
                None => return BranchCheck::Any,
            }
        }

        // Optimization: if all groups are ImageBasename / ImageBasenameSet, merge into one set
        if checks.iter().all(|c| {
            matches!(
                c,
                SingleCheck::ImageBasename(_) | SingleCheck::ImageBasenameSet(_)
            )
        }) {
            let mut union_bases = Vec::new();
            for c in checks {
                match c {
                    SingleCheck::ImageBasename(b) => union_bases.push(b),
                    SingleCheck::ImageBasenameSet(bases) => union_bases.extend(bases),
                    _ => {}
                }
            }
            union_bases.sort_unstable();
            union_bases.dedup();
            return BranchCheck::Single(SingleCheck::ImageBasenameSet(union_bases));
        }

        // Optimization: if all groups are ParentImageBasename / ParentImageBasenameSet, merge
        if checks.iter().all(|c| {
            matches!(
                c,
                SingleCheck::ParentImageBasename(_) | SingleCheck::ParentImageBasenameSet(_)
            )
        }) {
            let mut union_bases = Vec::new();
            for c in checks {
                match c {
                    SingleCheck::ParentImageBasename(b) => union_bases.push(b),
                    SingleCheck::ParentImageBasenameSet(bases) => union_bases.extend(bases),
                    _ => {}
                }
            }
            union_bases.sort_unstable();
            union_bases.dedup();
            return BranchCheck::Single(SingleCheck::ParentImageBasenameSet(union_bases));
        }

        // Optimization: if all groups are OriginalFileBasename / OriginalFileBasenameSet, merge
        if checks.iter().all(|c| {
            matches!(
                c,
                SingleCheck::OriginalFileBasename(_) | SingleCheck::OriginalFileBasenameSet(_)
            )
        }) {
            let mut union_bases = Vec::new();
            for c in checks {
                match c {
                    SingleCheck::OriginalFileBasename(b) => union_bases.push(b),
                    SingleCheck::OriginalFileBasenameSet(bases) => union_bases.extend(bases),
                    _ => {}
                }
            }
            union_bases.sort_unstable();
            union_bases.dedup();
            return BranchCheck::Single(SingleCheck::OriginalFileBasenameSet(union_bases));
        }

        BranchCheck::Disjunction(checks)
    }
}

/// A sound prefilter check across all positive branches of a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuleFeasibility {
    pub(crate) checks: Vec<BranchCheck>,
    pub(crate) feasibility_bitmask: u64,
}

impl Default for RuleFeasibility {
    fn default() -> Self {
        Self {
            checks: Vec::new(),
            feasibility_bitmask: u64::MAX,
        }
    }
}

/// Compute branch feasibility checks across all positive identifiers of a rule.
///
/// Uses AST truth-table evaluation to map each subset of possible branches to whether
/// the rule condition could be satisfied.
pub(crate) fn compute_rule_feasibility(
    conditions: &[ConditionNode],
    identifiers: &[SearchIdentifier],
) -> RuleFeasibility {
    let non_filter: Vec<&SearchIdentifier> = identifiers
        .iter()
        .filter(|id| !id.name.starts_with("filter"))
        .collect();

    if non_filter.is_empty() || non_filter.len() > 32 {
        return RuleFeasibility::default();
    }

    let mut checks = Vec::with_capacity(non_filter.len());
    let mut any_count = 0usize;
    for id in &non_filter {
        let check = compute_ident_branch_check(id);
        if check == BranchCheck::Any {
            any_count += 1;
        }
        checks.push(check);
    }

    if any_count == non_filter.len() {
        return RuleFeasibility::default();
    }

    let mut results: HashMap<String, bool> = identifiers
        .iter()
        .map(|id| (id.name.clone(), false))
        .collect();

    let n = non_filter.len();
    if n <= 6 {
        let num_masks = 1usize << n;
        let mut feasibility_bitmask = 0u64;

        for possible_mask in 0..num_masks {
            let mut can_fire = false;
            for sub_assignment in 0..num_masks {
                if (sub_assignment & !possible_mask) != 0 {
                    continue;
                }
                for (bit, id) in non_filter.iter().enumerate() {
                    *results.get_mut(&id.name).expect("id present") =
                        (sub_assignment >> bit) & 1 == 1;
                }
                if conditions.iter().any(|cond| cond.evaluate(&results)) {
                    can_fire = true;
                    break;
                }
            }
            if can_fire {
                feasibility_bitmask |= 1u64 << possible_mask;
            }
        }

        RuleFeasibility {
            checks,
            feasibility_bitmask,
        }
    } else {
        // For 6 < n <= 32:
        // Test if the rule can fire when all non-filter branches are false.
        for id in &non_filter {
            *results.get_mut(&id.name).expect("id present") = false;
        }
        let can_fire_all_false = conditions.iter().any(|cond| cond.evaluate(&results));
        let feasibility_bitmask = if can_fire_all_false { u64::MAX } else { !1u64 };

        RuleFeasibility {
            checks,
            feasibility_bitmask,
        }
    }
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

    #[test]
    fn test_compute_rule_mandatory_bloom_single_condition() {
        let yaml = r#"
title: Test Mandatory Bloom Single
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'mimikatz'
    condition: selection
"#;
        let (_rule, identifiers) = parse_rule(yaml).unwrap();
        let conditions = vec![compile_condition("selection", &identifiers).unwrap()];
        let (field_bit, bloom) = compute_rule_mandatory_bloom(&conditions, &identifiers);
        assert_eq!(field_bit, 0); // CommandLine is slot 0
        assert!(!bloom.is_empty());
        let test_bloom = crate::bloom::compute_bloom256("powershell.exe -c mimikatz");
        assert!(bloom.is_subset_of(&test_bloom));
        let benign_bloom = crate::bloom::compute_bloom256("chrome.exe --type=gpu-process");
        assert!(!bloom.is_subset_of(&benign_bloom));
    }

    #[test]
    fn test_compute_rule_mandatory_bloom_disjunction_shared_bigrams() {
        let yaml = r#"
title: Test Mandatory Bloom Disjunction
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'vssadmin delete shadows'
            - 'vssadmin resize shadowstorage'
    condition: selection
"#;
        let (_rule, identifiers) = parse_rule(yaml).unwrap();
        let conditions = vec![compile_condition("selection", &identifiers).unwrap()];
        let (field_bit, bloom) = compute_rule_mandatory_bloom(&conditions, &identifiers);
        assert_eq!(field_bit, 0);
        assert!(!bloom.is_empty());
        let test_match = crate::bloom::compute_bloom256("cmd.exe /c vssadmin delete shadows /all");
        assert!(bloom.is_subset_of(&test_match));
        let benign = crate::bloom::compute_bloom256("chrome.exe --type=gpu-process");
        assert!(!bloom.is_subset_of(&benign));
    }

    #[test]
    fn test_compute_rule_mandatory_bloom_or_condition_not_mandatory() {
        let yaml = r#"
title: Test Non-Mandatory
logsource:
    category: process_creation
    product: windows
detection:
    sel1:
        CommandLine|contains: 'mimikatz'
    sel2:
        CommandLine|contains: 'sekurlsa'
    condition: sel1 or sel2
"#;
        let (_rule, identifiers) = parse_rule(yaml).unwrap();
        let conditions = vec![compile_condition("sel1 or sel2", &identifiers).unwrap()];
        let (field_bit, bloom) = compute_rule_mandatory_bloom(&conditions, &identifiers);
        assert_eq!(field_bit, 255);
        assert!(bloom.is_empty());
    }

    #[test]
    fn test_extract_regex_mandatory_bloom() {
        // Pattern with prefix and middle unquantified literals
        let pat = r#"(?i)\.exe["']?\s+[^\"]{0,64}werfaultsecure\.exe["']?\s+\d{2,10}"#;
        let bloom = extract_regex_mandatory_bloom(pat).expect("must extract mandatory bloom");
        assert!(!bloom.is_empty());

        let matching_haystack = crate::bloom::compute_bloom256(
            r#"c:\path\to\something.exe "c:\temp\werfaultsecure.exe" 1234"#,
        );
        assert!(bloom.is_subset_of(&matching_haystack));

        let benign_haystack = crate::bloom::compute_bloom256(
            r#""c:\program files\google\chrome\application\chrome.exe" --type=gpu-process"#,
        );
        assert!(!bloom.is_subset_of(&benign_haystack));

        // Purely wildcard/repetition regex has no mandatory bloom
        let dynamic_pat = r#".*[\d]+"#;
        assert_eq!(extract_regex_mandatory_bloom(dynamic_pat), None);

        // Alternation where both branches share a mandatory token
        let alt_pat = r#"Invoke-Mimikatz|Invoke-AllChecks"#;
        let alt_bloom =
            extract_regex_mandatory_bloom(alt_pat).expect("must extract shared token bloom");
        let token_bloom = crate::bloom::compute_bloom256("invoke-");
        assert!(token_bloom.is_subset_of(&alt_bloom));
    }

    #[test]
    fn test_compute_group_check_conjunction() {
        let yaml = r#"
title: Test Conjunction Group Check
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|contains|all:
            - 'C:\Users\'
            - '\AppData\Local\Temp\'
            - '\DismHost.exe'
        IntegrityLevel:
            - 'High'
            - 'System'
    condition: selection
"#;
        let (_rule, identifiers) = parse_rule(yaml).unwrap();
        let check = compute_group_check(&identifiers[0].groups[0]).expect("must compute check");
        match check {
            SingleCheck::All(checks) => {
                assert_eq!(checks.len(), 2);
                // Checks should include ParentImage bloom (slot 2) and IntegrityLevel bloom (slot 8)
                let slots: Vec<u8> = checks
                    .iter()
                    .map(|c| match c {
                        SingleCheck::FieldBloom { slot, .. } => *slot,
                        SingleCheck::FieldBloomAny { slot, .. } => *slot,
                        _ => 255,
                    })
                    .collect();
                assert!(slots.contains(&2));
                assert!(slots.contains(&8));
            }
            other => panic!("expected SingleCheck::All, got {:?}", other),
        }
    }
}
