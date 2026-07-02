// =============================================================================
// Sigma Rule Engine — Corpus Replay Tests
// =============================================================================
// These tests serve the same stability purpose as a fuzz corpus, but run on
// stable Rust with zero nightly dependency.
//
// A fuzz corpus is a set of known-interesting inputs: the seeds prime the
// fuzzer, and the discovered cases are regression tests that prevent
// re-introducing a previously-found crash.
//
// Here we commit the seed inputs directly as deterministic test cases. Every
// `cargo test` run guarantees the parser and evaluator handle them without
// panicking — which is the primary safety property a fuzz run would validate.
//
// If you later want coverage-guided fuzzing (e.g. in a nightly CI job), the
// corpus directory layout expected by cargo-fuzz is documented below each
// target so it can be re-introduced without re-writing the seeds.
//
// corpus/fuzz_parse_rule/ → feeds arbitrary bytes to parse_rule()
// corpus/fuzz_evaluate_event/ → feeds structured events to evaluate_event()
// =============================================================================

#[cfg(test)]
mod corpus_replay {
    use null_sigma::{parse_rule, parse_rules, SigmaEngine};
    use std::collections::HashMap;

    // ── Seed corpus: parse_rule ───────────────────────────────────────────────

    /// Minimal valid Sigma rule — the simplest rule that must parse successfully.
    const CORPUS_MINIMAL: &str = r#"
title: Minimal Rule
logsource: {}
detection:
    sel:
        field: value
    condition: sel
"#;

    /// Full-featured rule exercising every top-level field.
    const CORPUS_FULL: &str = r#"
title: Full Rule
id: 12345678-1234-4321-abcd-123456789abc
status: stable
level: high
description: A full rule with all modifiers
author: Test Author
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
    service: sysmon
detection:
    sel:
        CommandLine|contains|all:
            - '-enc'
            - 'powershell'
        Image|endswith: '.exe'
        Image|startswith: 'C:\Windows'
    filter:
        CommandLine|contains: 'legitimate'
    condition: sel and not filter
falsepositives:
    - Legitimate admin use
"#;

    /// Rule using regex and CIDR modifiers.
    const CORPUS_REGEX_CIDR: &str = r#"
title: Regex Rule
logsource: {}
detection:
    sel:
        CommandLine|re: '(?i)(mimikatz|sekurlsa|lsadump)'
        DestinationIp|cidr: '192.168.0.0/16'
    condition: sel
"#;

    /// Multi-document YAML — two rules separated by `---`.
    const CORPUS_MULTI_DOC: &str = r#"
title: Rule A
logsource: {}
detection:
    sel:
        f: v
    condition: sel
---
title: Rule B
logsource: {}
detection:
    s1:
        a: b
    s2:
        c: d
    condition: s1 or s2
"#;

    /// Empty input — must not panic, must return a parse error.
    const CORPUS_EMPTY: &str = "";

    /// Invalid YAML that can never parse — must return an error, never panic.
    const CORPUS_INVALID: &str = "not yaml at all :::";

    /// Windows CRLF line endings throughout.
    const CORPUS_CRLF: &str =
        "title: CRLF Rule\r\nlogsource: {}\r\ndetection:\r\n    sel:\r\n        f: v\r\n    condition: sel";

    /// Deeply nested condition logic — tests the condition AST compiler at depth.
    const CORPUS_DEEP_CONDITION: &str = r#"
title: Deep Condition
logsource: {}
detection:
    s1:
        CommandLine|contains: 'a'
    s2:
        CommandLine|contains: 'b'
    s3:
        CommandLine|contains: 'c'
    s4:
        CommandLine|contains: 'd'
    f1:
        Image|endswith: 'trusted.exe'
    condition: (s1 or s2) and (s3 or s4) and not f1
"#;

    /// Rule with 50 values in a single identifier — stress-tests AC registration.
    fn corpus_many_values() -> String {
        let values: String = (0..50)
            .map(|i| format!("        - 'corpus_val_{i:03}'"))
            .collect::<Vec<_>>()
            .join("\n");
        format!(
            "title: Many Values\nlogsource: {{}}\ndetection:\n    sel:\n        CommandLine|contains:\n{values}\n    condition: sel\n"
        )
    }

    // ── Parse safety: no panic on any corpus input ────────────────────────────

    #[test]
    fn corpus_parse_minimal_succeeds() {
        let result = parse_rule(CORPUS_MINIMAL);
        assert!(
            result.is_ok(),
            "Minimal corpus seed must parse: {:?}",
            result.err()
        );
    }

    #[test]
    fn corpus_parse_full_succeeds() {
        let result = parse_rule(CORPUS_FULL);
        assert!(
            result.is_ok(),
            "Full corpus seed must parse: {:?}",
            result.err()
        );
    }

    #[test]
    fn corpus_parse_regex_cidr_succeeds() {
        let result = parse_rule(CORPUS_REGEX_CIDR);
        assert!(
            result.is_ok(),
            "Regex/CIDR corpus seed must parse: {:?}",
            result.err()
        );
    }

    #[test]
    fn corpus_parse_multi_doc_both_succeed() {
        let results = parse_rules(CORPUS_MULTI_DOC);
        let ok_count = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(
            ok_count, 2,
            "Multi-doc corpus must yield 2 successful rules, got {ok_count}"
        );
    }

    #[test]
    fn corpus_parse_empty_is_graceful_error() {
        assert!(
            parse_rule(CORPUS_EMPTY).is_err(),
            "Empty corpus seed must be an error, not Ok"
        );
    }

    #[test]
    fn corpus_parse_invalid_is_graceful_error() {
        assert!(
            parse_rule(CORPUS_INVALID).is_err(),
            "Invalid YAML seed must be an error, not Ok"
        );
    }

    #[test]
    fn corpus_parse_crlf_succeeds() {
        let result = parse_rule(CORPUS_CRLF);
        assert!(
            result.is_ok(),
            "CRLF line endings must parse correctly: {:?}",
            result.err()
        );
    }

    #[test]
    fn corpus_parse_deep_condition_succeeds() {
        let result = parse_rule(CORPUS_DEEP_CONDITION);
        assert!(
            result.is_ok(),
            "Deep condition corpus seed must parse: {:?}",
            result.err()
        );
    }

    #[test]
    fn corpus_parse_many_values_succeeds() {
        let yaml = corpus_many_values();
        let result = parse_rule(&yaml);
        assert!(
            result.is_ok(),
            "50-value corpus seed must parse: {:?}",
            result.err()
        );
    }

    // ── Evaluate safety: no panic on any corpus-derived event ────────────────

    /// Load all corpus rules into the engine and verify it can evaluate a set of
    /// representative events derived from the corpus without panicking.
    #[test]
    fn corpus_evaluate_all_rules_no_panic() {
        let mut engine = SigmaEngine::new();

        // Load every valid corpus seed
        let valid_rules = [
            CORPUS_MINIMAL,
            CORPUS_FULL,
            CORPUS_REGEX_CIDR,
            CORPUS_DEEP_CONDITION,
        ];
        for rule in &valid_rules {
            let _ = engine.load_rule(rule); // partial load is acceptable
        }
        let (_, errors) = engine.load_rules(CORPUS_MULTI_DOC);
        assert!(
            errors.is_empty(),
            "Multi-doc corpus must load cleanly: {:?}",
            errors
        );

        assert!(
            engine.rule_count() >= 6,
            "At least 6 corpus rules must load"
        );

        // Corpus-derived events: a representative sample of matching and
        // non-matching events drawn from the field values in the corpus rules.
        let events: Vec<HashMap<String, String>> = vec![
            // Matching: contains 'value'
            [("field", "value")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            // Matching: multi-doc rule B
            [("a", "b")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            // Matching: deep condition hit (a + c, not trusted.exe)
            [("CommandLine", "a c run"), ("Image", "cmd.exe")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            // Non-matching: deep condition filtered (trusted.exe)
            [("CommandLine", "a c run"), ("Image", "trusted.exe")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            // Matching: CRLF rule
            [("f", "v")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            // Empty event
            HashMap::new(),
            // Event with 50 arbitrary fields
            (0..50usize)
                .map(|i| (format!("field_{i}"), format!("val_{i}")))
                .collect(),
        ];

        let results = engine.evaluate_batch(&events);
        assert_eq!(
            results.len(),
            events.len(),
            "evaluate_batch must return one result per event"
        );
        // Must complete without panic — results are not asserted on correctness here
    }
}
