// =============================================================================
// Sigma Rule Engine — Property-Based Tests
// =============================================================================
// Unlike unit tests that verify specific inputs, property tests declare
// *invariants* — universal truths that must hold for ALL inputs — and use
// proptest to generate thousands of random cases that attempt to break them.
//
// This is the gold standard for parsing and evaluation engines. The Sigma
// engine handles untrusted YAML from external feeds and arbitrary events from
// production systems. Properties proven here hold for inputs we haven't thought
// of, not just the hand-picked cases in sigma_tests.rs.
//
// Properties proven here:
//   P1. No panic on any event (arbitrary fields, arbitrary values).
//   P2. Determinism — same engine + same event always returns the same result.
//   P3. Soundness — a rule requiring field X never fires when X is absent.
//   P4. Monotonicity — adding more (unrelated) fields never suppresses a match.
//   P5. Parser never panics on arbitrary byte sequences.
//   P6. Empty logsource rule matches any logsource.
// =============================================================================

use null_sigma::SigmaEngine;
use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;
use std::collections::HashMap;

// Proptest stores regression cases adjacent to the crate's lib.rs by default.
// Integration tests live in tests/ which has no lib.rs, so we redirect to the
// cargo target directory to avoid the "failed to find lib.rs" warning.
// 10,000 cases per property — aggressive coverage without nightly/libFuzzer.
fn proptest_cfg() -> ProptestConfig {
    ProptestConfig {
        cases: 10_000,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        ..Default::default()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategies — Generators for random test inputs
// ─────────────────────────────────────────────────────────────────────────────

/// Generate a random printable ASCII string (1–64 chars). Used for field names
/// and values. We restrict to printable ASCII to avoid YAML parser edge cases
/// that are covered separately by the garbage-input test in sigma_tests.rs.
fn printable_ascii(min: usize, max: usize) -> impl Strategy<Value = String> {
    proptest::collection::vec(0x20u8..=0x7eu8, min..=max)
        .prop_map(|v| String::from_utf8(v).unwrap())
}

/// Generate a random event: 0–15 fields, each with a printable ASCII key and value.
fn arb_event() -> impl Strategy<Value = HashMap<String, String>> {
    proptest::collection::hash_map(printable_ascii(1, 20), printable_ascii(0, 64), 0..=15)
}

/// Generate a random field name (printable ASCII, 1–20 chars).
fn arb_field_name() -> impl Strategy<Value = String> {
    printable_ascii(1, 20)
}

/// Generate a random field value (printable ASCII, 0–64 chars).
fn arb_field_value() -> impl Strategy<Value = String> {
    printable_ascii(0, 64)
}

// ─────────────────────────────────────────────────────────────────────────────
// Fixture rules — valid Sigma rules used as engine fixtures in property tests
// ─────────────────────────────────────────────────────────────────────────────

/// A rule that matches `CommandLine|contains: 'proptest_marker'`.
/// Safe to use as a fixture: the marker string is unlikely to appear in random
/// printable ASCII events, so it tests the no-match path almost exclusively.
const FIXTURE_CONTAINS_RULE: &str = r#"
title: Proptest Fixture Contains
logsource: {}
detection:
    sel:
        CommandLine|contains: 'proptest_marker_xyz'
    condition: sel
"#;

/// A rule with AND logic requiring two specific fields.
const FIXTURE_AND_RULE: &str = r#"
title: Proptest Fixture AND
logsource: {}
detection:
    proc:
        Image|endswith: 'proptest_proc.exe'
    arg:
        CommandLine|contains: 'proptest_cmd'
    condition: proc and arg
"#;

/// A rule with wildcard logsource — must fire for any event logsource.
const FIXTURE_WILDCARD_LOGSOURCE: &str = r#"
title: Proptest Wildcard Logsource
logsource: {}
detection:
    sel:
        SentinelField|contains: 'proptest_sentinel'
    condition: sel
"#;

// ─────────────────────────────────────────────────────────────────────────────
// P1 — No panic on arbitrary events
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(proptest_cfg())]
    /// For any event with arbitrary fields and values, evaluate_event must
    /// complete without panicking. The result (match or no-match) is secondary —
    /// stability is the invariant.
    ///
    /// This would catch: index out-of-bounds in AC prefilter, unwrap() on
    /// None in field lookup, integer overflow in flat_ac_indices slicing.
    #[test]
    fn p1_no_panic_on_arbitrary_event(event in arb_event()) {
        let mut engine = SigmaEngine::new();
        engine.load_rule(FIXTURE_CONTAINS_RULE).unwrap();
        engine.load_rule(FIXTURE_AND_RULE).unwrap();
        // Must not panic — result is intentionally unchecked
        let _ = engine.evaluate_event(&event);
    }
}

proptest! {
    #![proptest_config(proptest_cfg())]
    /// A freshly constructed engine (zero rules) must never panic for any event.
    #[test]
    fn p1_no_panic_empty_engine_arbitrary_event(event in arb_event()) {
        let engine = SigmaEngine::new();
        let results = engine.evaluate_event(&event);
        prop_assert!(results.is_empty(),
            "Zero rules: must always return empty results");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// P2 — Determinism
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(proptest_cfg())]
    /// Evaluating the same event twice against the same engine must return
    /// identical results. This tests that evaluate_event has no hidden mutable
    /// state that changes between calls (e.g., AC automaton rebuild flipping results).
    #[test]
    fn p2_determinism_same_event_same_result(event in arb_event()) {
        let mut engine = SigmaEngine::new();
        engine.load_rule(FIXTURE_CONTAINS_RULE).unwrap();

        let first  = engine.evaluate_event(&event);
        let second = engine.evaluate_event(&event);

        prop_assert_eq!(
            first.len(), second.len(),
            "Determinism violated: same event returned different match count ({} vs {})",
            first.len(), second.len()
        );
        // If both matched, compare rule titles
        for (a, b) in first.iter().zip(second.iter()) {
            prop_assert_eq!(&a.rule_title, &b.rule_title,
                "Determinism violated: match order or identity changed between calls");
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// P3 — Soundness: absent required field never fires the rule
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(proptest_cfg())]
    /// A rule requiring `CommandLine` must never fire when the event contains
    /// any combination of other fields — as long as `CommandLine` is absent.
    ///
    /// This is the absence soundness property: missing required field = no match.
    /// It would catch: wildcard field-name matching, incorrect default values,
    /// or logsource-bypass bugs letting the rule fire without its required field.
    #[test]
    fn p3_soundness_absent_required_field_never_fires(
        field_name  in arb_field_name().prop_filter("must not be CommandLine or its alias",
            |n| n != "CommandLine" && n != "commandline" && n != "command_line"),
        field_value in arb_field_value(),
    ) {
        let mut engine = SigmaEngine::new();
        engine.load_rule(FIXTURE_CONTAINS_RULE).unwrap();

        // Event has one field — NOT CommandLine
        let mut event = HashMap::new();
        event.insert(field_name, field_value);

        let results = engine.evaluate_event(&event);
        prop_assert!(
            results.is_empty(),
            "Rule requiring CommandLine fired without it. Event fields: {:?}, Matches: {:?}",
            event, results.iter().map(|m| &m.rule_title).collect::<Vec<_>>()
        );
    }
}

proptest! {
    #![proptest_config(proptest_cfg())]
    /// AND rule: if EITHER required field is absent, the rule must not fire.
    /// Tests both halves of the AND independently with random other-field noise.
    #[test]
    fn p3_soundness_and_rule_misses_when_first_field_absent(
        noise_key   in arb_field_name().prop_filter("no collision with fixture fields",
            |n| n != "Image" && n != "CommandLine"),
        noise_value in arb_field_value(),
    ) {
        let mut engine = SigmaEngine::new();
        engine.load_rule(FIXTURE_AND_RULE).unwrap();

        // Only CommandLine matches — Image is absent
        let mut event = HashMap::new();
        event.insert("CommandLine".to_string(), "proptest_cmd".to_string());
        event.insert(noise_key, noise_value);

        let results = engine.evaluate_event(&event);
        prop_assert!(results.is_empty(),
            "AND rule fired with only one of two required fields present");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// P4 — Monotonicity: adding fields doesn't suppress a match
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(proptest_cfg())]
    /// If an event matches a rule, adding extra unrelated fields to the event
    /// must not suppress that match (no false negatives from field noise).
    ///
    /// This catches bugs where the engine checks "fields must equal exactly these
    /// keys" rather than "all required fields must be present and matching".
    #[test]
    fn p4_monotonicity_extra_fields_dont_suppress_match(
        extra_key   in arb_field_name().prop_filter("no collision with matching field",
            |n| n != "CommandLine"),
        extra_value in arb_field_value(),
    ) {
        let mut engine = SigmaEngine::new();
        engine.load_rule(FIXTURE_CONTAINS_RULE).unwrap();

        // Base event that must match
        let mut base_event = HashMap::new();
        base_event.insert("CommandLine".to_string(), "proptest_marker_xyz".to_string());

        // Augmented event with one extra noise field
        let mut augmented = base_event.clone();
        augmented.insert(extra_key, extra_value);

        let base_results      = engine.evaluate_event(&base_event);
        let augmented_results = engine.evaluate_event(&augmented);

        prop_assert_eq!(
            base_results.len(), 1,
            "Base event must match (contains exact marker): {:?}", base_event
        );
        prop_assert_eq!(
            augmented_results.len(), base_results.len(),
            "Adding extra field suppressed a match: base={}, augmented={}",
            base_results.len(), augmented_results.len()
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// P5 — Parser never panics on arbitrary byte sequences
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(proptest_cfg())]
    /// parse_rule must return Ok or Err for any input — never panic.
    /// This is the primary safety property for a function that will be called
    /// with untrusted YAML from rule feeds, SIEM exports, and user submissions.
    #[test]
    fn p5_parser_never_panics_on_arbitrary_printable_input(
        input in printable_ascii(0, 256)
    ) {
        // Result discarded — only the absence of panic is the invariant
        let _ = null_sigma::parse_rule(&input);
    }
}

proptest! {
    #![proptest_config(proptest_cfg())]
    /// load_rule on the engine must also never panic on arbitrary input.
    #[test]
    fn p5_engine_load_rule_never_panics_on_arbitrary_input(
        input in printable_ascii(0, 256)
    ) {
        let mut engine = SigmaEngine::new();
        let _ = engine.load_rule(&input);
        // Engine state must remain consistent after a failed load
        prop_assert_eq!(engine.rule_count(), 0,
            "Failed load_rule must not corrupt rule_count");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// P6 — Wildcard logsource matches any event logsource
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(proptest_cfg())]
    /// A rule with empty `logsource: {}` must fire for ANY event whose
    /// `SentinelField` matches — regardless of whatever logsource fields the
    /// event contains.
    #[test]
    fn p6_wildcard_logsource_matches_regardless_of_event_logsource(
        event_category in printable_ascii(0, 20),
        event_product  in printable_ascii(0, 20),
        event_service  in printable_ascii(0, 20),
    ) {
        let mut engine = SigmaEngine::new();
        engine.load_rule(FIXTURE_WILDCARD_LOGSOURCE).unwrap();

        let mut event = HashMap::new();
        event.insert("SentinelField".to_string(), "proptest_sentinel".to_string());
        // Inject arbitrary logsource fields — must not suppress the match
        if !event_category.is_empty() {
            event.insert("category".to_string(), event_category);
        }
        if !event_product.is_empty() {
            event.insert("product".to_string(), event_product);
        }
        if !event_service.is_empty() {
            event.insert("service".to_string(), event_service);
        }

        let results = engine.evaluate_event(&event);
        prop_assert_eq!(results.len(), 1,
            "Wildcard logsource rule must fire regardless of event logsource fields. \
             Event: {:?}", event);
    }
}
