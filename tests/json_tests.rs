//! Unit and integration tests for the `json` feature: nested telemetry
//! flattening semantics, adversarial guards, and end-to-end evaluation
//! against realistic event fixtures (ECS, Sysmon, CloudTrail).
#![cfg(feature = "json")]

use null_sigma::json::{
    flatten_str, flatten_str_with, flatten_value, FlattenError, FlattenOptions,
};
use null_sigma::SigmaEngine;

// ─────────────────────────────────────────────────────────────────────────────
// Flattening semantics
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn flat_object_passes_through() {
    let event = flatten_str(r#"{"CommandLine": "cmd /c whoami", "User": "SYSTEM"}"#).unwrap();
    assert_eq!(event["CommandLine"], "cmd /c whoami");
    assert_eq!(event["User"], "SYSTEM");
    assert_eq!(event.len(), 2);
}

#[test]
fn nested_objects_become_dot_paths() {
    let event =
        flatten_str(r#"{"process": {"name": "cmd.exe", "parent": {"name": "explorer.exe"}}}"#)
            .unwrap();
    assert_eq!(event["process.name"], "cmd.exe");
    assert_eq!(event["process.parent.name"], "explorer.exe");
    assert_eq!(event.len(), 2);
}

#[test]
fn scalars_render_canonically() {
    let event = flatten_str(
        r#"{"int": 42, "neg": -7, "float": 3.5, "yes": true, "no": false, "s": "text"}"#,
    )
    .unwrap();
    assert_eq!(event["int"], "42");
    assert_eq!(event["neg"], "-7");
    assert_eq!(event["float"], "3.5");
    assert_eq!(event["yes"], "true");
    assert_eq!(event["no"], "false");
    assert_eq!(event["s"], "text");
}

/// i64/u64 boundaries must round-trip exactly — no float precision loss for
/// large counters, timestamps, or event record IDs.
#[test]
fn numeric_boundaries_exact() {
    let event = flatten_str(
        r#"{"imin": -9223372036854775808, "imax": 9223372036854775807, "u64": 18446744073709551615}"#,
    )
    .unwrap();
    assert_eq!(event["imin"], "-9223372036854775808");
    assert_eq!(event["imax"], "9223372036854775807");
    assert_eq!(event["u64"], "18446744073709551615");
}

/// JSON null → empty string, so Sigma `field: null` (matches empty) works.
#[test]
fn null_becomes_empty_string() {
    let event = flatten_str(r#"{"TargetUser": null}"#).unwrap();
    assert_eq!(event["TargetUser"], "");
}

#[test]
fn null_field_matches_sigma_null_condition() {
    let yaml = r#"
title: Null Field Rule
logsource: {}
detection:
    sel:
        TargetUser: null
    condition: sel
"#;
    let mut engine = SigmaEngine::new();
    engine.load_rule(yaml).unwrap();

    let matches = engine.evaluate_json(r#"{"TargetUser": null}"#).unwrap();
    assert_eq!(matches.len(), 1, "JSON null must satisfy `field: null`");

    let matches = engine.evaluate_json(r#"{"TargetUser": "admin"}"#).unwrap();
    assert!(matches.is_empty());
}

#[test]
fn empty_object_produces_no_fields() {
    let event = flatten_str("{}").unwrap();
    assert!(event.is_empty());
}

#[test]
fn nested_empty_object_produces_no_fields() {
    let event = flatten_str(r#"{"a": {}}"#).unwrap();
    assert!(event.is_empty(), "empty nested object has nothing to match");
}

#[test]
fn unicode_keys_and_values_preserved() {
    let event = flatten_str(r#"{"процесс": {"имя": "cmd.exe"}, "emoji": "⚠️"}"#).unwrap();
    assert_eq!(event["процесс.имя"], "cmd.exe");
    assert_eq!(event["emoji"], "⚠️");
}

// ─────────────────────────────────────────────────────────────────────────────
// Array semantics
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn empty_array_becomes_empty_string() {
    let event = flatten_str(r#"{"tags": []}"#).unwrap();
    assert_eq!(event["tags"], "");
}

/// Single-element arrays collapse to the base key — one hash, one IP, etc.
/// should look exactly like a plain field.
#[test]
fn single_element_array_collapses_to_base_key() {
    let event = flatten_str(r#"{"ip": ["10.0.0.1"]}"#).unwrap();
    assert_eq!(event["ip"], "10.0.0.1");
    assert!(
        !event.contains_key("ip.0"),
        "no indexed key for single element"
    );
}

/// Multi-element arrays produce indexed keys AND a newline-joined base key.
#[test]
fn multi_element_array_indexed_plus_joined() {
    let event = flatten_str(r#"{"Hashes": ["md5=aaa", "sha1=bbb", "sha256=ccc"]}"#).unwrap();
    assert_eq!(event["Hashes.0"], "md5=aaa");
    assert_eq!(event["Hashes.1"], "sha1=bbb");
    assert_eq!(event["Hashes.2"], "sha256=ccc");
    assert_eq!(event["Hashes"], "md5=aaa\nsha1=bbb\nsha256=ccc");
}

/// The joined base key is what makes `Field|contains` behave as
/// "any element matches" — the semantics real rules expect for multi-value
/// fields like Hashes.
#[test]
fn array_contains_matches_any_element() {
    let yaml = r#"
title: Hash Match
logsource: {}
detection:
    sel:
        Hashes|contains: 'sha1=bbb'
    condition: sel
"#;
    let mut engine = SigmaEngine::new();
    engine.load_rule(yaml).unwrap();

    let matches = engine
        .evaluate_json(r#"{"Hashes": ["md5=aaa", "sha1=bbb"]}"#)
        .unwrap();
    assert_eq!(matches.len(), 1, "contains must match any array element");

    let matches = engine
        .evaluate_json(r#"{"Hashes": ["md5=aaa", "sha1=zzz"]}"#)
        .unwrap();
    assert!(matches.is_empty());
}

#[test]
fn array_of_objects_flattens_by_index() {
    let event = flatten_str(r#"{"Records": [{"user": "alice"}, {"user": "bob"}]}"#).unwrap();
    assert_eq!(event["Records.0.user"], "alice");
    assert_eq!(event["Records.1.user"], "bob");
    assert!(
        !event.contains_key("Records"),
        "object elements are not joinable scalars — no base key"
    );
}

#[test]
fn mixed_array_joins_only_scalars() {
    let event = flatten_str(r#"{"mixed": ["a", {"k": "v"}, "b"]}"#).unwrap();
    assert_eq!(event["mixed.0"], "a");
    assert_eq!(event["mixed.1.k"], "v");
    assert_eq!(event["mixed.2"], "b");
    assert_eq!(event["mixed"], "a\nb", "joined base key skips containers");
}

#[test]
fn nested_arrays_flatten_by_index() {
    let event = flatten_str(r#"{"m": [[1, 2], [3]]}"#).unwrap();
    assert_eq!(event["m.0.0"], "1");
    assert_eq!(event["m.0.1"], "2");
    assert_eq!(event["m.1"], "3", "inner single-element array collapses");
}

// ─────────────────────────────────────────────────────────────────────────────
// Collision policy
// ─────────────────────────────────────────────────────────────────────────────

/// A literal "a.b" key and nested a→b both map to path `a.b`.
/// First write wins; serde_json maps iterate in sorted key order, so
/// `"a"` (nested) sorts before `"a.b"` (literal) — the nested value wins
/// deterministically, and nothing is silently overwritten.
#[test]
fn dot_key_collision_first_write_wins_deterministic() {
    let event = flatten_str(r#"{"a": {"b": "nested"}, "a.b": "literal"}"#).unwrap();
    assert_eq!(event.len(), 1);
    assert_eq!(event["a.b"], "nested");

    // Same input, reversed source order in the document — identical result.
    let event2 = flatten_str(r#"{"a.b": "literal", "a": {"b": "nested"}}"#).unwrap();
    assert_eq!(
        event2["a.b"], "nested",
        "result must not depend on document order"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Guards (fail loud)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn invalid_json_is_parse_error() {
    let err = flatten_str("{not json").unwrap_err();
    assert!(matches!(err, FlattenError::Parse(_)));
}

#[test]
fn top_level_array_rejected() {
    let err = flatten_str(r#"[{"a": 1}]"#).unwrap_err();
    assert_eq!(err, FlattenError::NotAnObject);
}

#[test]
fn top_level_scalar_rejected() {
    let err = flatten_str("42").unwrap_err();
    assert_eq!(err, FlattenError::NotAnObject);
}

#[test]
fn depth_guard_rejects_deep_nesting() {
    // Build JSON nested deeper than the limit: {"a":{"a":{...}}}
    let depth = 80;
    let mut json = String::new();
    for _ in 0..depth {
        json.push_str(r#"{"a":"#);
    }
    json.push('1');
    json.push_str(&"}".repeat(depth));

    let err = flatten_str(&json).unwrap_err();
    assert_eq!(
        err,
        FlattenError::DepthExceeded { max_depth: 64 },
        "default guard must reject 80-deep nesting"
    );

    // With a raised limit the same document flattens fine.
    let opts = FlattenOptions {
        max_depth: 128,
        ..FlattenOptions::default()
    };
    let event = flatten_str_with(&json, opts).unwrap();
    assert_eq!(event.len(), 1);
}

#[test]
fn depth_at_exact_limit_is_accepted() {
    // Depth counts nesting levels; a top-level scalar is depth 1.
    let opts = FlattenOptions {
        max_depth: 3,
        ..FlattenOptions::default()
    };
    // a.b.c = scalar at depth 3 — accepted.
    let ok = flatten_str_with(r#"{"a": {"b": {"c": 1}}}"#, opts).unwrap();
    assert_eq!(ok["a.b.c"], "1");
    // One level deeper — rejected.
    let err = flatten_str_with(r#"{"a": {"b": {"c": {"d": 1}}}}"#, opts).unwrap_err();
    assert_eq!(err, FlattenError::DepthExceeded { max_depth: 3 });
}

#[test]
fn field_cap_rejects_amplification() {
    let opts = FlattenOptions {
        max_fields: 10,
        ..FlattenOptions::default()
    };
    // 11 scalar fields — one over the cap.
    let pairs: Vec<String> = (0..11).map(|i| format!("\"k{i}\": {i}")).collect();
    let json = format!("{{{}}}", pairs.join(", "));
    let err = flatten_str_with(&json, opts).unwrap_err();
    assert_eq!(err, FlattenError::FieldsExceeded { max_fields: 10 });

    // Exactly at the cap — accepted.
    let pairs: Vec<String> = (0..10).map(|i| format!("\"k{i}\": {i}")).collect();
    let json = format!("{{{}}}", pairs.join(", "));
    assert_eq!(flatten_str_with(&json, opts).unwrap().len(), 10);
}

#[test]
fn flatten_value_accepts_prebuilt_json() {
    let value = serde_json::json!({"proc": {"pid": 1234}});
    let event = flatten_value(&value).unwrap();
    assert_eq!(event["proc.pid"], "1234");
}

// ─────────────────────────────────────────────────────────────────────────────
// End-to-end fixtures: realistic telemetry shapes
// ─────────────────────────────────────────────────────────────────────────────

const ECS_FIXTURE: &str = include_str!("fixtures/ecs_process_creation.json");
const SYSMON_FIXTURE: &str = include_str!("fixtures/sysmon_process_creation.json");
const CLOUDTRAIL_FIXTURE: &str = include_str!("fixtures/cloudtrail_console_login.json");

/// ECS-shaped process event: nested `process.command_line`, dotted rule field.
#[test]
fn ecs_fixture_end_to_end() {
    let yaml = r#"
title: ECS Encoded PowerShell
logsource: {}
detection:
    sel:
        process.command_line|contains: '-EncodedCommand'
    condition: sel
"#;
    let mut engine = SigmaEngine::new();
    engine.load_rule(yaml).unwrap();

    let matches = engine.evaluate_json(ECS_FIXTURE).unwrap();
    assert_eq!(
        matches.len(),
        1,
        "ECS fixture must match the encoded-command rule"
    );

    // Non-match control: same shape, benign command line.
    let benign = ECS_FIXTURE.replace("-EncodedCommand SQBFAFgA", "-Help");
    assert!(engine.evaluate_json(&benign).unwrap().is_empty());
}

/// Sysmon-shaped event: flat Windows fields + multi-value Hashes array.
#[test]
fn sysmon_fixture_end_to_end() {
    let yaml = r#"
title: Sysmon Mimikatz Hash
logsource:
    product: windows
detection:
    sel_img:
        Image|endswith: '\mimikatz.exe'
    sel_hash:
        Hashes|contains: 'SHA256=8815e7fe8ba1d0f04dcf05a15e92db4996b6b4a6'
    condition: sel_img or sel_hash
"#;
    let mut engine = SigmaEngine::new();
    engine.load_rule(yaml).unwrap();

    let matches = engine.evaluate_json(SYSMON_FIXTURE).unwrap();
    assert_eq!(
        matches.len(),
        1,
        "Sysmon fixture must match via the hash array"
    );

    let benign = SYSMON_FIXTURE.replace("8815e7fe8ba1d0f04dcf05a15e92db4996b6b4a6", "0000");
    assert!(engine.evaluate_json(&benign).unwrap().is_empty());
}

/// CloudTrail-shaped record: deep nesting (userIdentity.sessionContext…),
/// booleans, and numbers.
#[test]
fn cloudtrail_fixture_end_to_end() {
    let yaml = r#"
title: Root Console Login Without MFA
logsource:
    service: cloudtrail
detection:
    sel:
        eventName: ConsoleLogin
        userIdentity.type: Root
        additionalEventData.MFAUsed: 'No'
    condition: sel
"#;
    let mut engine = SigmaEngine::new();
    engine.load_rule(yaml).unwrap();

    let matches = engine.evaluate_json(CLOUDTRAIL_FIXTURE).unwrap();
    assert_eq!(
        matches.len(),
        1,
        "CloudTrail fixture must match root-no-MFA rule"
    );

    let with_mfa = CLOUDTRAIL_FIXTURE.replace(r#""MFAUsed": "No""#, r#""MFAUsed": "Yes""#);
    assert!(engine.evaluate_json(&with_mfa).unwrap().is_empty());
}

/// Corpus smoke test: the full SigmaHQ rule set evaluated against all three
/// JSON fixtures through `evaluate_json` — no panics, results returned.
/// Requires the vendored corpus (`corpus/sigmahq`, gitignored); skips
/// silently when absent so CI without the corpus stays green.
#[test]
fn corpus_smoke_evaluate_json_fixtures() {
    let corpus_dir = std::path::Path::new("corpus/sigmahq/rules");
    if !corpus_dir.exists() {
        return; // dev-only corpus not vendored — covered by local runs
    }

    fn collect(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect(&path, out);
            } else if path.extension().and_then(|e| e.to_str()) == Some("yml") {
                out.push(path);
            }
        }
    }

    let mut files = Vec::new();
    collect(corpus_dir, &mut files);
    assert!(!files.is_empty(), "corpus present but no rules found");

    let mut engine = SigmaEngine::new();
    let mut all_yaml = String::new();
    for path in &files {
        if let Ok(content) = std::fs::read_to_string(path) {
            all_yaml.push_str(&content);
            all_yaml.push_str("\n---\n");
        }
    }
    let (loaded, _errors) = engine.load_rules(&all_yaml);
    assert!(
        loaded.len() > 3000,
        "expected the bulk of the corpus to load"
    );

    // Every fixture must evaluate without panicking against the full corpus.
    for fixture in [ECS_FIXTURE, SYSMON_FIXTURE, CLOUDTRAIL_FIXTURE] {
        let result = engine.evaluate_json(fixture);
        assert!(result.is_ok(), "fixture must flatten cleanly: {result:?}");
    }
}

/// Numeric comparison against a flattened JSON number.
#[test]
fn numeric_comparison_on_flattened_field() {
    let yaml = r#"
title: High Logon Count
logsource: {}
detection:
    sel:
        stats.logon_count|gt: 100
    condition: sel
"#;
    let mut engine = SigmaEngine::new();
    engine.load_rule(yaml).unwrap();

    assert_eq!(
        engine
            .evaluate_json(r#"{"stats": {"logon_count": 250}}"#)
            .unwrap()
            .len(),
        1
    );
    assert!(engine
        .evaluate_json(r#"{"stats": {"logon_count": 5}}"#)
        .unwrap()
        .is_empty());
}

#[test]
fn evaluate_json_count_matches_evaluate_json_len() {
    let yaml = r#"
title: Count Parity
id: count-parity-001
status: test
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        Image|endswith: '\mimikatz.exe'
    condition: sel
"#;
    let mut engine = SigmaEngine::new();
    engine.load_rule(yaml).unwrap();

    let event = r#"{"category":"process_creation","product":"windows","Image":"C:\\Users\\Public\\mimikatz.exe"}"#;
    assert_eq!(
        engine.evaluate_json_count(event).unwrap(),
        engine.evaluate_json(event).unwrap().len()
    );
    assert_eq!(engine.evaluate_json_count(event).unwrap(), 1);

    let benign = r#"{"category":"process_creation","product":"windows","Image":"C:\\Windows\\notepad.exe"}"#;
    assert_eq!(engine.evaluate_json_count(benign).unwrap(), 0);
}
