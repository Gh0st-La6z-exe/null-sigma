/// Minimal end-to-end example: load a Sigma rule, feed it a suspicious event.
///
/// Run with:
///
/// ```text
/// cargo run -p null-sigma --example detect_powershell
/// ```
///
/// Expected output:
///
/// ```text
/// [ALERT] Matched 1 rule(s)
///   - Suspicious Encoded PowerShell  [high]  score=0.75
///     tags: attack.execution, attack.t1059.001
/// ```
use null_sigma::SigmaEngine;
use std::collections::HashMap;

/// Sigma rule that detects Base64-encoded PowerShell invocations.
///
/// This is a minimal reproduction of a real detection that ships with the
/// Sigma community rule set (rule ID: `d7da0a5c-...`). Production rules would
/// include `falsepositives`, `references`, and a richer logsource block.
const RULE: &str = r#"
title: Suspicious Encoded PowerShell
id: d7da0a5c-0001-0000-0000-000000000001
status: experimental
description: Detects invocation of PowerShell with Base64-encoded commands.
logsource:
  category: process_creation
  product: windows
detection:
  encoded:
    CommandLine|contains:
      - '-EncodedCommand'
      - '-enc '
      - '-ec '
  condition: encoded
level: high
tags:
  - attack.execution
  - attack.t1059.001
"#;

fn main() {
    // ── 1. Build engine and load the rule ────────────────────────────────────
    let mut engine = SigmaEngine::new();
    let rule_id = engine
        .load_rule(RULE)
        .expect("rule YAML is valid — if this panics, the YAML is malformed");

    println!("Loaded rule: {rule_id}");
    println!("Engine has {} rule(s)\n", engine.rule_count());

    // ── 2. Construct a synthetic Windows process-creation event ──────────────
    //
    // In production this event comes from a Sysmon EventID 1 log parsed by
    // a connector (e.g., sysmon_winlogbeat_connector.py), enriched into a
    // flat HashMap<String, String> by the backend ingestion pipeline.
    let event: HashMap<String, String> = [
        ("CommandLine", "powershell.exe -EncodedCommand SQBFAFgA..."),
        (
            "Image",
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        ),
        ("User", "CORP\\jsmith"),
        ("ParentImage", "C:\\Windows\\explorer.exe"),
        ("category", "process_creation"),
        ("product", "windows"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();

    // ── 3. Evaluate ───────────────────────────────────────────────────────────
    let matches = engine.evaluate_event(&event);

    if matches.is_empty() {
        println!("No matches — event is benign (or rule didn't load correctly).");
        return;
    }

    println!("[ALERT] Matched {} rule(s)", matches.len());
    for m in &matches {
        println!(
            "  - {}  [{}]  score={:.2}",
            m.rule_title,
            m.rule_level.as_str(),
            m.rule_level.to_score(),
        );
        if !m.tags.is_empty() {
            println!("    tags: {}", m.tags.join(", "));
        }
    }

    // ── 4. Demonstrate batch evaluation ───────────────────────────────────────
    let benign: HashMap<String, String> = [
        ("CommandLine", "notepad.exe README.txt"),
        ("category", "process_creation"),
        ("product", "windows"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();

    let batch_results = engine.evaluate_batch(&[event.clone(), benign]);
    println!("\nBatch ({} events):", batch_results.len());
    for (i, result) in batch_results.iter().enumerate() {
        println!("  event[{i}]: {} match(es)", result.matches.len());
    }
}
