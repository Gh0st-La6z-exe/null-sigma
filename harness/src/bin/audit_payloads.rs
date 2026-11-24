//! Empirical Measurement of Pathological Payloads across null-sigma and rsigma-eval.
//!
//! Evaluates:
//! 1. 16 KB, 32 KB, 64 KB pathological payload bombs (common 1,110 rules).
//! 2. 256 KB, 512 KB, 1,024 KB active linear scan bombs (2,427 Windows rules).
//!
//! Accurately records latency and throughput without any estimated values.

use std::collections::HashMap;
use std::hint::black_box;
use std::path::PathBuf;
use std::time::Instant;

use null_sigma_harness::{
    find_all_yaml_files, load_rule_dir, NullSigmaBench, SigmaRustBench, TauBench,
};

fn main() {
    println!("===============================================================================");
    println!("          EMPIRICAL AUDIT: PATHOLOGICAL PAYLOADS & LINEAR SCAN                 ");
    println!("===============================================================================");

    // ─────────────────────────────────────────────────────────────────────────
    // Part 1: Common 1,110 Process Creation Rules (16 KB, 32 KB, 64 KB)
    // ─────────────────────────────────────────────────────────────────────────
    let rule_dir = null_sigma_harness::default_rule_dir();
    let report = load_rule_dir(&rule_dir).expect("failed to load rule directory");
    let common = report.common();
    let yamls: Vec<String> = common.iter().map(|r| r.yaml.clone()).collect();
    let refs: Vec<&str> = yamls.iter().map(String::as_str).collect();

    let ns_bench = NullSigmaBench::new(&refs);
    let tau_bench = TauBench::new(&refs);
    let sr_bench = SigmaRustBench::new(&refs);

    let mut parsed_rules = Vec::new();
    for y in &refs {
        if let Ok(col) = rsigma_parser::parse_sigma_yaml(y) {
            parsed_rules.extend(col.rules);
        }
    }
    let mut rsigma_eng = rsigma_eval::Engine::new();
    rsigma_eng.add_rules(&parsed_rules);

    println!("\n--- Part 1: 1,110 Rules (16 KiB, 32 KiB, 64 KiB Payloads) ---");
    let sizes_kb = [16, 32, 64];
    for &size_kb in &sizes_kb {
        let size_bytes = size_kb * 1024;
        let repeats = size_bytes / 20;
        let mut bomb = String::with_capacity(size_bytes + 100);
        bomb.push_str("cmd.exe /c ");
        for _ in 0..repeats {
            bomb.push_str("set a=1 && ");
        }
        bomb.push_str("set b=2");

        let mut event_map = HashMap::new();
        event_map.insert("category".into(), "process_creation".into());
        event_map.insert("product".into(), "windows".into());
        event_map.insert("Image".into(), r"C:\Windows\System32\cmd.exe".into());
        event_map.insert("CommandLine".into(), bomb.clone());
        event_map.insert("ParentImage".into(), r"C:\Windows\explorer.exe".into());

        let json_val = serde_json::json!({
            "category": "process_creation",
            "product": "windows",
            "Image": r"C:\Windows\System32\cmd.exe",
            "CommandLine": bomb,
            "ParentImage": r"C:\Windows\explorer.exe",
        });
        let rsigma_event = rsigma_eval::event::JsonEvent::borrow(&json_val);
        let sr_event = SigmaRustBench::prepare_event(json_val.as_object().unwrap());

        // Warmup
        for _ in 0..10 {
            black_box(ns_bench.count_matches(&event_map));
            black_box(rsigma_eng.evaluate(&rsigma_event).len());
            black_box(tau_bench.count_matches(&json_val));
        }

        let iters = 500;
        let ns_start = Instant::now();
        let mut ns_hits = 0;
        for _ in 0..iters {
            ns_hits += black_box(ns_bench.count_matches(&event_map));
        }
        let ns_us = ns_start.elapsed().as_secs_f64() * 1e6 / iters as f64;

        let rsigma_start = Instant::now();
        let mut rsigma_hits = 0;
        for _ in 0..iters {
            rsigma_hits += black_box(rsigma_eng.evaluate(&rsigma_event).len());
        }
        let rsigma_us = rsigma_start.elapsed().as_secs_f64() * 1e6 / iters as f64;

        let tau_iters = 50;
        let tau_start = Instant::now();
        let mut tau_hits = 0;
        for _ in 0..tau_iters {
            tau_hits += black_box(tau_bench.count_matches(&json_val));
        }
        let tau_us = tau_start.elapsed().as_secs_f64() * 1e6 / tau_iters as f64;

        let sr_iters = match size_kb {
            16 => 3,
            32 => 2,
            _ => 1,
        };
        let sr_start = Instant::now();
        let mut sr_hits = 0;
        for _ in 0..sr_iters {
            sr_hits += black_box(sr_bench.count_matches(&sr_event));
        }
        let sr_us = sr_start.elapsed().as_secs_f64() * 1e6 / sr_iters as f64;

        let size_mib = size_bytes as f64 / (1024.0 * 1024.0);
        let tp_ns = size_mib / (ns_us / 1e6);
        let tp_rsigma = size_mib / (rsigma_us / 1e6);
        let tp_tau = size_mib / (tau_us / 1e6);
        let tp_sr = size_mib / (sr_us / 1e6);

        println!(
            "\nPayload {:2} KiB ({} bytes) | Hits: ns={}, rsigma={}, tau={}, sr={}",
            size_kb,
            size_bytes,
            ns_hits / iters,
            rsigma_hits / iters,
            tau_hits / tau_iters,
            sr_hits / sr_iters
        );
        println!(
            "  null-sigma  : {:10.2} µs ({:6.0} EPS, {:7.2} MiB/s)",
            ns_us,
            1e6 / ns_us,
            tp_ns
        );
        println!(
            "  rsigma-eval : {:10.2} µs ({:6.0} EPS, {:7.2} MiB/s)  [null-sigma is {:.2}× faster]",
            rsigma_us,
            1e6 / rsigma_us,
            tp_rsigma,
            rsigma_us / ns_us
        );
        println!(
            "  tau-engine  : {:10.2} µs ({:6.0} EPS, {:7.2} MiB/s)  [null-sigma is {:.2}× faster]",
            tau_us,
            1e6 / tau_us,
            tp_tau,
            tau_us / ns_us
        );
        println!(
            "  sigma-rust  : {:10.2} µs ({:6.0} EPS, {:7.2} MiB/s)  [null-sigma is {:.2}× faster]",
            sr_us,
            1e6 / sr_us,
            tp_sr,
            sr_us / ns_us
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Part 2: 2,427 Unified Windows Rules (256 KB, 512 KB, 1024 KB Payloads)
    // ─────────────────────────────────────────────────────────────────────────
    println!("\n--- Part 2: 2,427 Windows Rules (256 KB, 512 KB, 1,024 KB Payloads) ---");
    let win_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../corpus/sigmahq/rules/windows");
    let mut rule_paths = Vec::new();
    find_all_yaml_files(&win_dir, &mut rule_paths).expect("failed to scan windows directory");
    rule_paths.sort();

    let mut mega_engine = null_sigma::SigmaEngine::new();
    let mut mega_rsigma_rules = Vec::new();
    for path in &rule_paths {
        if let Ok(yaml) = std::fs::read_to_string(path) {
            let _ = mega_engine.load_rule(&yaml);
            if let Ok(col) = rsigma_parser::parse_sigma_yaml(&yaml) {
                mega_rsigma_rules.extend(col.rules);
            }
        }
    }
    let mut mega_rsigma = rsigma_eval::Engine::new();
    mega_rsigma.add_rules(&mega_rsigma_rules);
    println!(
        "[+] Mega-Engines compiled: null-sigma has {} rules, rsigma-eval has {} rules",
        mega_engine.rule_count(),
        mega_rsigma_rules.len()
    );

    let large_sizes_kb = [256, 512, 1024];
    for &size_kb in &large_sizes_kb {
        let size_bytes = size_kb * 1024;
        let repeats = size_bytes / 20;
        let mut bomb = String::with_capacity(size_bytes + 100);
        bomb.push_str("cmd.exe /c ");
        for _ in 0..repeats {
            bomb.push_str("set a=1 && ");
        }
        bomb.push_str("set b=2");

        let mut evt = HashMap::new();
        evt.insert("category".into(), "process_creation".into());
        evt.insert("product".into(), "windows".into());
        evt.insert("EventID".into(), "1".into());
        evt.insert("Image".into(), r"C:\Windows\System32\cmd.exe".into());
        evt.insert("CommandLine".into(), bomb.clone());

        let json_val = serde_json::json!({
            "category": "process_creation",
            "product": "windows",
            "EventID": "1",
            "Image": r"C:\Windows\System32\cmd.exe",
            "CommandLine": bomb,
        });
        let rsigma_event = rsigma_eval::event::JsonEvent::borrow(&json_val);

        // Warmup
        for _ in 0..5 {
            black_box(mega_engine.evaluate_event_count(&evt));
            black_box(mega_rsigma.evaluate(&rsigma_event).len());
        }

        let iters = 100;
        let ns_start = Instant::now();
        let mut ns_hits = 0;
        for _ in 0..iters {
            ns_hits += black_box(mega_engine.evaluate_event_count(&evt));
        }
        let ns_us = ns_start.elapsed().as_secs_f64() * 1e6 / iters as f64;

        let rsigma_start = Instant::now();
        let mut rsigma_hits = 0;
        for _ in 0..iters {
            rsigma_hits += black_box(mega_rsigma.evaluate(&rsigma_event).len());
        }
        let rsigma_us = rsigma_start.elapsed().as_secs_f64() * 1e6 / iters as f64;

        let throughput_mib_ns = (size_bytes as f64 / (1024.0 * 1024.0)) / (ns_us / 1e6);
        let throughput_mib_rsigma = (size_bytes as f64 / (1024.0 * 1024.0)) / (rsigma_us / 1e6);

        println!(
            "Payload {:4} KiB | null-sigma: {:8.2} µs ({:5.0} EPS, {:6.1} MiB/s, {} hits) | rsigma-eval: {:8.2} µs ({:5.0} EPS, {:6.1} MiB/s, {} hits)",
            size_kb,
            ns_us,
            1e6 / ns_us,
            throughput_mib_ns,
            ns_hits / iters,
            rsigma_us,
            1e6 / rsigma_us,
            throughput_mib_rsigma,
            rsigma_hits / iters,
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Part 3: Discriminator Pre-Filtering Path (Bypassed Rules)
    // ─────────────────────────────────────────────────────────────────────────
    println!("\n--- Part 3: Discriminator Pre-Filtering Path (Bypassed Rules) ---");
    for &size_kb in &sizes_kb {
        let size_bytes = size_kb * 1024;
        let repeats = size_bytes / 20;
        let mut bomb = String::with_capacity(size_bytes + 100);
        bomb.push_str("cmd.exe /c ");
        for _ in 0..repeats {
            bomb.push_str("set a=1 && ");
        }
        bomb.push_str("set b=2");

        let mut event_map = HashMap::new();
        event_map.insert("category".into(), "registry_event".into());
        event_map.insert("product".into(), "windows".into());
        event_map.insert("Image".into(), r"C:\Windows\System32\dwm.exe".into());
        event_map.insert("CommandLine".into(), bomb.clone());
        event_map.insert(
            "ParentImage".into(),
            r"C:\Windows\System32\winlogon.exe".into(),
        );

        let json_val = serde_json::json!({
            "category": "registry_event",
            "product": "windows",
            "Image": r"C:\Windows\System32\dwm.exe",
            "CommandLine": bomb,
            "ParentImage": r"C:\Windows\System32\winlogon.exe",
        });
        let rsigma_event = rsigma_eval::event::JsonEvent::borrow(&json_val);

        // Warmup
        for _ in 0..100 {
            black_box(ns_bench.count_matches(&event_map));
            black_box(rsigma_eng.evaluate(&rsigma_event).len());
        }

        let iters = 10_000;
        let ns_start = Instant::now();
        let mut ns_hits = 0;
        for _ in 0..iters {
            ns_hits += black_box(ns_bench.count_matches(&event_map));
        }
        let ns_us = ns_start.elapsed().as_secs_f64() * 1e6 / iters as f64;

        let rsigma_start = Instant::now();
        let mut rsigma_hits = 0;
        for _ in 0..iters {
            rsigma_hits += black_box(rsigma_eng.evaluate(&rsigma_event).len());
        }
        let rsigma_us = rsigma_start.elapsed().as_secs_f64() * 1e6 / iters as f64;

        println!(
            "\nPayload {:2} KiB ({} bytes) | Hits: ns={}, rsigma={}",
            size_kb,
            size_bytes,
            ns_hits / iters,
            rsigma_hits / iters
        );
        println!(
            "  null-sigma  : {:10.2} µs ({:6.0} EPS)",
            ns_us,
            1e6 / ns_us
        );
        println!(
            "  rsigma-eval : {:10.2} µs ({:6.0} EPS)  [null-sigma is {:.2}× faster]",
            rsigma_us,
            1e6 / rsigma_us,
            rsigma_us / ns_us
        );
    }
}
