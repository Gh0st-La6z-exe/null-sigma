//! Benchmark null-sigma vs rsigma-eval head-to-head on identical SigmaHQ rules and events.

use null_sigma_harness::{
    default_rule_dir, find_all_yaml_files, load_rule_dir, NullSigmaBench, SigmaRustBench, TauBench,
};
use rsigma_eval::event::JsonEvent;
use rsigma_eval::Engine as RsigmaEngine;
use rsigma_parser::parse_sigma_yaml;
use serde_json::Value;
use std::time::Instant;

fn main() {
    println!("===============================================================================");
    println!("          HEAD-TO-HEAD: NULL-SIGMA vs RSIGMA-EVAL vs TAU vs SIGMA-RUST        ");
    println!("===============================================================================");

    let rule_dir = default_rule_dir();
    println!("[+] Loading rules from: {}", rule_dir.display());

    // ─────────────────────────────────────────────────────────────────────────
    // Full 1,193 Process Creation Ingestion Audit
    // ─────────────────────────────────────────────────────────────────────────
    println!("\n--- Full 1,193 Process Creation Rule Ingestion Audit ---");
    let mut all_paths = Vec::new();
    find_all_yaml_files(&rule_dir, &mut all_paths).unwrap();
    all_paths.sort();
    let total_all = all_paths.len();

    let mut ns_all_ok = 0;
    let mut rsigma_all_ok = 0;
    let mut tau_all_ok = 0;

    for p in &all_paths {
        if let Ok(y) = std::fs::read_to_string(p) {
            let mut ns_test = null_sigma::SigmaEngine::new();
            if ns_test.load_rule(&y).is_ok() {
                ns_all_ok += 1;
            }
            if let Ok(col) = parse_sigma_yaml(&y) {
                let mut rsigma_test = RsigmaEngine::new();
                if rsigma_test.add_rules(&col.rules).is_empty() {
                    rsigma_all_ok += 1;
                }
            }
            if null_sigma_harness::convert::sigma_to_tau(&y).is_ok() {
                tau_all_ok += 1;
            }
        }
    }
    println!("  Total Rule Files Discovered : {}", total_all);
    println!(
        "  null-sigma Ingestion Parity : {} / {} ({:.1}%)",
        ns_all_ok,
        total_all,
        ns_all_ok as f64 * 100.0 / total_all as f64
    );
    println!(
        "  rsigma-eval Ingestion Parity: {} / {} ({:.1}%)",
        rsigma_all_ok,
        total_all,
        rsigma_all_ok as f64 * 100.0 / total_all as f64
    );
    println!(
        "  tau-engine Ingestion Parity : {} / {} ({:.1}%)",
        tau_all_ok,
        total_all,
        tau_all_ok as f64 * 100.0 / total_all as f64
    );

    let report = load_rule_dir(&rule_dir).expect("failed to load rule directory");
    let common = report.common();
    println!("\n[+] Common 3-engine rules: {}", common.len());

    let mut valid_yamls = Vec::new();
    for r in &common {
        if let Ok(col) = parse_sigma_yaml(&r.yaml) {
            let mut test_eng = RsigmaEngine::new();
            if test_eng.add_rules(&col.rules).is_empty() {
                valid_yamls.push(r.yaml.clone());
            }
        }
    }
    println!(
        "[+] Common 4-engine rules (including rsigma): {}\n",
        valid_yamls.len()
    );

    let refs: Vec<&str> = valid_yamls.iter().map(String::as_str).collect();

    println!("[+] Compiling null-sigma engine...");
    let t0 = Instant::now();
    let ns_bench = NullSigmaBench::new(&refs);
    let ns_compile_time = t0.elapsed();
    println!(
        "    -> Compiled {} rules in {:?}",
        refs.len(),
        ns_compile_time
    );

    println!("[+] Compiling rsigma engine (candidate index + bloom)...");
    let t0 = Instant::now();
    let mut parsed_rules = Vec::new();
    for y in &refs {
        let col = parse_sigma_yaml(y).unwrap();
        parsed_rules.extend(col.rules);
    }
    let mut rsigma_engine = RsigmaEngine::new();
    let errors = rsigma_engine.add_rules(&parsed_rules);
    assert!(
        errors.is_empty(),
        "rsigma add_rules had errors: {:?}",
        errors
    );
    let rsigma_compile_time = t0.elapsed();
    println!(
        "    -> Compiled {} rules in {:?}",
        refs.len(),
        rsigma_compile_time
    );

    println!("[+] Compiling tau-engine...");
    let t0 = Instant::now();
    let tau_bench = TauBench::new(&refs);
    let tau_compile_time = t0.elapsed();
    println!(
        "    -> Compiled {} rules in {:?}\n",
        refs.len(),
        tau_compile_time
    );

    println!("[+] Pre-generating 10,000 realistic mixed telemetry events...");
    let raw_events = null_sigma_harness::gen::generate(42, 10_000);
    let ns_events: Vec<_> = raw_events
        .iter()
        .map(NullSigmaBench::prepare_event)
        .collect();
    let json_events: Vec<Value> = raw_events.iter().map(TauBench::prepare_event).collect();
    println!("[+] Dataset ready.\n");

    let eval_count = 50_000;

    // ─────────────────────────────────────────────────────────────────────────
    // 1. null-sigma
    // ─────────────────────────────────────────────────────────────────────────
    println!("--- Testing null-sigma (Single-Core) ---");
    let t0 = Instant::now();
    let mut ns_hits = 0;
    for i in 0..eval_count {
        let evt = &ns_events[i % ns_events.len()];
        ns_hits += ns_bench.count_matches(evt);
    }
    let ns_elapsed = t0.elapsed();
    let ns_eps = eval_count as f64 / ns_elapsed.as_secs_f64();
    let ns_us = (ns_elapsed.as_secs_f64() * 1_000_000.0) / eval_count as f64;
    println!(
        "  null-sigma: {:8.2} µs/eval | {:8.0} EPS | hits: {}",
        ns_us, ns_eps, ns_hits
    );

    // ─────────────────────────────────────────────────────────────────────────
    // 2. rsigma-eval
    // ─────────────────────────────────────────────────────────────────────────
    println!("--- Testing rsigma-eval (Single-Core) ---");
    let t0 = Instant::now();
    let mut rsigma_hits = 0;
    for i in 0..eval_count {
        let evt = &json_events[i % json_events.len()];
        let json_evt = JsonEvent::borrow(evt);
        rsigma_hits += rsigma_engine.evaluate(&json_evt).len();
    }
    let rsigma_elapsed = t0.elapsed();
    let rsigma_eps = eval_count as f64 / rsigma_elapsed.as_secs_f64();
    let rsigma_us = (rsigma_elapsed.as_secs_f64() * 1_000_000.0) / eval_count as f64;
    println!(
        "  rsigma-eval: {:8.2} µs/eval | {:8.0} EPS | hits: {}",
        rsigma_us, rsigma_eps, rsigma_hits
    );

    // ─────────────────────────────────────────────────────────────────────────
    // 3. tau-engine (Chainsaw)
    // ─────────────────────────────────────────────────────────────────────────
    println!("--- Testing tau-engine (Single-Core) ---");
    let tau_eval_count = 5_000;
    let t0 = Instant::now();
    let mut tau_hits = 0;
    for i in 0..tau_eval_count {
        let evt = &json_events[i % json_events.len()];
        tau_hits += tau_bench.count_matches(evt);
    }
    let tau_elapsed = t0.elapsed();
    let tau_eps = tau_eval_count as f64 / tau_elapsed.as_secs_f64();
    let tau_us = (tau_elapsed.as_secs_f64() * 1_000_000.0) / tau_eval_count as f64;
    println!(
        "  tau-engine: {:8.2} µs/eval | {:8.0} EPS | hits: {} (scaled to 5k)\n",
        tau_us, tau_eps, tau_hits
    );

    // ─────────────────────────────────────────────────────────────────────────
    // 4. sigma-rust (Reference)
    // ─────────────────────────────────────────────────────────────────────────
    println!("--- Testing sigma-rust (Single-Core) ---");
    let t0 = Instant::now();
    let sr_bench = SigmaRustBench::new(&refs);
    let sr_compile_time = t0.elapsed();
    println!(
        "    -> Loaded {} rules in {:?}",
        refs.len(),
        sr_compile_time
    );

    let sr_eval_count = 200;
    let sr_events: Vec<sigma_rust::Event> = raw_events
        .iter()
        .take(sr_eval_count)
        .map(SigmaRustBench::prepare_event)
        .collect();

    let t0 = Instant::now();
    let mut sr_hits = 0;
    for evt in &sr_events {
        sr_hits += sr_bench.count_matches(evt);
    }
    let sr_elapsed = t0.elapsed();
    let sr_eps = sr_eval_count as f64 / sr_elapsed.as_secs_f64();
    let sr_us = (sr_elapsed.as_secs_f64() * 1_000_000.0) / sr_eval_count as f64;
    println!(
        "  sigma-rust: {:8.2} µs/eval | {:8.0} EPS | hits: {} (scaled to 200)\n",
        sr_us, sr_eps, sr_hits
    );

    println!("===============================================================================");
    println!("                                SUMMARY RATIOS                                 ");
    println!("===============================================================================");
    println!(
        "null-sigma vs rsigma-eval : {:5.2}× throughput ({:.0} vs {:.0} EPS)",
        ns_eps / rsigma_eps,
        ns_eps,
        rsigma_eps
    );
    println!(
        "null-sigma vs tau-engine  : {:5.2}× throughput ({:.0} vs {:.0} EPS)",
        ns_eps / tau_eps,
        ns_eps,
        tau_eps
    );
    println!(
        "null-sigma vs sigma-rust  : {:5.2}× throughput ({:.0} vs {:.0} EPS)",
        ns_eps / sr_eps,
        ns_eps,
        sr_eps
    );
    println!(
        "Compile Speed Ratio       : {:5.2}× faster than rsigma-eval ({:?} vs {:?})",
        rsigma_compile_time.as_secs_f64() / ns_compile_time.as_secs_f64(),
        ns_compile_time,
        rsigma_compile_time
    );
    println!("===============================================================================");
}
