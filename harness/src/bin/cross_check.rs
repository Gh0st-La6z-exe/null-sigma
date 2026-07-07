//! Correctness cross-check — must be run (and its findings recorded) BEFORE
//! any performance numbers are published. A wrong engine being fast is not a
//! win.
//!
//! Loads the SigmaHQ process_creation rules into all three engines, reports
//! per-engine load compatibility, then evaluates every common rule against
//! every generated event and compares per-rule hit vectors across engines.
//!
//! Usage: cargo run --release --bin cross_check [rule_dir] [event_count]

use std::collections::HashMap;

use null_sigma_harness::{gen, load_rule_dir, null_sigma_hits, rule_title};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let rule_dir = args
        .get(1)
        .map_or_else(null_sigma_harness::default_rule_dir, std::path::PathBuf::from);
    let event_count: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(2000);

    println!("rule dir : {}", rule_dir.display());
    let report = load_rule_dir(&rule_dir).expect("failed to read rule dir");
    let (total, ns, tau, sr) = report.loaded_counts();
    println!("\n== Load compatibility ==");
    println!("total rule files     : {total}");
    println!("null-sigma loaded    : {ns} ({:.1}%)", pct(ns, total));
    println!("tau-engine converted : {tau} ({:.1}%)  [Chainsaw conversion path]", pct(tau, total));
    println!("sigma-rust loaded    : {sr} ({:.1}%)", pct(sr, total));

    // Top tau-engine conversion failure reasons.
    let mut tau_reasons: HashMap<String, usize> = HashMap::new();
    for r in &report.rules {
        if let Err(e) = &r.tau {
            let key = e.split(':').next().unwrap_or(e).to_string();
            *tau_reasons.entry(key).or_insert(0) += 1;
        }
    }
    let mut tau_reasons: Vec<_> = tau_reasons.into_iter().collect();
    tau_reasons.sort_by(|a, b| b.1.cmp(&a.1));
    println!("\ntau-engine conversion failures by reason:");
    for (reason, count) in &tau_reasons {
        println!("  {count:5}  {reason}");
    }
    let mut sr_reasons: HashMap<String, usize> = HashMap::new();
    for r in &report.rules {
        if let Err(e) = &r.sigma_rust {
            let key = e.split(':').next().unwrap_or(e).to_string();
            *sr_reasons.entry(key).or_insert(0) += 1;
        }
    }
    let mut sr_reasons: Vec<_> = sr_reasons.into_iter().collect();
    sr_reasons.sort_by(|a, b| b.1.cmp(&a.1));
    if !sr_reasons.is_empty() {
        println!("\nsigma-rust load failures by reason:");
        for (reason, count) in sr_reasons.iter().take(10) {
            println!("  {count:5}  {reason}");
        }
    }

    let common = report.common();
    println!("\ncommon set (all three engines): {} rules", common.len());

    // ── Build engines over the common set ───────────────────────────────
    let yamls: Vec<&str> = common.iter().map(|r| r.yaml.as_str()).collect();
    let titles: Vec<String> = common.iter().map(|r| rule_title(&r.yaml)).collect();

    let mut ns_engine = null_sigma::SigmaEngine::new();
    let mut ns_ids = Vec::with_capacity(yamls.len());
    for y in &yamls {
        ns_ids.push(ns_engine.load_rule(y).expect("load"));
    }
    let tau_bench = null_sigma_harness::TauBench::new(&yamls);
    let sr_bench = null_sigma_harness::SigmaRustBench::new(&yamls);

    // ── Evaluate the shared event stream ────────────────────────────────
    let events = gen::generate(42, event_count);
    println!("events   : {event_count} (seed 42)\n== Cross-check ==");

    let mut cells: u64 = 0;
    let mut ns_total = 0u64;
    let mut tau_total = 0u64;
    let mut sr_total = 0u64;
    // rule index -> (ns_vs_tau, ns_vs_sr, tau_vs_sr) disagreement counts
    let mut disagree: HashMap<usize, [u64; 3]> = HashMap::new();

    for event in &events {
        let ns_event = null_sigma_harness::NullSigmaBench::prepare_event(event);
        let tau_event = null_sigma_harness::TauBench::prepare_event(event);
        let sr_event = null_sigma_harness::SigmaRustBench::prepare_event(event);

        let ns = null_sigma_hits(&ns_engine, &ns_ids, &ns_event);
        let tau = tau_bench.hits(&tau_event);
        let sr = sr_bench.hits(&sr_event);

        for i in 0..yamls.len() {
            cells += 1;
            ns_total += u64::from(ns[i]);
            tau_total += u64::from(tau[i]);
            sr_total += u64::from(sr[i]);
            if ns[i] != tau[i] {
                disagree.entry(i).or_default()[0] += 1;
            }
            if ns[i] != sr[i] {
                disagree.entry(i).or_default()[1] += 1;
            }
            if tau[i] != sr[i] {
                disagree.entry(i).or_default()[2] += 1;
            }
        }
    }

    println!("rule×event evaluations : {cells}");
    println!("total hits — null-sigma: {ns_total}, tau-engine: {tau_total}, sigma-rust: {sr_total}");

    let ns_tau: u64 = disagree.values().map(|d| d[0]).sum();
    let ns_sr: u64 = disagree.values().map(|d| d[1]).sum();
    let tau_sr: u64 = disagree.values().map(|d| d[2]).sum();
    println!("\npairwise disagreement (rule×event cells):");
    println!("  null-sigma vs tau-engine : {ns_tau} ({:.4}%)", pct64(ns_tau, cells));
    println!("  null-sigma vs sigma-rust : {ns_sr} ({:.4}%)", pct64(ns_sr, cells));
    println!("  tau-engine vs sigma-rust : {tau_sr} ({:.4}%)", pct64(tau_sr, cells));

    let mut rows: Vec<(usize, [u64; 3])> = disagree.into_iter().collect();
    rows.sort_by(|a, b| (b.1[0] + b.1[1] + b.1[2]).cmp(&(a.1[0] + a.1[1] + a.1[2])));
    if rows.is_empty() {
        println!("\nAll three engines agree on every rule×event cell.");
    } else {
        println!("\ntop disagreeing rules (ns/tau, ns/sr, tau/sr):");
        for (idx, d) in rows.iter().take(15) {
            println!("  [{:4} {:4} {:4}]  {}", d[0], d[1], d[2], titles[*idx]);
        }
    }
}

fn pct(n: usize, d: usize) -> f64 {
    if d == 0 {
        0.0
    } else {
        n as f64 * 100.0 / d as f64
    }
}

fn pct64(n: u64, d: u64) -> f64 {
    if d == 0 {
        0.0
    } else {
        n as f64 * 100.0 / d as f64
    }
}
