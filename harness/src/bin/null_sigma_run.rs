//! Minimal end-to-end CLI runner for Tier B wall-clock comparison
//! (and a precursor to roadmap item 4's `null-sigma-cli`).
//!
//! Reads a Sigma rule directory and a JSONL event file, evaluates every event
//! through `SigmaEngine::evaluate_json_count`, and prints the match count.
//!
//! Usage: null_sigma_run <rule_dir> <events.jsonl>

use std::io::{BufRead, BufReader};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: null_sigma_run <rule_dir> <events.jsonl>");
        std::process::exit(2);
    }
    let rule_dir = std::path::Path::new(&args[1]);
    let events_path = std::path::Path::new(&args[2]);

    let start = std::time::Instant::now();
    let mut engine = null_sigma::SigmaEngine::new();
    let mut paths: Vec<_> = std::fs::read_dir(rule_dir)
        .expect("cannot read rule dir")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "yml" || e == "yaml"))
        .collect();
    paths.sort();
    // Bulk load as one multi-document stream: the AC automaton is rebuilt
    // once at the end instead of once per rule.
    let joined = paths
        .iter()
        .map(|p| std::fs::read_to_string(p).expect("cannot read rule"))
        .collect::<Vec<_>>()
        .join("\n---\n");
    let (loaded_ids, errors) = engine.load_rules(&joined);
    let (loaded, skipped) = (loaded_ids.len(), errors.len());
    let load_ms = start.elapsed().as_millis();

    let start = std::time::Instant::now();
    let reader = BufReader::new(std::fs::File::open(events_path).expect("cannot open events"));
    let mut events = 0u64;
    let mut matches = 0u64;
    for line in reader.lines() {
        let line = line.expect("read error");
        if line.trim().is_empty() {
            continue;
        }
        events += 1;
        matches += engine
            .evaluate_json_count(&line)
            .expect("bad event JSON") as u64;
    }
    let scan = start.elapsed();

    eprintln!(
        "rules: {loaded} loaded, {skipped} skipped ({load_ms} ms) | events: {events} | \
         matches: {matches} | scan: {:.3}s ({:.0} events/sec)",
        scan.as_secs_f64(),
        events as f64 / scan.as_secs_f64()
    );
    println!("{matches}");
}
