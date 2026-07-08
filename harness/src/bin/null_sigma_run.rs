//! Minimal end-to-end CLI runner for Tier B wall-clock comparison
//! (and a precursor to roadmap item 4's `null-sigma-cli`).
//!
//! Reads a Sigma rule directory and a JSONL event file, evaluates every event
//! through `SigmaEngine::evaluate_event_count`, and prints the match count.
//!
//! Timing breakdown (stderr) splits scan wall clock into:
//!   read  — `BufRead::read_line` into a reused `String`
//!   parse — `serde_json::from_str`
//!   flat  — `flatten_value`
//!   eval  — `evaluate_event_count`
//!
//! Usage: null_sigma_run <rule_dir> <events.jsonl>

use std::io::{BufRead, BufReader};
use std::time::Duration;

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
    let mut reader = BufReader::new(std::fs::File::open(events_path).expect("cannot open events"));
    let mut line = String::new();
    let mut events = 0u64;
    let mut matches = 0u64;
    let mut t_read = Duration::ZERO;
    let mut t_parse = Duration::ZERO;
    let mut t_flat = Duration::ZERO;
    let mut t_eval = Duration::ZERO;

    loop {
        line.clear();
        let t0 = std::time::Instant::now();
        let n = reader.read_line(&mut line).expect("read error");
        t_read += t0.elapsed();
        if n == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        events += 1;

        let t0 = std::time::Instant::now();
        let value: serde_json::Value =
            serde_json::from_str(trimmed).expect("bad event JSON");
        t_parse += t0.elapsed();

        let t0 = std::time::Instant::now();
        let event = null_sigma::flatten_value(&value).expect("flatten failed");
        t_flat += t0.elapsed();

        let t0 = std::time::Instant::now();
        matches += engine.evaluate_event_count(&event) as u64;
        t_eval += t0.elapsed();
    }
    let scan = start.elapsed();
    let accounted = t_read + t_parse + t_flat + t_eval;
    let other = scan.saturating_sub(accounted);

    let pct = |d: Duration| -> f64 {
        if scan.is_zero() {
            0.0
        } else {
            100.0 * d.as_secs_f64() / scan.as_secs_f64()
        }
    };

    eprintln!(
        "rules: {loaded} loaded, {skipped} skipped ({load_ms} ms) | events: {events} | \
         matches: {matches} | scan: {:.3}s ({:.0} events/sec)",
        scan.as_secs_f64(),
        events as f64 / scan.as_secs_f64()
    );
    eprintln!(
        "tier_b_tax: read={:.3}s ({:.1}%) parse={:.3}s ({:.1}%) flat={:.3}s ({:.1}%) \
         eval={:.3}s ({:.1}%) other={:.3}s ({:.1}%)",
        t_read.as_secs_f64(),
        pct(t_read),
        t_parse.as_secs_f64(),
        pct(t_parse),
        t_flat.as_secs_f64(),
        pct(t_flat),
        t_eval.as_secs_f64(),
        pct(t_eval),
        other.as_secs_f64(),
        pct(other),
    );
    println!("{matches}");
}
