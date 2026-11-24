use std::collections::HashMap;
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::time::Instant;

fn find_all_yaml_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            find_all_yaml_files(&p, out);
        } else if matches!(p.extension().and_then(|s| s.to_str()), Some("yml" | "yaml")) {
            out.push(p);
        }
    }
}

fn main() {
    let base_dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../corpus/sigmahq/rules/windows");
    let net_dir = base_dir.join("network_connection");

    let mut files = Vec::new();
    find_all_yaml_files(&net_dir, &mut files);
    files.sort();

    let mut parsed_rules = Vec::new();
    for f in &files {
        let c = std::fs::read_to_string(f).unwrap();
        if let Ok(col) = rsigma_parser::parse_sigma_yaml(&c) {
            parsed_rules.extend(col.rules);
        }
    }

    println!(
        "Total parsed rules for rsigma in network_connection: {}",
        parsed_rules.len()
    );
    let mut eng = rsigma_eval::Engine::new();
    eng.add_rules(&parsed_rules);

    // Let's print out what logsource categories/products are in parsed_rules
    let mut logsources: HashMap<String, usize> = HashMap::new();
    for r in &parsed_rules {
        let ls = format!(
            "cat={:?}, prod={:?}, serv={:?}",
            r.logsource.category, r.logsource.product, r.logsource.service
        );
        *logsources.entry(ls).or_default() += 1;
    }
    println!(
        "Logsources in 51 network_connection rules: {:#?}",
        logsources
    );

    // Now test our net_event:
    let mut net_event = HashMap::new();
    net_event.insert("category".into(), "network_connection".into());
    net_event.insert("product".into(), "windows".into());
    net_event.insert("EventID".into(), "3".into());
    net_event.insert("DestinationIp".into(), "185.220.101.5".into());
    net_event.insert("DestinationPort".into(), "4444".into());
    net_event.insert("Image".into(), r"C:\Windows\System32\powershell.exe".into());

    let val = serde_json::to_value(&net_event).unwrap();
    let r_event = rsigma_eval::event::JsonEvent::borrow(&val);

    let matches = eng.evaluate(&r_event);
    println!("Matches fired by rsigma on net_event: {}", matches.len());

    // Also let's test null-sigma:
    let mut ns_engine = null_sigma::SigmaEngine::new();
    for f in &files {
        let c = std::fs::read_to_string(f).unwrap();
        let _ = ns_engine.load_rule(&c);
    }
    let ns_matches = ns_engine.evaluate_event(&net_event);
    println!(
        "Matches fired by null-sigma on net_event: {}",
        ns_matches.len()
    );

    // Let's test latency of both
    let iters = 10_000;
    for _ in 0..100 {
        black_box(eng.evaluate(&r_event).len());
        black_box(ns_engine.evaluate_event(&net_event).len());
    }

    let t0 = Instant::now();
    for _ in 0..iters {
        black_box(eng.evaluate(&r_event).len());
    }
    let rsigma_us = t0.elapsed().as_secs_f64() * 1e6 / iters as f64;

    let t1 = Instant::now();
    for _ in 0..iters {
        black_box(ns_engine.evaluate_event(&net_event).len());
    }
    let ns_us = t1.elapsed().as_secs_f64() * 1e6 / iters as f64;

    println!("Latency on net_event across 51 rules:");
    println!(
        "  rsigma-eval: {:.2} µs ({:.0} EPS)",
        rsigma_us,
        1e6 / rsigma_us
    );
    println!("  null-sigma : {:.2} µs ({:.0} EPS)", ns_us, 1e6 / ns_us);
}
