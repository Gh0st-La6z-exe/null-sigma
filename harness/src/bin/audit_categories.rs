use std::collections::HashMap;
use std::path::{Path, PathBuf};

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
    let categories = [
        ("registry", base_dir.join("registry")),
        ("file", base_dir.join("file")),
        ("network_connection", base_dir.join("network_connection")),
        ("powershell", base_dir.join("powershell")),
    ];

    for (cat_name, cat_dir) in &categories {
        let mut files = Vec::new();
        find_all_yaml_files(cat_dir, &mut files);
        files.sort();

        let mut ns_ok = 0;
        let mut rsigma_ok = 0;
        let mut tau_ok = 0;
        let mut sr_ok = 0;

        let mut rsigma_errs: HashMap<String, usize> = HashMap::new();
        let mut tau_errs: HashMap<String, usize> = HashMap::new();
        let mut sr_errs: HashMap<String, usize> = HashMap::new();

        let mut all_yamls = Vec::new();

        for file in &files {
            let content = match std::fs::read_to_string(file) {
                Ok(c) => c,
                Err(_) => continue,
            };
            all_yamls.push(content.clone());

            // null-sigma
            let mut engine = null_sigma::SigmaEngine::new();
            if engine.load_rule(&content).is_ok() {
                ns_ok += 1;
            }

            // rsigma
            match rsigma_parser::parse_sigma_yaml(&content) {
                Ok(col) => {
                    if !col.rules.is_empty() {
                        rsigma_ok += 1;
                    } else {
                        *rsigma_errs.entry("empty rules".to_string()).or_default() += 1;
                    }
                }
                Err(e) => {
                    *rsigma_errs.entry(format!("{e:?}")).or_default() += 1;
                }
            }

            // tau
            match null_sigma_harness::convert::sigma_to_tau(&content) {
                Ok(_) => tau_ok += 1,
                Err(e) => {
                    *tau_errs.entry(e.to_string()).or_default() += 1;
                }
            }

            // sigma-rust
            match sigma_rust::rule_from_yaml(&content) {
                Ok(_) => sr_ok += 1,
                Err(e) => {
                    *sr_errs.entry(e.to_string()).or_default() += 1;
                }
            }
        }

        println!(
            "=== Category: {} (total files: {}) ===",
            cat_name,
            files.len()
        );
        println!(
            "  null-sigma : {} / {} ({:.1}%)",
            ns_ok,
            files.len(),
            ns_ok as f64 * 100.0 / files.len() as f64
        );
        println!(
            "  rsigma-eval: {} / {} ({:.1}%)",
            rsigma_ok,
            files.len(),
            rsigma_ok as f64 * 100.0 / files.len() as f64
        );
        println!(
            "  tau-engine : {} / {} ({:.1}%)",
            tau_ok,
            files.len(),
            tau_ok as f64 * 100.0 / files.len() as f64
        );
        println!(
            "  sigma-rust : {} / {} ({:.1}%)",
            sr_ok,
            files.len(),
            sr_ok as f64 * 100.0 / files.len() as f64
        );
        if !rsigma_errs.is_empty() {
            println!("  rsigma errors: {:?}", rsigma_errs);
        }
        if !tau_errs.is_empty() {
            println!(
                "  tau errors (sample): {:?}",
                tau_errs.keys().take(3).collect::<Vec<_>>()
            );
        }
        if !sr_errs.is_empty() {
            println!("  sigma-rust errors: {:?}", sr_errs);
        }
        println!();
    }
}
