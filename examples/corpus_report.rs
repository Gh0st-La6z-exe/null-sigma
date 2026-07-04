//! SigmaHQ corpus compatibility report.
//!
//! Walks a directory tree of Sigma rule YAML files, attempts to parse and
//! load every rule, and prints a categorized compatibility report.
//!
//! Usage:
//! ```text
//! cargo run --release --example corpus_report -- corpus/sigmahq/rules [more dirs...]
//! ```

use null_sigma::SigmaEngine;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Recursively collect all `.yml` / `.yaml` files under `dir`.
fn collect_yaml_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_yaml_files(&path, out);
        } else if matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("yml" | "yaml")
        ) {
            out.push(path);
        }
    }
}

/// Reduce an error message to a stable category key so thousands of failures
/// aggregate into a handful of actionable buckets.
fn categorize(err: &str) -> String {
    if let Some(rest) = err.strip_prefix("Parse error: Invalid modifier '") {
        // "Invalid modifier 'fieldref' on field '...'" → bucket per modifier
        let modifier = rest.split('\'').next().unwrap_or("?");
        return format!("unsupported modifier |{modifier}");
    }
    if err.contains("Invalid condition") {
        // Bucket by the first token that looks like the culprit
        if err.contains("count(") || err.contains("| count") {
            return "deprecated aggregation condition (count/near)".to_string();
        }
        return "condition parse failure".to_string();
    }
    if err.starts_with("Parse error: YAML parse error") {
        return "YAML deserialization failure".to_string();
    }
    if err.starts_with("Parse error: Missing required field") {
        return err.strip_prefix("Parse error: ").unwrap_or(err).to_string();
    }
    if err.starts_with("Invalid |re pattern") {
        return "invalid |re regex".to_string();
    }
    if err.starts_with("Compile error") {
        return "condition compile failure".to_string();
    }
    // Fallback: first 60 chars
    err.chars().take(60).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let dirs: Vec<PathBuf> = if args.is_empty() {
        vec![PathBuf::from("corpus/sigmahq/rules")]
    } else {
        args.iter().map(PathBuf::from).collect()
    };

    let mut files = Vec::new();
    for dir in &dirs {
        collect_yaml_files(dir, &mut files);
    }
    files.sort();
    println!("Scanning {} rule files from {:?}\n", files.len(), dirs);

    let mut loaded = 0usize;
    let mut failed = 0usize;
    let mut unreadable = 0usize;
    // category → (count, up to 3 example file paths)
    let mut buckets: BTreeMap<String, (usize, Vec<String>)> = BTreeMap::new();
    let mut all_yaml = String::new();

    let start = Instant::now();
    for path in &files {
        let Ok(content) = std::fs::read_to_string(path) else {
            unreadable += 1;
            continue;
        };

        // Fresh engine per file: isolates failures and keeps AC rebuild cost
        // linear across the corpus instead of quadratic in one engine.
        let mut engine = SigmaEngine::new();
        match engine.load_rule(&content) {
            Ok(_) => {
                loaded += 1;
                all_yaml.push_str(&content);
                all_yaml.push_str("\n---\n");
            }
            Err(e) => {
                failed += 1;
                let cat = categorize(&e.to_string());
                let entry = buckets.entry(cat).or_insert((0, Vec::new()));
                entry.0 += 1;
                if entry.1.len() < 3 {
                    entry.1.push(path.display().to_string());
                }
            }
        }
    }
    let per_file_elapsed = start.elapsed();

    // Whole-corpus load into a single engine (one AC rebuild) for a realistic
    // "load the world" timing figure.
    let start = Instant::now();
    let mut big_engine = SigmaEngine::new();
    let (successes, errors) = big_engine.load_rules(&all_yaml);
    let bulk_elapsed = start.elapsed();

    let total = loaded + failed;
    println!("── Compatibility ───────────────────────────────────────────");
    println!(
        "  loaded : {loaded:5} / {total}  ({:.1}%)",
        100.0 * loaded as f64 / total as f64
    );
    println!(
        "  failed : {failed:5} / {total}  ({:.1}%)",
        100.0 * failed as f64 / total as f64
    );
    if unreadable > 0 {
        println!("  unreadable files: {unreadable}");
    }

    println!("\n── Failure categories (count, examples) ────────────────────");
    let mut sorted: Vec<_> = buckets.iter().collect();
    sorted.sort_by(|a, b| b.1 .0.cmp(&a.1 .0));
    for (cat, (count, examples)) in sorted {
        println!("  {count:5}  {cat}");
        for ex in examples {
            println!("           e.g. {ex}");
        }
    }

    println!("\n── Bulk load (single engine, one AC rebuild) ───────────────");
    println!(
        "  {} rules loaded, {} errors, in {:.2?} (per-file pass: {:.2?})",
        successes.len(),
        errors.len(),
        bulk_elapsed,
        per_file_elapsed,
    );
    println!("  engine holds {} rules", big_engine.rule_count());
}
