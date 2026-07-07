//! Head-to-head benchmark harness for null-sigma (roadmap item 3).
//!
//! Loads the same SigmaHQ rule set and the same generated event stream into
//! three engines and measures them side by side:
//!
//! - **null-sigma** — this project.
//! - **tau-engine** — Chainsaw's matching core, fed rules through a faithful
//!   port of Chainsaw's own Sigma converter plus its optimiser passes.
//! - **sigma-rust** — the closest direct library peer.
//!
//! Nothing here touches the core crate; see `harness/README.md`.

pub mod convert;
pub mod gen;

use std::collections::HashMap;
use std::path::Path;

use serde_json::{Map, Value};

/// A Sigma rule source file plus which engines managed to load it.
pub struct RuleCompat {
    pub path: String,
    pub yaml: String,
    pub null_sigma: Result<(), String>,
    pub tau: Result<(), String>,
    pub sigma_rust: Result<(), String>,
}

/// The outcome of loading a rule directory into all three engines.
pub struct LoadReport {
    pub rules: Vec<RuleCompat>,
}

impl LoadReport {
    /// Paths of rules that ALL three engines loaded — the common benchmark set.
    pub fn common(&self) -> Vec<&RuleCompat> {
        self.rules
            .iter()
            .filter(|r| r.null_sigma.is_ok() && r.tau.is_ok() && r.sigma_rust.is_ok())
            .collect()
    }

    pub fn loaded_counts(&self) -> (usize, usize, usize, usize) {
        let total = self.rules.len();
        let ns = self.rules.iter().filter(|r| r.null_sigma.is_ok()).count();
        let tau = self.rules.iter().filter(|r| r.tau.is_ok()).count();
        let sr = self.rules.iter().filter(|r| r.sigma_rust.is_ok()).count();
        (total, ns, tau, sr)
    }
}

/// Read every `.yml` rule under `dir` (non-recursive subdirs skipped —
/// SigmaHQ's process_creation directory is flat) and try to load each into
/// all three engines.
pub fn load_rule_dir(dir: &Path) -> std::io::Result<LoadReport> {
    let mut rules = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(std::result::Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "yml" || e == "yaml"))
        .collect();
    entries.sort();

    for path in entries {
        let yaml = std::fs::read_to_string(&path)?;

        let null_sigma = {
            let mut probe = null_sigma::SigmaEngine::new();
            probe.load_rule(&yaml).map(|_| ()).map_err(|e| format!("{e:?}"))
        };
        let tau = convert::sigma_to_tau(&yaml).map(|_| ()).map_err(|e| e.to_string());
        let sigma_rust =
            sigma_rust::rule_from_yaml(&yaml).map(|_| ()).map_err(|e| e.to_string());

        rules.push(RuleCompat {
            path: path.display().to_string(),
            yaml,
            null_sigma,
            tau,
            sigma_rust,
        });
    }
    Ok(LoadReport { rules })
}

// ── Prepared engines over a fixed rule set ──────────────────────────────────

/// null-sigma engine plus the flat-string event representation it consumes.
pub struct NullSigmaBench {
    pub engine: null_sigma::SigmaEngine,
}

impl NullSigmaBench {
    pub fn new(yamls: &[&str]) -> Self {
        // Bulk-load through the multi-document path: the Aho-Corasick
        // automaton is rebuilt once at the end instead of once per rule
        // (`load_rule` rebuilds eagerly — intended for incremental use).
        let joined = yamls.join("\n---\n");
        let mut engine = null_sigma::SigmaEngine::new();
        let (loaded, errors) = engine.load_rules(&joined);
        assert!(
            errors.is_empty() && loaded.len() == yamls.len(),
            "bulk load failed: {} loaded, {} errors ({:?})",
            loaded.len(),
            errors.len(),
            errors.first()
        );
        Self { engine }
    }

    /// Convert a generated JSON event into null-sigma's native flat map.
    pub fn prepare_event(event: &Map<String, Value>) -> HashMap<String, String> {
        event
            .iter()
            .map(|(k, v)| {
                let s = match v {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                (k.clone(), s)
            })
            .collect()
    }

    pub fn count_matches(&self, event: &HashMap<String, String>) -> usize {
        self.engine.evaluate_event_count(event)
    }
}

/// tau-engine (Chainsaw's matcher) with converted, optimised rules.
pub struct TauBench {
    pub rules: Vec<tau_engine::Rule>,
}

impl TauBench {
    pub fn new(yamls: &[&str]) -> Self {
        let rules = yamls
            .iter()
            .map(|y| convert::sigma_to_tau(y).expect("rule failed to convert for tau"))
            .collect();
        Self { rules }
    }

    /// tau's native Chainsaw-path input is a serde_json::Value document.
    pub fn prepare_event(event: &Map<String, Value>) -> Value {
        Value::Object(event.clone())
    }

    pub fn count_matches(&self, event: &Value) -> usize {
        self.rules.iter().filter(|r| r.matches(event)).count()
    }

    /// Per-rule hit vector for the correctness cross-check.
    pub fn hits(&self, event: &Value) -> Vec<bool> {
        self.rules.iter().map(|r| r.matches(event)).collect()
    }
}

/// sigma-rust with directly parsed Sigma rules.
pub struct SigmaRustBench {
    pub rules: Vec<sigma_rust::Rule>,
}

impl SigmaRustBench {
    pub fn new(yamls: &[&str]) -> Self {
        let rules = yamls
            .iter()
            .map(|y| sigma_rust::rule_from_yaml(y).expect("rule failed to load into sigma-rust"))
            .collect();
        Self { rules }
    }

    /// sigma-rust's native input is its own Event type, built from JSON.
    pub fn prepare_event(event: &Map<String, Value>) -> sigma_rust::Event {
        sigma_rust::event_from_json(&Value::Object(event.clone()).to_string())
            .expect("event JSON must parse")
    }

    pub fn count_matches(&self, event: &sigma_rust::Event) -> usize {
        self.rules.iter().filter(|r| sigma_rust::check_rule(r, event)).count()
    }

    pub fn hits(&self, event: &sigma_rust::Event) -> Vec<bool> {
        self.rules.iter().map(|r| sigma_rust::check_rule(r, event)).collect()
    }
}

/// Per-rule hit vector from null-sigma for the correctness cross-check.
/// `ids` must be the rule ids returned by `load_rule`, in load order.
pub fn null_sigma_hits(
    engine: &null_sigma::SigmaEngine,
    ids: &[String],
    event: &HashMap<String, String>,
) -> Vec<bool> {
    let matches = engine.evaluate_event(event);
    let matched: std::collections::HashSet<&str> =
        matches.iter().map(|m| m.rule_id.as_str()).collect();
    ids.iter().map(|id| matched.contains(id.as_str())).collect()
}

/// Extract the `title:` line of a Sigma rule (for reporting).
pub fn rule_title(yaml: &str) -> String {
    for line in yaml.lines() {
        if let Some(rest) = line.strip_prefix("title:") {
            return rest.trim().trim_matches('\'').trim_matches('"').to_string();
        }
    }
    String::from("<untitled>")
}

/// Default location of the vendored SigmaHQ process_creation rules,
/// relative to the harness crate root.
pub fn default_rule_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../corpus/sigmahq/rules/windows/process_creation")
}
