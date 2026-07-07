//! High-performance [Sigma](https://sigmahq.io) rule evaluation engine.
//!
//! Parse Sigma rules from YAML once, compile them into an optimised internal
//! representation, then evaluate streams of security events against the full
//! rule set at **311 000+ events/second × 1 000 synthetic rules on a single core**
//! (Apple M4, release, microbenchmark suite). Against real `SigmaHQ`
//! `process_creation` rules: **~1 850 events/second** (see `harness/` and
//! `PERFORMANCE.md` §11).
#![forbid(unsafe_code)]
#![deny(missing_docs)]
//!
//! # Quick Start
//!
//! ```
//! use null_sigma::SigmaEngine;
//! use std::collections::HashMap;
//!
//! let yaml = r#"
//! title: Detect Encoded PowerShell
//! logsource: {}
//! detection:
//!     sel:
//!         CommandLine|contains: '-EncodedCommand'
//!     condition: sel
//! "#;
//!
//! let mut engine = SigmaEngine::new();
//! engine.load_rule(yaml).unwrap();
//!
//! let mut event = HashMap::new();
//! event.insert("CommandLine".to_string(), "powershell -EncodedCommand abc".to_string());
//!
//! let matches = engine.evaluate_event(&event);
//! assert_eq!(matches.len(), 1);
//! assert_eq!(matches[0].rule_title, "Detect Encoded PowerShell");
//! ```
//!
//! # Architecture
//!
//! | Module | Role |
//! |--------|------|
//! | [`types`] | Core type system: `SigmaRule`, `SeverityLevel`, `ValueModifier`, … |
//! | [`parser`] | YAML → `SigmaRule` with full validation |
//! | [`condition`] | Condition expression → boolean AST |
//! | [`matcher`] | Event field matching — all 19 Sigma modifiers |
//! | [`fieldmap`] | Sigma field-name translation |
//! | [`engine`] | Multi-rule evaluation with Aho-Corasick optimisation |

/// Condition expression compiler: Sigma condition strings → boolean AST
/// ([`condition::ConditionNode`]).
pub mod condition;
/// Multi-rule evaluation engine with Aho-Corasick batch prefilter and
/// cache-friendly hot/cold struct split.
pub mod engine;
mod event_view;
/// Sigma field-name translation and enrichment.
pub mod fieldmap;
mod fold;
/// Nested JSON telemetry ingestion — flattens ECS/Sysmon/CloudTrail-style
/// events into the engine's flat format (requires the `json` feature).
#[cfg(feature = "json")]
pub mod json;
/// Event field matching — implements all 19 Sigma value modifiers (`contains`,
/// `startswith`, `endswith`, `re` + `i`/`m`/`s` flags, `cidr`, `base64`,
/// `wide`, `windash`, `fieldref`, …).
pub mod matcher;
/// YAML → [`types::SigmaRule`] parsing with full Sigma spec validation.
pub mod parser;
/// Core type system: `SigmaRule`, `SeverityLevel`, `ValueModifier`, and all
/// supporting data types used throughout the crate.
pub mod types;

// Re-export the primary public API
pub use condition::{compile_condition, CompileError, ConditionNode};
pub use engine::{EngineError, SigmaEngine};
pub use fieldmap::FieldMapping;
#[cfg(feature = "json")]
pub use json::{flatten_str, flatten_value, FlattenError, FlattenOptions};
pub use matcher::{match_field_condition, match_identifier};
pub use parser::{parse_rule, parse_rules, ParseError};
pub use types::{
    ConditionExpr, Detection, EvalResult, FieldCondition, FieldConditionGroup, LogSource,
    RuleMatch, RuleStatus, SearchIdentifier, SeverityLevel, SigmaRule, SigmaValue, ValueModifier,
};

// ── Compile-time thread-safety proof ─────────────────────────────────────────
// `evaluate_event` takes `&self`, and the README documents `Arc<SigmaEngine>`
// as the recommended concurrent usage pattern. These assertions guarantee that
// the compiler will catch any future change that accidentally makes the engine
// non-Send or non-Sync before it reaches users.
const _: () = {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    fn check() {
        assert_send::<SigmaEngine>();
        assert_sync::<SigmaEngine>();
    }
    let _ = check;
};
