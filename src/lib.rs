//! High-performance [Sigma](https://sigmahq.io) rule evaluation engine.
//!
//! Parse Sigma rules from YAML once, compile them into an optimised internal
//! representation, then evaluate streams of security events against the full
//! rule set at **455 000+ events/second × 1 000 rules on a single core**
//! (Apple M4, release, Criterion-measured).
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
//! | [`matcher`] | Event field matching — all 15 Sigma modifiers |
//! | [`fieldmap`] | Sigma field-name translation |
//! | [`engine`] | Multi-rule evaluation with Aho-Corasick optimisation |

/// Core type system: `SigmaRule`, `SeverityLevel`, `ValueModifier`, and all
/// supporting data types used throughout the crate.
pub mod types;
/// YAML → [`types::SigmaRule`] parsing with full Sigma spec validation.
pub mod parser;
/// Condition expression compiler: Sigma condition strings → boolean AST
/// ([`condition::ConditionNode`]).
pub mod condition;
/// Event field matching — implements all 15 Sigma value modifiers (`contains`,
/// `startswith`, `endswith`, `re`, `cidr`, `base64`, `wide`, `windash`, …).
pub mod matcher;
/// Sigma field-name translation and enrichment.
pub mod fieldmap;
/// Multi-rule evaluation engine with Aho-Corasick batch prefilter and
/// cache-friendly hot/cold struct split.
pub mod engine;

// Re-export the primary public API
pub use engine::SigmaEngine;
pub use types::{
    SigmaRule, LogSource, Detection, SearchIdentifier, FieldConditionGroup,
    FieldCondition, SigmaValue, ValueModifier, SeverityLevel, RuleStatus,
    RuleMatch, EvalResult, ConditionExpr,
};
pub use parser::{parse_rule, parse_rules, ParseError};
pub use condition::{compile_condition, ConditionNode, CompileError};
pub use matcher::{match_identifier, match_field_condition};
pub use fieldmap::FieldMapping;
