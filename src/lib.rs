// =============================================================================
// NuLLAI Sigma Rule Engine — Public API
// =============================================================================
// High-performance Sigma rule evaluation engine written in Rust, exposed to
// Python via PyO3 for seamless integration with the NuLLAI backend.
//
// CRATE ARCHITECTURE:
//   types.rs    — Type system (SigmaRule, SeverityLevel, ValueModifier, etc.)
//   parser.rs   — YAML → SigmaRule parsing with full validation
//   condition.rs — Condition expression → boolean AST compilation
//   matcher.rs  — Event field matching with all 15 modifier implementations
//   fieldmap.rs — Sigma ↔ NuLLAI field name translation
//   engine.rs   — Multi-rule evaluation with Aho-Corasick optimization
//
// PERFORMANCE TARGET: 100K events/sec × 1000 rules on a single core.
// =============================================================================

pub mod types;
pub mod parser;
pub mod condition;
pub mod matcher;
pub mod fieldmap;
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
