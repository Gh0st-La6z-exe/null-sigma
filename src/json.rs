// =============================================================================
// JSON Telemetry Ingestion — feature-gated flattening layer
// =============================================================================
//
// Real security telemetry is nested JSON (ECS, Sysmon JSON exports,
// CloudTrail records). The core engine deliberately consumes a flat
// `HashMap<String, String>` — this module bridges the two by flattening
// nested JSON into dotted field paths WITHOUT touching matcher or engine
// internals. The core crate compiles identically with this feature off.
//
// Flattening specification (mirrors the module docs below):
//   objects  → dot paths        {"process":{"name":"x"}} → process.name = "x"
//   scalars  → strings          numbers via canonical display, bools true/false
//   null     → ""               preserves Sigma `field: null` (matches empty)
//   arrays   → indexed keys     Hashes.0, Hashes.1, …
//              + joined base    Hashes = elements joined with '\n' so that
//                               `Field|contains` emulates "any element matches"
//              (single-element arrays collapse to the base key only)
//   collisions → first write wins, never overwrite (deterministic: serde_json
//                maps iterate in sorted key order)
//   guards   → max_depth / max_fields return typed errors, never panic
// =============================================================================

use crate::engine::SigmaEngine;
use crate::types::RuleMatch;
use std::collections::HashMap;

/// Default maximum nesting depth accepted by [`flatten_value`].
///
/// 64 comfortably covers every real telemetry schema (ECS nests 3–5 deep)
/// while rejecting adversarial deep-nesting payloads long before recursion
/// becomes a stack risk.
pub const DEFAULT_MAX_DEPTH: usize = 64;

/// Default maximum number of flattened fields produced from one event.
///
/// Caps amplification bombs (huge arrays / wide objects). Real events are
/// tens of fields; 10 000 is far above any legitimate schema.
pub const DEFAULT_MAX_FIELDS: usize = 10_000;

/// Error produced by the JSON flattening layer.
///
/// Fail-loud policy: an event we cannot represent faithfully is rejected
/// with a typed error rather than silently truncated — a partially flattened
/// event could silently miss detections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlattenError {
    /// The input string is not valid JSON.
    Parse(String),
    /// The document is not a JSON object at the top level.
    /// Events must be objects — a bare array/scalar has no field names.
    NotAnObject,
    /// Nesting exceeded [`FlattenOptions::max_depth`].
    DepthExceeded {
        /// The configured limit that was exceeded.
        max_depth: usize,
    },
    /// Flattening produced more than [`FlattenOptions::max_fields`] fields.
    FieldsExceeded {
        /// The configured limit that was exceeded.
        max_fields: usize,
    },
}

impl std::fmt::Display for FlattenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FlattenError::Parse(e) => write!(f, "JSON parse error: {e}"),
            FlattenError::NotAnObject => {
                write!(f, "JSON event must be an object at the top level")
            }
            FlattenError::DepthExceeded { max_depth } => {
                write!(f, "JSON nesting exceeds maximum depth of {max_depth}")
            }
            FlattenError::FieldsExceeded { max_fields } => {
                write!(f, "JSON flattening exceeds maximum of {max_fields} fields")
            }
        }
    }
}

impl std::error::Error for FlattenError {}

/// Configuration for the flattening guards.
///
/// The defaults ([`DEFAULT_MAX_DEPTH`], [`DEFAULT_MAX_FIELDS`]) are safe for
/// any real telemetry source; tighten them at trust boundaries that ingest
/// fully untrusted documents.
#[derive(Debug, Clone, Copy)]
pub struct FlattenOptions {
    /// Maximum nesting depth (objects + arrays) before rejection.
    pub max_depth: usize,
    /// Maximum number of flattened output fields before rejection.
    pub max_fields: usize,
}

impl Default for FlattenOptions {
    fn default() -> Self {
        FlattenOptions {
            max_depth: DEFAULT_MAX_DEPTH,
            max_fields: DEFAULT_MAX_FIELDS,
        }
    }
}

/// Flatten a parsed JSON value into the engine's flat event format using
/// default [`FlattenOptions`].
///
/// See the module documentation for the full flattening specification.
///
/// # Errors
///
/// Returns [`FlattenError::NotAnObject`] for non-object documents, and
/// [`FlattenError::DepthExceeded`] / [`FlattenError::FieldsExceeded`] when a
/// guard trips.
pub fn flatten_value(value: &serde_json::Value) -> Result<HashMap<String, String>, FlattenError> {
    flatten_value_with(value, FlattenOptions::default())
}

/// Thread-local scratch buffers for zero-allocation JSON flattening and evaluation.
#[derive(Debug, Default)]
pub struct JsonScratch {
    /// Reusable map for flattened fields
    pub map: HashMap<String, String>,
    /// Reusable path buffer
    pub path_buf: String,
}

impl JsonScratch {
    /// Create a new empty scratch buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset scratch buffers, preserving heap capacity.
    pub fn reset(&mut self) {
        self.map.clear();
        self.path_buf.clear();
    }
}

thread_local! {
    pub(crate) static JSON_SCRATCH: std::cell::RefCell<JsonScratch> = std::cell::RefCell::new(JsonScratch::new());
}

/// Flatten a parsed JSON value with explicit guard configuration.
///
/// # Errors
///
/// Same failure modes as [`flatten_value`].
pub fn flatten_value_with(
    value: &serde_json::Value,
    options: FlattenOptions,
) -> Result<HashMap<String, String>, FlattenError> {
    let serde_json::Value::Object(map) = value else {
        return Err(FlattenError::NotAnObject);
    };

    let mut out = HashMap::new();
    let mut path_buf = String::new();
    for (key, val) in map {
        path_buf.push_str(key);
        flatten_into_buf(&mut path_buf, val, &mut out, 1, options)?;
        path_buf.clear();
    }
    Ok(out)
}

/// Parse a JSON string and flatten it using default [`FlattenOptions`].
///
/// # Errors
///
/// Returns [`FlattenError::Parse`] for invalid JSON, plus the failure modes
/// of [`flatten_value`].
pub fn flatten_str(json: &str) -> Result<HashMap<String, String>, FlattenError> {
    flatten_str_with(json, FlattenOptions::default())
}

/// Parse a JSON string and flatten it with explicit guard configuration.
///
/// # Errors
///
/// Same failure modes as [`flatten_str`].
pub fn flatten_str_with(
    json: &str,
    options: FlattenOptions,
) -> Result<HashMap<String, String>, FlattenError> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|e| FlattenError::Parse(e.to_string()))?;
    flatten_value_with(&value, options)
}

/// Insert a flattened field, enforcing the collision and field-count policies.
///
/// Collision policy: FIRST WRITE WINS. A literal `"a.b"` key and a nested
/// `a` → `b` path can both produce the path `a.b`; overwriting would make the
/// result depend on iteration order of the two sources. `serde_json` maps
/// iterate in sorted key order, so first-write-wins is fully deterministic.
fn insert_field(
    out: &mut HashMap<String, String>,
    path: String,
    value: String,
    options: FlattenOptions,
) -> Result<(), FlattenError> {
    if out.len() >= options.max_fields {
        return Err(FlattenError::FieldsExceeded {
            max_fields: options.max_fields,
        });
    }
    out.entry(path).or_insert(value);
    Ok(())
}

/// Render a JSON scalar to its flat string form.
///
/// Numbers use `serde_json`'s canonical display — `i64`/`u64` round-trip exactly;
/// floats render with full precision. `null` becomes the empty string so the
/// Sigma `field: null` condition (matches empty) behaves correctly.
fn scalar_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => String::new(),
        // Callers only pass scalars; objects/arrays are handled structurally.
        serde_json::Value::Object(_) | serde_json::Value::Array(_) => {
            unreachable!("scalar_to_string called on a container")
        }
    }
}

/// Recursively flatten one JSON value under `path_buf`.
///
/// `depth` counts nesting levels (top-level fields are depth 1); both objects
/// and arrays consume a level, so the recursion depth is bounded by
/// `options.max_depth` regardless of input shape.
fn flatten_into_buf(
    path_buf: &mut String,
    value: &serde_json::Value,
    out: &mut HashMap<String, String>,
    depth: usize,
    options: FlattenOptions,
) -> Result<(), FlattenError> {
    if depth > options.max_depth {
        return Err(FlattenError::DepthExceeded {
            max_depth: options.max_depth,
        });
    }

    match value {
        serde_json::Value::Object(map) => {
            let base_len = path_buf.len();
            for (key, val) in map {
                path_buf.push('.');
                path_buf.push_str(key);
                flatten_into_buf(path_buf, val, out, depth + 1, options)?;
                path_buf.truncate(base_len);
            }
        }

        serde_json::Value::Array(items) => match items.as_slice() {
            // Empty array: field carries no matchable value → empty string,
            // consistent with the null convention.
            [] => insert_field(out, path_buf.clone(), String::new(), options)?,

            // Single element collapses to the base key — the dominant real
            // case (e.g. one hash, one IP) should look like a plain field.
            [only] if !only.is_object() && !only.is_array() => {
                insert_field(out, path_buf.clone(), scalar_to_string(only), options)?;
            }

            _ => {
                let base_len = path_buf.len();
                // Indexed keys for exact per-element access…
                for (i, item) in items.iter().enumerate() {
                    path_buf.push('.');
                    use std::fmt::Write;
                    let _ = write!(path_buf, "{i}");
                    flatten_into_buf(path_buf, item, out, depth + 1, options)?;
                    path_buf.truncate(base_len);
                }
                // …plus a newline-joined base key over the SCALAR elements so
                // `Field|contains` emulates "any element matches" (multi-value
                // field semantics à la Elasticsearch). Newline is the safest
                // separator: it cannot appear inside a JSON string without an
                // explicit \n escape, so accidental cross-element matches
                // require a pattern that itself spans lines. Trade-off
                // documented in the module docs.
                let scalars: Vec<String> = items
                    .iter()
                    .filter(|v| !v.is_object() && !v.is_array())
                    .map(scalar_to_string)
                    .collect();
                if !scalars.is_empty() {
                    insert_field(out, path_buf.clone(), scalars.join("\n"), options)?;
                }
            }
        },

        scalar => insert_field(out, path_buf.clone(), scalar_to_string(scalar), options)?,
    }

    Ok(())
}

/// Helper to parse and flatten JSON using thread-local scratch buffers to eliminate heap allocations.
pub fn with_flattened_str<R>(
    json: &str,
    options: FlattenOptions,
    f: impl FnOnce(&HashMap<String, String>) -> R,
) -> Result<R, FlattenError> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|e| FlattenError::Parse(e.to_string()))?;
    let serde_json::Value::Object(map) = value else {
        return Err(FlattenError::NotAnObject);
    };

    JSON_SCRATCH.with(|cell| {
        let scratch = &mut *cell.borrow_mut();
        scratch.reset();
        for (key, val) in map {
            scratch.path_buf.push_str(&key);
            flatten_into_buf(&mut scratch.path_buf, &val, &mut scratch.map, 1, options)?;
            scratch.path_buf.clear();
        }
        let res = f(&scratch.map);
        scratch.reset();
        Ok(res)
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// SigmaEngine convenience — defined HERE so engine.rs stays JSON-free
// ─────────────────────────────────────────────────────────────────────────────

impl SigmaEngine {
    /// Parse a JSON event string, flatten it, and evaluate it against all
    /// loaded rules using thread-local pooled buffers.
    ///
    /// ```
    /// # use null_sigma::SigmaEngine;
    /// let mut engine = SigmaEngine::new();
    /// engine.load_rule(r#"
    /// title: Encoded PowerShell
    /// logsource: {}
    /// detection:
    ///     sel:
    ///         process.command_line|contains: '-EncodedCommand'
    ///     condition: sel
    /// "#).unwrap();
    ///
    /// let matches = engine.evaluate_json(
    ///     r#"{"process": {"command_line": "powershell -EncodedCommand SQBFAFgA"}}"#,
    /// ).unwrap();
    /// assert_eq!(matches.len(), 1);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`FlattenError`] for invalid JSON, non-object documents, or
    /// guard violations. Evaluation itself cannot fail.
    pub fn evaluate_json<'a>(&'a self, json: &str) -> Result<Vec<RuleMatch<'a>>, FlattenError> {
        with_flattened_str(json, FlattenOptions::default(), |event| {
            self.evaluate_event(event)
        })
    }

    /// Parse JSON and count matching rules without building [`RuleMatch`] payloads or allocating maps.
    ///
    /// Same semantics as [`Self::evaluate_json`], but skips result metadata
    /// allocation — use for throughput-sensitive JSONL ingestion paths.
    ///
    /// # Errors
    ///
    /// Returns [`FlattenError`] for invalid JSON, non-object documents, or
    /// guard violations. Evaluation itself cannot fail.
    pub fn evaluate_json_count(&self, json: &str) -> Result<usize, FlattenError> {
        with_flattened_str(json, FlattenOptions::default(), |event| {
            self.evaluate_event_count(event)
        })
    }

    /// Parse JSON and evaluate into a reusable matches buffer without map allocations.
    ///
    /// # Errors
    ///
    /// Returns [`FlattenError`] for invalid JSON, non-object documents, or
    /// guard violations. Evaluation itself cannot fail.
    pub fn evaluate_json_into<'a>(
        &'a self,
        json: &str,
        matches_buf: &mut Vec<RuleMatch<'a>>,
    ) -> Result<(), FlattenError> {
        with_flattened_str(json, FlattenOptions::default(), |event| {
            self.evaluate_event_into(event, matches_buf);
        })
    }
}
