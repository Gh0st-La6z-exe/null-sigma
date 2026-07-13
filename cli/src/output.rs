//! Alert writers for stdout — lean NDJSON or text (§11.10 / Day 2).
//!
//! Callers own flush policy: default is buffered `BufWriter` with end-of-run
//! flush; `--flush-alerts` flushes after each alert.

use std::collections::HashMap;
use std::io::{self, Write};

use null_sigma::RuleMatch;
use serde_json::{json, Map, Value};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputFormat {
    Ndjson,
    Text,
}

impl OutputFormat {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "ndjson" => Ok(Self::Ndjson),
            "text" => Ok(Self::Text),
            _ => Err(format!(
                "invalid --format value: {raw} (expected ndjson|text)"
            )),
        }
    }
}

/// Write one alert line into `out`. Does **not** flush.
pub fn write_alert(
    out: &mut impl Write,
    format: OutputFormat,
    include_event: bool,
    m: &RuleMatch,
    event: &HashMap<String, String>,
) -> io::Result<()> {
    match format {
        OutputFormat::Ndjson => write_ndjson(out, include_event, m, event),
        OutputFormat::Text => {
            writeln!(
                out,
                "{} {} {}",
                m.rule_level.as_str(),
                m.rule_id,
                m.rule_title
            )
        }
    }
}

fn write_ndjson(
    out: &mut impl Write,
    include_event: bool,
    m: &RuleMatch,
    event: &HashMap<String, String>,
) -> io::Result<()> {
    let mut obj = Map::new();
    obj.insert("rule_id".into(), Value::String(m.rule_id.clone()));
    obj.insert("rule_title".into(), Value::String(m.rule_title.clone()));
    obj.insert(
        "rule_level".into(),
        Value::String(m.rule_level.as_str().to_string()),
    );
    obj.insert(
        "tags".into(),
        Value::Array(m.tags.iter().cloned().map(Value::String).collect()),
    );
    obj.insert("score".into(), json!(m.score));
    obj.insert(
        "matched_identifiers".into(),
        Value::Array(
            m.matched_identifiers
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );
    if include_event {
        let mut ev = Map::new();
        for (k, v) in event {
            ev.insert(k.clone(), Value::String(v.clone()));
        }
        obj.insert("event".into(), Value::Object(ev));
    }
    serde_json::to_writer(&mut *out, &Value::Object(obj))?;
    out.write_all(b"\n")?;
    Ok(())
}

/// Map write failures for CLI exit policy.
pub fn map_write_err(err: io::Error) -> String {
    if err.kind() == io::ErrorKind::BrokenPipe {
        "broken_pipe".to_string()
    } else {
        format!("stdout write error: {err}")
    }
}
