//! Sigma → tau-engine rule conversion — a faithful port of Chainsaw's own
//! converter (`chainsaw/src/rule/sigma.rs`, MIT), so tau-engine evaluates
//! Sigma rules exactly the way Chainsaw ships them: case-insensitive `i`
//! prefixed patterns, `?regex` escape, `of`-expression expansion, and the
//! same four optimiser passes Chainsaw applies after conversion
//! (`coalesce` → `shake` → `rewrite` → `matrix`).
//!
//! Rules Chainsaw cannot convert (unsupported modifiers such as `|windash`
//! or `|cidr`, aggregation conditions, keyless identifiers) are rejected
//! here too — that rejection rate is itself a reported compatibility
//! finding, not a harness limitation.

use std::collections::{HashMap, HashSet};

use base64::Engine as _;
use serde::Deserialize;
use serde_norway::{Mapping, Sequence, Value as Yaml};

/// Why a rule could not be converted to a Chainsaw-style tau rule.
#[derive(Debug, Clone)]
pub struct ConvertError(pub String);

impl std::fmt::Display for ConvertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ConvertError {}

type Result<T> = std::result::Result<T, ConvertError>;

fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(ConvertError(msg.into()))
}

#[derive(Clone, Debug, Deserialize)]
struct Detection {
    #[serde(default)]
    condition: Option<Yaml>,
    #[serde(flatten)]
    identifiers: Mapping,
}

#[derive(Clone, Deserialize)]
struct SigmaDoc {
    #[serde(default)]
    detection: Option<Detection>,
    #[serde(default)]
    action: Option<String>,
}

// ── Chainsaw's Match trait, ported as functions ─────────────────────────────

fn as_contains(s: &str) -> String {
    format!("i*{s}*")
}

fn as_endswith(s: &str) -> String {
    format!("i*{s}")
}

fn as_startswith(s: &str) -> String {
    format!("i{s}*")
}

fn as_match(s: &str) -> Option<String> {
    // Chainsaw: exact match with optional leading/trailing `*`; nested
    // wildcards are not expressible and fall back to regex conversion.
    let len = s.len();
    if len > 1 {
        let mut start = 0;
        let mut end = len;
        if s.starts_with('*') {
            start += 1;
        }
        if s.ends_with('*') {
            end -= 1;
        }
        if s[start..end].contains('*') || s[start..end].contains('?') {
            return None;
        }
    }
    Some(format!("i{s}"))
}

fn as_regex(s: &str, convert: bool) -> Option<String> {
    if convert {
        // Convert a wildcard string into an equivalent regex (Chainsaw's
        // nested-wildcard fallback).
        let literal = regex_escape(s);
        let mut scratch = Vec::with_capacity(literal.len());
        let mut escaped = false;
        for c in literal.chars() {
            match c {
                '*' | '?' => {
                    if !escaped {
                        scratch.push('.');
                    }
                }
                '\\' => {
                    escaped = !escaped;
                }
                _ => {
                    escaped = false;
                }
            }
            scratch.push(c);
        }
        Some(format!("?{}", scratch.into_iter().collect::<String>()))
    } else {
        // Chainsaw validates the regex compiles; tau will compile it again at
        // rule load so a load failure downstream covers invalid patterns.
        Some(format!("?{s}"))
    }
}

/// Equivalent of `regex::escape` — avoids pulling the regex crate into the
/// harness just for escaping.
fn regex_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(
            c,
            '\\' | '.' | '+' | '*' | '?' | '(' | ')' | '|' | '[' | ']' | '{' | '}' | '^' | '$'
                | '#' | '&' | '-' | '~'
        ) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn supported_modifiers() -> &'static HashSet<String> {
    use std::sync::OnceLock;
    static SET: OnceLock<HashSet<String>> = OnceLock::new();
    SET.get_or_init(|| {
        ["all", "base64", "base64offset", "contains", "endswith", "startswith", "re"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect()
    })
}

fn parse_identifier(value: &Yaml, modifiers: &HashSet<String>) -> Result<Yaml> {
    let mut unsupported: Vec<String> =
        modifiers.difference(supported_modifiers()).cloned().collect();
    if !unsupported.is_empty() {
        unsupported.sort();
        return err(format!("unsupported modifiers: {}", unsupported.join(", ")));
    }

    let v = match value {
        Yaml::Mapping(m) => {
            let mut scratch = Mapping::new();
            for (k, v) in m {
                scratch.insert(k.clone(), parse_identifier(v, modifiers)?);
            }
            Yaml::Mapping(scratch)
        }
        Yaml::Sequence(s) => {
            let mut scratch = vec![];
            for s in s {
                let value = parse_identifier(s, modifiers)?;
                match value {
                    Yaml::Sequence(s) => scratch.extend(s),
                    _ => scratch.push(value),
                }
            }
            Yaml::Sequence(scratch)
        }
        Yaml::String(s) => {
            if modifiers.contains("base64") {
                let mut remaining = modifiers.clone();
                let _ = remaining.remove("base64");
                let encoded = base64::engine::general_purpose::STANDARD.encode(s);
                parse_identifier(&Yaml::String(encoded), &remaining)?
            } else if modifiers.contains("base64offset") {
                let mut remaining = modifiers.clone();
                let _ = remaining.remove("base64offset");
                let mut scratch = Vec::with_capacity(3);
                for i in 0..3 {
                    let mut value = " ".repeat(i);
                    value.push_str(s);
                    let encoded = base64::engine::general_purpose::STANDARD.encode(&value);
                    static S: [usize; 3] = [0, 2, 3];
                    static E: [usize; 3] = [0, 3, 2];
                    let len = value.len();
                    let trimmed = encoded[S[i]..encoded.len() - E[len % 3]].to_owned();
                    scratch.push(parse_identifier(&Yaml::String(trimmed), &remaining)?);
                }
                Yaml::Sequence(scratch)
            } else if modifiers.contains("contains") {
                Yaml::String(as_contains(s))
            } else if modifiers.contains("endswith") {
                Yaml::String(as_endswith(s))
            } else if modifiers.contains("re") {
                match as_regex(s, false) {
                    Some(r) => Yaml::String(r),
                    None => return err(format!("unsupported regex: {s}")),
                }
            } else if modifiers.contains("startswith") {
                Yaml::String(as_startswith(s))
            } else {
                match as_match(s) {
                    Some(s) => Yaml::String(s),
                    None => match as_regex(s, true) {
                        Some(r) => Yaml::String(r),
                        None => return err(format!("unsupported match: {s}")),
                    },
                }
            }
        }
        _ => value.clone(),
    };
    Ok(v)
}

fn condition_unsupported(condition: &str) -> bool {
    condition.contains(" | ")
        | condition.contains('*')
        | condition.contains(" avg ")
        | condition.contains(" of ")
        | condition.contains(" max ")
        | condition.contains(" min ")
        | condition.contains(" near ")
        | condition.contains(" sum ")
}

fn detections_to_tau(detection: Detection) -> Result<Mapping> {
    let mut tau = Mapping::new();
    let mut det = Mapping::new();

    let condition = match detection.condition {
        Some(Yaml::String(s)) => s,
        Some(u) => return err(format!("unsupported condition: {u:?}")),
        None => return err("missing condition"),
    };

    let mut patches: HashMap<String, String> = HashMap::new();
    for (k, v) in detection.identifiers {
        let k = match k.as_str() {
            Some(s) => s.to_string(),
            None => return err("identifiers must be strings"),
        };
        if k == "timeframe" {
            // Chainsaw ignores timeframe for the matching path.
            continue;
        }
        match v {
            Yaml::Sequence(sequence) => {
                let mut blocks = vec![];
                for (index, entry) in sequence.into_iter().enumerate() {
                    let mapping = match entry.as_mapping() {
                        Some(mapping) => mapping,
                        None => return err("keyless identifiers cannot be converted"),
                    };
                    let mut collect = true;
                    let mut seen = HashSet::new();
                    let mut maps = vec![];
                    for (f, v) in mapping {
                        let f = match f.as_str() {
                            Some(s) => s.to_string(),
                            None => return err("keys must be strings"),
                        };
                        let mut it = f.split('|');
                        let mut f = it.next().expect("could not get field").to_string();
                        if f.is_empty() {
                            return err("keyless identifiers cannot be converted");
                        }
                        if seen.contains(&f) {
                            collect = false;
                        }
                        seen.insert(f.clone());
                        let modifiers: HashSet<String> = it.map(|s| s.to_string()).collect();
                        if modifiers.contains("all") {
                            f = format!("all({f})");
                        }
                        let v = parse_identifier(v, &modifiers)?;
                        let mut map = Mapping::new();
                        map.insert(Yaml::String(f), v);
                        maps.push(map);
                    }
                    if collect {
                        let mut m = Mapping::new();
                        for map in maps {
                            for (k, v) in map {
                                m.insert(k, v);
                            }
                        }
                        let ident = format!("{k}_{index}");
                        blocks.push((ident, Yaml::Mapping(m)));
                    } else {
                        let ident = format!("all({k}_{index})");
                        blocks.push((
                            ident,
                            Yaml::Sequence(maps.into_iter().map(Yaml::Mapping).collect()),
                        ));
                    }
                }
                patches.insert(
                    k,
                    format!(
                        "({})",
                        blocks.iter().map(|(k, _)| k).cloned().collect::<Vec<_>>().join(" or "),
                    ),
                );
                for (k, v) in blocks {
                    det.insert(Yaml::String(k), v);
                }
            }
            Yaml::Mapping(mapping) => {
                let mut collect = true;
                let mut seen = HashSet::new();
                let mut maps = vec![];
                for (f, v) in mapping {
                    let f = match f.as_str() {
                        Some(s) => s.to_string(),
                        None => return err("keys must be strings"),
                    };
                    let mut it = f.split('|');
                    let mut f = it.next().expect("could not get field").to_string();
                    if f.is_empty() {
                        return err("keyless identifiers cannot be converted");
                    }
                    if seen.contains(&f) {
                        collect = false;
                    }
                    seen.insert(f.clone());
                    let modifiers: HashSet<String> = it.map(|s| s.to_string()).collect();
                    if modifiers.contains("all") {
                        f = format!("all({f})");
                    }
                    let v = parse_identifier(&v, &modifiers)?;
                    let mut map = Mapping::new();
                    map.insert(Yaml::String(f), v);
                    maps.push(map);
                }
                if collect {
                    let mut m = Mapping::new();
                    for map in maps {
                        for (k, v) in map {
                            m.insert(k, v);
                        }
                    }
                    det.insert(Yaml::String(k), Yaml::Mapping(m));
                } else {
                    let ident = format!("all({k})");
                    det.insert(
                        Yaml::String(k.clone()),
                        Yaml::Sequence(maps.into_iter().map(Yaml::Mapping).collect()),
                    );
                    patches.insert(k, ident);
                }
            }
            _ => {
                return err("identifier blocks must be a mapping or a sequence of mappings");
            }
        }
    }

    let condition = condition
        .replace(" AND ", " and ")
        .replace(" NOT ", " not ")
        .replace(" OR ", " or ")
        .split_whitespace()
        .map(|ident| {
            let key = ident.trim_start_matches('(').trim_end_matches(')');
            match patches.get(key) {
                Some(v) => ident.replace(key, v),
                None => ident.to_owned(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ");

    let condition = if condition == "all of them" {
        let mut identifiers = vec![];
        for (k, _) in &det {
            let key = k.as_str().expect("could not get key");
            match patches.get(key) {
                Some(i) => identifiers.push(i.to_owned()),
                None => identifiers.push(key.to_owned()),
            }
        }
        identifiers.join(" and ")
    } else if condition == "1 of them" {
        let mut identifiers = vec![];
        for (k, _) in &det {
            let key = k.as_str().expect("could not get key");
            match patches.get(key) {
                Some(i) => identifiers.push(i.to_owned()),
                None => identifiers.push(key.to_owned()),
            }
        }
        identifiers.join(" or ")
    } else {
        let mut mutated = vec![];
        let mut parts = condition.split_whitespace();
        while let Some(part) = parts.next() {
            let mut token = part;
            while let Some(tail) = token.strip_prefix('(') {
                mutated.push("(".to_owned());
                token = tail;
            }
            match token {
                "all" | "1" => {
                    if let Some(next) = parts.next() {
                        if next != "of" {
                            mutated.push(token.to_owned());
                            mutated.push(next.to_owned());
                            continue;
                        }

                        if let Some(next) = parts.next() {
                            let mut brackets = vec![];
                            let mut identifier = next;
                            while let Some(head) = identifier.strip_suffix(')') {
                                brackets.push(")".to_owned());
                                identifier = head;
                            }
                            if let Some(ident) = identifier.strip_suffix('*') {
                                let mut keys = vec![];
                                for (k, _) in &det {
                                    if let Yaml::String(key) = k {
                                        if key.starts_with(ident) {
                                            match patches.get(key) {
                                                Some(i) => keys.push(i.to_owned()),
                                                None => keys.push(key.to_owned()),
                                            }
                                        }
                                    }
                                }
                                if keys.is_empty() {
                                    return err("could not find any applicable identifiers");
                                }
                                let expression = if token == "all" {
                                    format!("({})", keys.join(" and "))
                                } else {
                                    format!("({})", keys.join(" or "))
                                };
                                mutated.push(expression);
                            } else {
                                let key = match patches.get(identifier) {
                                    Some(i) => i.as_str(),
                                    None => identifier,
                                };
                                let key = next.replace(identifier, key);
                                if part == "all" {
                                    mutated.push(format!("all({key})"));
                                } else if part == "1" {
                                    mutated.push(format!("of({key}, 1)"));
                                }
                            }
                            mutated.extend(brackets);
                            continue;
                        }
                    }
                }
                _ => {}
            }
            mutated.push(token.to_owned());
        }
        mutated.join(" ").replace("( ", "(").replace(" )", ")")
    };
    if condition_unsupported(&condition) {
        return err(format!("unsupported condition: {condition}"));
    }

    det.insert(Yaml::String("condition".into()), Yaml::String(condition));

    tau.insert(Yaml::String("detection".into()), Yaml::Mapping(det));
    tau.insert(Yaml::String("true_positives".into()), Yaml::Sequence(Sequence::new()));
    tau.insert(Yaml::String("true_negatives".into()), Yaml::Sequence(Sequence::new()));

    Ok(tau)
}

/// Convert a single-document Sigma rule into a loaded, optimised tau-engine
/// rule — the exact form Chainsaw evaluates during `chainsaw hunt --sigma`.
pub fn sigma_to_tau(yaml: &str) -> Result<tau_engine::Rule> {
    let doc: SigmaDoc = match serde_norway::from_str(yaml) {
        Ok(d) => d,
        Err(e) => return err(format!("yaml parse: {e}")),
    };
    if doc.action.is_some() {
        return err("rule collections are not supported");
    }
    let detection = match doc.detection {
        Some(d) => d,
        None => return err("missing detection"),
    };
    if let Some(Yaml::String(c)) = &detection.condition {
        if c.contains(" | ") {
            return err("aggregation conditions are not supported");
        }
    }

    let tau = detections_to_tau(detection)?;
    let rule_yaml = serde_norway::to_string(&Yaml::Mapping(tau))
        .map_err(|e| ConvertError(format!("serialize: {e}")))?;

    let mut rule = tau_engine::Rule::from_str(&rule_yaml)
        .map_err(|e| ConvertError(format!("tau load: {e}")))?;

    // The same optimiser stack Chainsaw applies after conversion
    // (chainsaw/src/rule/mod.rs).
    rule.detection.expression = tau_engine::core::optimiser::coalesce(
        rule.detection.expression,
        &rule.detection.identifiers,
    );
    rule.detection.identifiers.clear();
    rule.detection.expression = tau_engine::core::optimiser::shake(rule.detection.expression);
    rule.detection.expression = tau_engine::core::optimiser::rewrite(rule.detection.expression);
    rule.detection.expression = tau_engine::core::optimiser::matrix(rule.detection.expression);

    Ok(rule)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn convert_and_match_basic_rule() {
        let rule = r"
title: Test
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains: '-EncodedCommand'
    condition: selection
";
        let tau = sigma_to_tau(rule).expect("conversion failed");
        let hit = json!({ "CommandLine": "powershell -encodedcommand abc" });
        let miss = json!({ "CommandLine": "notepad.exe" });
        assert!(tau.matches(&hit), "converted rule should match (case-insensitive)");
        assert!(!tau.matches(&miss));
    }

    #[test]
    fn convert_one_of_selection_star() {
        let rule = r"
title: Test
logsource:
    category: process_creation
detection:
    selection_a:
        Image|endswith: '\whoami.exe'
    selection_b:
        CommandLine|contains: '/priv'
    condition: 1 of selection_*
";
        let tau = sigma_to_tau(rule).expect("conversion failed");
        assert!(tau.matches(&json!({ "Image": r"C:\Windows\System32\whoami.exe" })));
        assert!(tau.matches(&json!({ "CommandLine": "whoami /priv" })));
        assert!(!tau.matches(&json!({ "Image": r"C:\Windows\notepad.exe" })));
    }

    #[test]
    fn unsupported_modifier_is_rejected() {
        let rule = r"
title: Test
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|windash: '-enc'
    condition: selection
";
        assert!(sigma_to_tau(rule).is_err());
    }

    #[test]
    fn filter_not_condition() {
        let rule = r"
title: Test
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith: '\certutil.exe'
    filter:
        CommandLine|contains: 'legit'
    condition: selection and not filter
";
        let tau = sigma_to_tau(rule).expect("conversion failed");
        assert!(tau.matches(&json!({ "Image": r"C:\Windows\System32\certutil.exe", "CommandLine": "certutil -urlcache" })));
        assert!(!tau.matches(&json!({ "Image": r"C:\Windows\System32\certutil.exe", "CommandLine": "certutil legit" })));
    }
}
