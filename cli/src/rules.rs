//! Load Sigma YAML rules from a directory into a [`null_sigma::SigmaEngine`].

use std::path::Path;

pub fn load_rules_from_dir(
    rule_dir: &Path,
) -> Result<(null_sigma::SigmaEngine, usize, usize, u128), String> {
    let start = std::time::Instant::now();
    let mut engine = null_sigma::SigmaEngine::new();
    let entries = std::fs::read_dir(rule_dir)
        .map_err(|e| format!("cannot read rule dir '{}': {e}", rule_dir.display()))?;
    let mut paths: Vec<_> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|ext| ext == "yml" || ext == "yaml"))
        .collect();
    paths.sort();

    let joined = paths
        .iter()
        .map(|p| {
            std::fs::read_to_string(p)
                .map_err(|e| format!("cannot read rule '{}': {e}", p.display()))
        })
        .collect::<Result<Vec<_>, _>>()?
        .join("\n---\n");

    let (loaded_ids, errors) = engine.load_rules(&joined);
    let load_ms = start.elapsed().as_millis();
    Ok((engine, loaded_ids.len(), errors.len(), load_ms))
}
