fn main() {
    let rule_path = "corpus/sigmahq/rules/windows/process_creation/proc_creation_win_susp_system_user_anomaly.yml";
    let yaml = std::fs::read_to_string(rule_path).expect("failed to read rule");

    match null_sigma_harness::convert::sigma_to_tau(&yaml) {
        Ok(rule) => {
            println!("=== Tau Rule Dump for proc_creation_win_susp_system_user_anomaly.yml ===");
            println!("Detection: {:#?}", rule.detection);
        }
        Err(e) => {
            println!("Tau conversion error: {e}");
        }
    }
}
