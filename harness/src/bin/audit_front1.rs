use null_sigma::SigmaEngine;
use std::collections::HashMap;
use std::path::PathBuf;

fn collect_yaml_files(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
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

fn main() {
    let windows_dir = PathBuf::from("corpus/sigmahq/rules/windows");
    let mut files = Vec::new();
    collect_yaml_files(&windows_dir, &mut files);
    files.sort();

    let mut engine = SigmaEngine::new();
    let mut loaded = 0usize;
    for file in &files {
        let Ok(content) = std::fs::read_to_string(file) else {
            continue;
        };
        if engine.load_rule(&content).is_ok() {
            loaded += 1;
        }
    }

    println!("===============================================================================");
    println!("             NULL-SIGMA FRONT 1: HARD LOGSOURCE & DISCRIMINATOR AUDIT          ");
    println!("===============================================================================");
    println!("Total rules loaded: {}", loaded);

    let (img, pimg, il, eid, pipe, qn, tfn, unconstrained) = engine.extended_discriminator_stats();
    println!("\nInverted Index Statistics:");
    println!("  Image Discriminators          : {:5} keys", img);
    println!("  ParentImage Discriminators    : {:5} keys", pimg);
    println!("  ImageLoaded Discriminators    : {:5} keys", il);
    println!("  EventID Discriminators        : {:5} keys", eid);
    println!("  PipeName Discriminators       : {:5} keys", pipe);
    println!("  QueryName Discriminators      : {:5} keys", qn);
    println!("  TargetFilename Discriminators : {:5} keys", tfn);
    println!(
        "  Total Unconstrained Rules     : {:5} / {} ({:.1}%)",
        unconstrained,
        loaded,
        unconstrained as f64 * 100.0 / loaded as f64
    );

    // Test candidate funnel on 5 distinct category events
    let mut proc_event = HashMap::new();
    proc_event.insert("category".into(), "process_creation".into());
    proc_event.insert("product".into(), "windows".into());
    proc_event.insert("Image".into(), r"C:\Windows\System32\cmd.exe".into());
    proc_event.insert("CommandLine".into(), "cmd.exe /c whoami".into());

    let mut reg_event = HashMap::new();
    reg_event.insert("category".into(), "registry_set".into());
    reg_event.insert("product".into(), "windows".into());
    reg_event.insert("EventID".into(), "13".into());
    reg_event.insert(
        "TargetObject".into(),
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Malware".into(),
    );

    let mut ps_event = HashMap::new();
    ps_event.insert("service".into(), "powershell".into());
    ps_event.insert("product".into(), "windows".into());
    ps_event.insert("EventID".into(), "4104".into());
    ps_event.insert("ScriptBlockText".into(), "Invoke-Mimikatz".into());

    let mut logon_event = HashMap::new();
    logon_event.insert("Channel".into(), "Security".into());
    logon_event.insert("product".into(), "windows".into());
    logon_event.insert("EventID".into(), "4624".into());

    let mut file_event = HashMap::new();
    file_event.insert("category".into(), "file_event".into());
    file_event.insert("product".into(), "windows".into());
    file_event.insert(
        "TargetFilename".into(),
        r"C:\Users\Admin\AppData\Local\Temp\payload.exe".into(),
    );

    println!(
        "\nCandidate Funnel Diagnostics (Candidates, Logsource, Fields, Bloom, Branches, Cold):"
    );
    let p_fun = engine.profile_candidate_funnel(&proc_event);
    println!(
        "  Process Creation (cmd.exe) : {} candidates -> {} passed logsource -> {} bloom",
        p_fun.0, p_fun.1, p_fun.3
    );

    let r_fun = engine.profile_candidate_funnel(&reg_event);
    println!(
        "  Registry Set (EID 13)      : {} candidates -> {} passed logsource -> {} bloom",
        r_fun.0, r_fun.1, r_fun.3
    );

    let ps_fun = engine.profile_candidate_funnel(&ps_event);
    println!(
        "  PowerShell (EID 4104)      : {} candidates -> {} passed logsource -> {} bloom",
        ps_fun.0, ps_fun.1, ps_fun.3
    );

    let l_fun = engine.profile_candidate_funnel(&logon_event);
    println!(
        "  Security Logon (EID 4624)  : {} candidates -> {} passed logsource -> {} bloom",
        l_fun.0, l_fun.1, l_fun.3
    );

    let f_fun = engine.profile_candidate_funnel(&file_event);
    println!(
        "  File Event (payload.exe)   : {} candidates -> {} passed logsource -> {} bloom",
        f_fun.0, f_fun.1, f_fun.3
    );
    println!("===============================================================================\n");
}
