// =============================================================================
// NuLLAI Sigma Rule Engine — Field Name Mapping
// =============================================================================
// Sigma rules use canonical field names from Windows Event Logs, Sysmon, etc.
// NuLLAI's internal event model uses snake_case fields in the `event_data` JSON.
// This module translates between the two.
//
// Example:
//   Sigma rule has: `CommandLine|contains: "powershell -enc"`
//   NuLLAI event has: `event_data.command_line: "powershell -enc ..."`
//   FieldMapping translates "CommandLine" → "command_line" transparently.
//
// EXTENSIBLE: Users can provide custom mappings for non-standard field names
// from their specific log sources (custom EDR, cloud, SaaS, etc.).
// =============================================================================

use std::collections::HashMap;

/// Field name mapping configuration. Maps Sigma canonical field names
/// to NuLLAI event_data field names.
///
/// Lookups are case-insensitive since Sigma field names can vary in casing
/// across different rule repositories.
#[derive(Debug, Clone)]
pub struct FieldMapping {
    /// Mapping from lowercase Sigma field name → NuLLAI field name.
    mappings: HashMap<String, String>,
}

impl FieldMapping {
    /// Create a new FieldMapping with default Sigma → NuLLAI translations.
    /// Covers Sysmon, Windows Security, Linux auditd, and generic fields.
    pub fn new() -> Self {
        let mut mappings = HashMap::new();

        // ─── Sysmon Process Events (EID 1, 5, 6, 7, 8, 9, 10, 25) ─────
        add(&mut mappings, "CommandLine", "command_line");
        add(&mut mappings, "Image", "image");
        add(&mut mappings, "ParentImage", "parent_image");
        add(&mut mappings, "ParentCommandLine", "parent_command_line");
        add(&mut mappings, "OriginalFileName", "original_file_name");
        add(&mut mappings, "CurrentDirectory", "current_directory");
        add(&mut mappings, "User", "user");
        add(&mut mappings, "LogonId", "logon_id");
        add(&mut mappings, "IntegrityLevel", "integrity_level");
        add(&mut mappings, "Hashes", "hashes");
        add(&mut mappings, "ProcessId", "process_id");
        add(&mut mappings, "ParentProcessId", "parent_process_id");
        add(&mut mappings, "ProcessGuid", "process_guid");
        add(&mut mappings, "ParentProcessGuid", "parent_process_guid");
        add(&mut mappings, "Company", "company");
        add(&mut mappings, "Product", "product");
        add(&mut mappings, "Description", "description");
        add(&mut mappings, "FileVersion", "file_version");
        add(&mut mappings, "UtcTime", "utc_time");

        // ─── Sysmon Network Events (EID 3) ─────────────────────────────
        add(&mut mappings, "DestinationIp", "destination_ip");
        add(&mut mappings, "DestinationPort", "destination_port");
        add(&mut mappings, "DestinationHostname", "destination_hostname");
        add(&mut mappings, "SourceIp", "source_ip");
        add(&mut mappings, "SourcePort", "source_port");
        add(&mut mappings, "Protocol", "protocol");
        add(&mut mappings, "Initiated", "initiated");
        add(&mut mappings, "SourceIsIpv6", "source_is_ipv6");
        add(&mut mappings, "DestinationIsIpv6", "destination_is_ipv6");

        // ─── Sysmon File Events (EID 11, 15, 23, 26) ──────────────────
        add(&mut mappings, "TargetFilename", "target_filename");
        add(&mut mappings, "CreationUtcTime", "creation_utc_time");

        // ─── Sysmon Registry Events (EID 12, 13, 14) ──────────────────
        add(&mut mappings, "TargetObject", "target_object");
        add(&mut mappings, "EventType", "event_type");
        add(&mut mappings, "Details", "details");

        // ─── Sysmon DNS Events (EID 22) ────────────────────────────────
        add(&mut mappings, "QueryName", "query_name");
        add(&mut mappings, "QueryStatus", "query_status");
        add(&mut mappings, "QueryResults", "query_results");

        // ─── Sysmon Pipe Events (EID 17, 18) ──────────────────────────
        add(&mut mappings, "PipeName", "pipe_name");

        // ─── Sysmon WMI Events (EID 19, 20, 21) ───────────────────────
        add(&mut mappings, "EventNamespace", "event_namespace");
        add(&mut mappings, "Name", "name");
        add(&mut mappings, "Destination", "destination");
        add(&mut mappings, "Consumer", "consumer");
        add(&mut mappings, "Filter", "filter");

        // ─── Sysmon Driver/Image Load (EID 6, 7) ──────────────────────
        add(&mut mappings, "ImageLoaded", "image_loaded");
        add(&mut mappings, "SignatureStatus", "signature_status");
        add(&mut mappings, "Signature", "signature");
        add(&mut mappings, "Signed", "signed");

        // ─── Sysmon LSASS/Process Access (EID 10) ─────────────────────
        add(&mut mappings, "SourceImage", "source_image");
        add(&mut mappings, "TargetImage", "target_image");
        add(&mut mappings, "GrantedAccess", "granted_access");
        add(&mut mappings, "CallTrace", "call_trace");

        // ─── Sysmon Clipboard (EID 24) ────────────────────────────────
        add(&mut mappings, "ClientInfo", "client_info");

        // ─── Sysmon FileDelete (EID 23, 26) ───────────────────────────
        add(&mut mappings, "IsExecutable", "is_executable");
        add(&mut mappings, "Archived", "archived");

        // ─── Windows Security Log Events ───────────────────────────────
        add(&mut mappings, "TargetUserName", "target_user_name");
        add(&mut mappings, "TargetDomainName", "target_domain_name");
        add(&mut mappings, "SubjectUserName", "subject_user_name");
        add(&mut mappings, "SubjectDomainName", "subject_domain_name");
        add(&mut mappings, "LogonType", "logon_type");
        add(&mut mappings, "IpAddress", "ip_address");
        add(&mut mappings, "IpPort", "ip_port");
        add(&mut mappings, "WorkstationName", "workstation_name");
        add(&mut mappings, "AuthenticationPackageName", "authentication_package_name");
        add(&mut mappings, "Status", "status");
        add(&mut mappings, "SubStatus", "sub_status");
        add(&mut mappings, "FailureReason", "failure_reason");
        add(&mut mappings, "TargetLogonId", "target_logon_id");
        add(&mut mappings, "SubjectLogonId", "subject_logon_id");
        add(&mut mappings, "PrivilegeList", "privilege_list");
        add(&mut mappings, "ServiceName", "service_name");
        add(&mut mappings, "ServiceFileName", "service_file_name");
        add(&mut mappings, "ServiceType", "service_type");
        add(&mut mappings, "ServiceStartType", "service_start_type");
        add(&mut mappings, "ObjectName", "object_name");
        add(&mut mappings, "ObjectType", "object_type");
        add(&mut mappings, "AccessMask", "access_mask");
        add(&mut mappings, "TaskName", "task_name");
        add(&mut mappings, "TaskContent", "task_content");

        // ─── Windows PowerShell / Script Block Logging ────────────────
        add(&mut mappings, "ScriptBlockText", "script_block_text");
        add(&mut mappings, "ScriptBlockId", "script_block_id");
        add(&mut mappings, "Path", "path");
        add(&mut mappings, "HostApplication", "host_application");
        add(&mut mappings, "HostName", "host_name");

        // ─── Windows Defender / AV ────────────────────────────────────
        add(&mut mappings, "ThreatName", "threat_name");
        add(&mut mappings, "NewValue", "new_value");
        add(&mut mappings, "OldValue", "old_value");

        // ─── Linux auditd / syslog Fields ─────────────────────────────
        add(&mut mappings, "comm", "comm");
        add(&mut mappings, "exe", "exe");
        add(&mut mappings, "key", "key");
        add(&mut mappings, "syscall", "syscall");
        add(&mut mappings, "type", "audit_type");
        add(&mut mappings, "uid", "uid");
        add(&mut mappings, "gid", "gid");
        add(&mut mappings, "euid", "euid");
        add(&mut mappings, "pid", "pid");
        add(&mut mappings, "ppid", "ppid");
        add(&mut mappings, "a0", "a0");
        add(&mut mappings, "a1", "a1");
        add(&mut mappings, "a2", "a2");
        add(&mut mappings, "a3", "a3");
        add(&mut mappings, "cwd", "cwd");
        add(&mut mappings, "proctitle", "proctitle");

        // ─── Generic / Cross-Platform ─────────────────────────────────
        add(&mut mappings, "md5", "md5");
        add(&mut mappings, "sha1", "sha1");
        add(&mut mappings, "sha256", "sha256");
        add(&mut mappings, "imphash", "imphash");

        FieldMapping { mappings }
    }

    /// Create an empty mapping (for testing or when no translation is wanted).
    pub fn empty() -> Self {
        FieldMapping { mappings: HashMap::new() }
    }

    /// Add a custom field mapping.
    pub fn add_mapping(&mut self, sigma_name: &str, nullai_name: &str) {
        self.mappings.insert(sigma_name.to_lowercase(), nullai_name.to_string());
    }

    /// Add multiple custom mappings at once.
    pub fn add_mappings(&mut self, map: &HashMap<String, String>) {
        for (k, v) in map {
            self.mappings.insert(k.to_lowercase(), v.clone());
        }
    }

    /// Translate a Sigma field name to the NuLLAI event_data field name.
    /// Returns the original name if no mapping exists (passthrough for
    /// events that already use the correct naming convention).
    pub fn translate(&self, sigma_field: &str) -> String {
        let lower = sigma_field.to_lowercase();
        self.mappings
            .get(&lower)
            .cloned()
            .unwrap_or_else(|| sigma_field.to_string())
    }

    /// Translate event data keys from NuLLAI format back to Sigma format.
    /// Used when we need to match rules that reference Sigma field names
    /// against events that already have NuLLAI field names.
    ///
    /// This creates a new event map with BOTH the original keys AND the
    /// Sigma-canonical keys, so rules can match regardless of naming convention.
    pub fn enrich_event(&self, event: &std::collections::HashMap<String, String>) -> std::collections::HashMap<String, String> {
        let mut enriched = event.clone();

        // Build reverse mapping (nullai → sigma)
        for (sigma_lower, nullai_name) in &self.mappings {
            if let Some(value) = event.get(nullai_name) {
                // Add the Sigma-canonical name pointing to the same value
                // (only if it's not already present to avoid clobbering)
                if !enriched.contains_key(sigma_lower) {
                    enriched.insert(sigma_lower.clone(), value.clone());
                }
            }
        }

        enriched
    }

    /// Get the number of configured mappings.
    pub fn len(&self) -> usize {
        self.mappings.len()
    }

    /// Check if the mapping table is empty.
    pub fn is_empty(&self) -> bool {
        self.mappings.is_empty()
    }
}

impl Default for FieldMapping {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper to insert both the canonical case and lowercase version.
fn add(map: &mut HashMap<String, String>, sigma: &str, nullai: &str) {
    map.insert(sigma.to_lowercase(), nullai.to_string());
}
