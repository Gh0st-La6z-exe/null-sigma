// =============================================================================
// Sigma Rule Engine — Field Name Mapping
// =============================================================================
// Sigma rules use canonical field names from Windows Event Logs, Sysmon, etc.
// The consuming application may use a different naming convention (e.g.,
// snake_case fields in an event_data JSON payload).
// This module translates between the two transparently.
//
// Example:
//   Sigma rule has: `CommandLine|contains: "powershell -enc"`
//   Application event has: `event_data.command_line: "powershell -enc ..."`
//   FieldMapping translates "CommandLine" → "command_line" transparently.
//
// EXTENSIBLE: Users can provide custom mappings for non-standard field names
// from their specific log sources (custom EDR, cloud, SaaS, etc.).
// =============================================================================

use std::collections::HashMap;

/// Field name mapping configuration. Maps Sigma canonical field names
/// to the consuming application's field names.
///
/// Lookups are case-insensitive since Sigma field names can vary in casing
/// across different rule repositories.
#[derive(Debug, Clone)]
pub struct FieldMapping {
    /// Mapping from lowercase Sigma field name → application field name.
    mappings: HashMap<String, String>,
    /// Reverse mapping: lowercase application field name → lowercase Sigma field name.
    /// Pre-built at construction time so `enrich_event_cow` can iterate `O(n_event)`
    /// instead of `O(n_mappings)` on the hot path.
    reverse: HashMap<String, String>,
}

/// Each entry is `(sigma_name, canonical_name)`. Keys are lowercased at insert
/// time via the `add()` helper. This table is the single source of truth for
/// all field name translations and can be extended without touching `new()`.
const SIGMA_FIELD_PAIRS: &[(&str, &str)] = &[
    // Sysmon Process Events (EID 1, 5, 6, 7, 8, 9, 10, 25)
    ("CommandLine",         "command_line"),
    ("Image",               "image"),
    ("ParentImage",         "parent_image"),
    ("ParentCommandLine",   "parent_command_line"),
    ("OriginalFileName",    "original_file_name"),
    ("CurrentDirectory",    "current_directory"),
    ("User",                "user"),
    ("LogonId",             "logon_id"),
    ("IntegrityLevel",      "integrity_level"),
    ("Hashes",              "hashes"),
    ("ProcessId",           "process_id"),
    ("ParentProcessId",     "parent_process_id"),
    ("ProcessGuid",         "process_guid"),
    ("ParentProcessGuid",   "parent_process_guid"),
    ("Company",             "company"),
    ("Product",             "product"),
    ("Description",         "description"),
    ("FileVersion",         "file_version"),
    ("UtcTime",             "utc_time"),
    // Sysmon Network Events (EID 3)
    ("DestinationIp",       "destination_ip"),
    ("DestinationPort",     "destination_port"),
    ("DestinationHostname", "destination_hostname"),
    ("SourceIp",            "source_ip"),
    ("SourcePort",          "source_port"),
    ("Protocol",            "protocol"),
    ("Initiated",           "initiated"),
    ("SourceIsIpv6",        "source_is_ipv6"),
    ("DestinationIsIpv6",   "destination_is_ipv6"),
    // Sysmon File Events (EID 11, 15, 23, 26)
    ("TargetFilename",      "target_filename"),
    ("CreationUtcTime",     "creation_utc_time"),
    // Sysmon Registry Events (EID 12, 13, 14)
    ("TargetObject",        "target_object"),
    ("EventType",           "event_type"),
    ("Details",             "details"),
    // Sysmon DNS Events (EID 22)
    ("QueryName",           "query_name"),
    ("QueryStatus",         "query_status"),
    ("QueryResults",        "query_results"),
    // Sysmon Pipe Events (EID 17, 18)
    ("PipeName",            "pipe_name"),
    // Sysmon WMI Events (EID 19, 20, 21)
    ("EventNamespace",      "event_namespace"),
    ("Name",                "name"),
    ("Destination",         "destination"),
    ("Consumer",            "consumer"),
    ("Filter",              "filter"),
    // Sysmon Driver/Image Load (EID 6, 7)
    ("ImageLoaded",         "image_loaded"),
    ("SignatureStatus",     "signature_status"),
    ("Signature",           "signature"),
    ("Signed",              "signed"),
    // Sysmon LSASS/Process Access (EID 10)
    ("SourceImage",         "source_image"),
    ("TargetImage",         "target_image"),
    ("GrantedAccess",       "granted_access"),
    ("CallTrace",           "call_trace"),
    // Sysmon Clipboard (EID 24)
    ("ClientInfo",          "client_info"),
    // Sysmon FileDelete (EID 23, 26)
    ("IsExecutable",        "is_executable"),
    ("Archived",            "archived"),
    // Windows Security Log
    ("TargetUserName",              "target_user_name"),
    ("TargetDomainName",            "target_domain_name"),
    ("SubjectUserName",             "subject_user_name"),
    ("SubjectDomainName",           "subject_domain_name"),
    ("LogonType",                   "logon_type"),
    ("IpAddress",                   "ip_address"),
    ("IpPort",                      "ip_port"),
    ("WorkstationName",             "workstation_name"),
    ("AuthenticationPackageName",   "authentication_package_name"),
    ("Status",                      "status"),
    ("SubStatus",                   "sub_status"),
    ("FailureReason",               "failure_reason"),
    ("TargetLogonId",               "target_logon_id"),
    ("SubjectLogonId",              "subject_logon_id"),
    ("PrivilegeList",               "privilege_list"),
    ("ServiceName",                 "service_name"),
    ("ServiceFileName",             "service_file_name"),
    ("ServiceType",                 "service_type"),
    ("ServiceStartType",            "service_start_type"),
    ("ObjectName",                  "object_name"),
    ("ObjectType",                  "object_type"),
    ("AccessMask",                  "access_mask"),
    ("TaskName",                    "task_name"),
    ("TaskContent",                 "task_content"),
    // Windows PowerShell / Script Block Logging
    ("ScriptBlockText",  "script_block_text"),
    ("ScriptBlockId",    "script_block_id"),
    ("Path",             "path"),
    ("HostApplication", "host_application"),
    ("HostName",         "host_name"),
    // Windows Defender / AV
    ("ThreatName",  "threat_name"),
    ("NewValue",    "new_value"),
    ("OldValue",    "old_value"),
    // Linux auditd / syslog
    ("comm",       "comm"),
    ("exe",        "exe"),
    ("key",        "key"),
    ("syscall",    "syscall"),
    ("type",       "audit_type"),
    ("uid",        "uid"),
    ("gid",        "gid"),
    ("euid",       "euid"),
    ("pid",        "pid"),
    ("ppid",       "ppid"),
    ("a0",         "a0"),
    ("a1",         "a1"),
    ("a2",         "a2"),
    ("a3",         "a3"),
    ("cwd",        "cwd"),
    ("proctitle",  "proctitle"),
    // Generic / Cross-Platform
    ("md5",     "md5"),
    ("sha1",    "sha1"),
    ("sha256",  "sha256"),
    ("imphash", "imphash"),
];

impl FieldMapping {
    /// Create a new `FieldMapping` with default Sigma → `snake_case` translations.
    /// Covers Sysmon, Windows Security, Linux auditd, and generic fields.
    #[must_use]
    pub fn new() -> Self {
        let mut mappings = HashMap::with_capacity(SIGMA_FIELD_PAIRS.len());
        let mut reverse  = HashMap::with_capacity(SIGMA_FIELD_PAIRS.len());
        for &(sigma, canonical) in SIGMA_FIELD_PAIRS {
            let sigma_lower    = sigma.to_lowercase();
            let canonical_lower = canonical.to_lowercase();
            reverse.entry(canonical_lower).or_insert_with(|| sigma_lower.clone());
            add(&mut mappings, sigma, canonical);
        }
        FieldMapping { mappings, reverse }
    }

    /// Create an empty mapping (for testing or when no translation is wanted).
    #[must_use]
    pub fn empty() -> Self {
        FieldMapping { mappings: HashMap::new(), reverse: HashMap::new() }
    }

    /// Add a custom field mapping.
    pub fn add_mapping(&mut self, sigma_name: &str, canonical_name: &str) {
        let sigma_lower     = sigma_name.to_lowercase();
        let canonical_lower = canonical_name.to_lowercase();
        self.reverse.entry(canonical_lower).or_insert_with(|| sigma_lower.clone());
        self.mappings.insert(sigma_lower, canonical_name.to_string());
    }

    /// Add multiple custom mappings at once.
    pub fn add_mappings(&mut self, map: &HashMap<String, String>) {
        for (k, v) in map {
            let sigma_lower     = k.to_lowercase();
            let canonical_lower = v.to_lowercase();
            self.reverse.entry(canonical_lower).or_insert_with(|| sigma_lower.clone());
            self.mappings.insert(sigma_lower, v.clone());
        }
    }

    /// Translate a Sigma field name to the application's field name.
    /// Returns the original name if no mapping exists (passthrough for
    /// events that already use the correct naming convention).
    #[must_use]
    pub fn translate(&self, sigma_field: &str) -> String {
        let lower = sigma_field.to_lowercase();
        self.mappings
            .get(&lower)
            .cloned()
            .unwrap_or_else(|| sigma_field.to_string())
    }

    /// Translate event data keys from application format back to Sigma format.
    ///
    /// Returns a new map containing all original keys PLUS any Sigma-canonical
    /// aliases for application field names found in the event.  If no aliases are
    /// needed the event is cloned as-is.
    ///
    /// For callers that can accept a `Cow`, prefer [`enrich_event_cow`] which
    /// avoids the clone entirely when the event already uses Sigma field names.
    ///
    /// [`enrich_event_cow`]: FieldMapping::enrich_event_cow
    #[must_use]
    pub fn enrich_event(&self, event: &std::collections::HashMap<String, String>) -> std::collections::HashMap<String, String> {
        self.enrich_event_cow(event).into_owned()
    }

    /// Like [`enrich_event`] but returns a [`Cow`] to avoid the heap allocation
    /// when the event already uses Sigma-canonical field names.
    ///
    /// - **`Cow::Borrowed`** — event already has the right field names; zero
    ///   allocation on the caller side.
    /// - **`Cow::Owned`** — event had application `snake_case` names; aliases were
    ///   added and the map was cloned once.
    ///
    /// Uses the pre-built reverse map to iterate `O(n_event)` rather than
    /// `O(n_mappings)` per call.
    ///
    /// [`enrich_event`]: FieldMapping::enrich_event
    /// [`Cow`]: std::borrow::Cow
    #[must_use]
    pub fn enrich_event_cow<'a>(
        &self,
        event: &'a std::collections::HashMap<String, String>,
    ) -> std::borrow::Cow<'a, std::collections::HashMap<String, String>> {
        // Collect only the aliases that are actually needed.
        // Iterates the event entries (typically 10-30) — not all ~120 mapping pairs.
        let mut aliases: Vec<(String, String)> = Vec::new();
        for (key, value) in event {
            let key_lower = key.to_lowercase();
            if let Some(sigma_lower) = self.reverse.get(&key_lower) {
                // Only add the alias if the event doesn't already have the Sigma name.
                if !event.contains_key(sigma_lower.as_str()) {
                    aliases.push((sigma_lower.clone(), value.clone()));
                }
            }
        }

        if aliases.is_empty() {
            // Fast path: event already uses Sigma names — no allocation needed.
            return std::borrow::Cow::Borrowed(event);
        }

        // Slow path: clone once, then insert only the needed aliases.
        let mut enriched = event.clone();
        for (k, v) in aliases {
            enriched.insert(k, v);
        }
        std::borrow::Cow::Owned(enriched)
    }

    /// Get the number of configured mappings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.mappings.len()
    }

    /// Check if the mapping table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.mappings.is_empty()
    }
}

impl Default for FieldMapping {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper to insert the lowercased Sigma name → canonical application name pair.
fn add(map: &mut HashMap<String, String>, sigma: &str, canonical: &str) {
    map.insert(sigma.to_lowercase(), canonical.to_string());
}
