// =============================================================================
// Sigma Rule Engine — Field-Presence Bitmask
// =============================================================================
// Maps canonical Sigma field names (and common snake_case aliases) to a compact
// 64-bit mask representation.
//
// Allows O(1) single-cycle bitwise rejection of rules that require fields absent
// from the event being evaluated.
// =============================================================================

/// Return the dense bit index (0..64) for a folded (lowercased) field name, if known.
#[inline]
pub(crate) fn field_bit(s: &str) -> Option<u8> {
    match s {
        "commandline" | "command_line" => Some(0),
        "image" => Some(1),
        "parentimage" | "parent_image" => Some(2),
        "parentcommandline" | "parent_command_line" => Some(3),
        "originalfilename" | "original_file_name" => Some(4),
        "currentdirectory" | "current_directory" => Some(5),
        "user" => Some(6),
        "logonid" | "logon_id" => Some(7),
        "integritylevel" | "integrity_level" => Some(8),
        "hashes" => Some(9),
        "processid" | "process_id" => Some(10),
        "parentprocessid" | "parent_process_id" => Some(11),
        "processguid" | "process_guid" => Some(12),
        "parentprocessguid" | "parent_process_guid" => Some(13),
        "company" => Some(14),
        "product" => Some(15),
        "description" => Some(16),
        "fileversion" | "file_version" => Some(17),
        "targetfilename" | "target_filename" => Some(18),
        "targetobject" | "target_object" => Some(19),
        "details" => Some(20),
        "destinationip" | "destination_ip" => Some(21),
        "destinationport" | "destination_port" => Some(22),
        "destinationhostname" | "destination_hostname" => Some(23),
        "sourceip" | "source_ip" => Some(24),
        "sourceport" | "source_port" => Some(25),
        "protocol" => Some(26),
        "queryname" | "query_name" => Some(27),
        "pipename" | "pipe_name" => Some(28),
        "scriptblocktext" | "script_block_text" => Some(29),
        "scriptblockid" | "script_block_id" => Some(30),
        "targetusername" | "target_user_name" => Some(31),
        "targetdomainname" | "target_domain_name" => Some(32),
        "subjectusername" | "subject_user_name" => Some(33),
        "subjectdomainname" | "subject_domain_name" => Some(34),
        "servicename" | "service_name" => Some(35),
        "servicefilename" | "service_file_name" => Some(36),
        "taskname" | "task_name" => Some(37),
        "eventtype" | "event_type" => Some(38),
        "imageloaded" | "image_loaded" => Some(39),
        "sourceimage" | "source_image" => Some(40),
        "targetimage" | "target_image" => Some(41),
        "calltrace" | "call_trace" => Some(42),
        "grantedaccess" | "granted_access" => Some(43),
        "hostapplication" | "host_application" => Some(44),
        "hostname" | "host_name" => Some(45),
        "newvalue" | "new_value" => Some(46),
        "oldvalue" | "old_value" => Some(47),
        "threatname" | "threat_name" => Some(48),
        "path" => Some(49),
        "comm" => Some(50),
        "exe" => Some(51),
        "key" => Some(52),
        "syscall" => Some(53),
        "cwd" => Some(54),
        "proctitle" => Some(55),
        "md5" => Some(56),
        "sha1" => Some(57),
        "sha256" => Some(58),
        "imphash" => Some(59),
        "utctime" | "utc_time" => Some(60),
        "creationutctime" | "creation_utc_time" => Some(61),
        "signature" => Some(62),
        "signed" => Some(63),
        _ => None,
    }
}

/// Return the canonical folded field name for a given bit (0..63).
#[inline]
pub(crate) fn bit_field(bit: u8) -> Option<&'static str> {
    match bit {
        0 => Some("commandline"),
        1 => Some("image"),
        2 => Some("parentimage"),
        3 => Some("parentcommandline"),
        4 => Some("originalfilename"),
        5 => Some("currentdirectory"),
        6 => Some("user"),
        7 => Some("logonid"),
        8 => Some("integritylevel"),
        9 => Some("hashes"),
        10 => Some("processid"),
        11 => Some("parentprocessid"),
        12 => Some("processguid"),
        13 => Some("parentprocessguid"),
        14 => Some("company"),
        15 => Some("product"),
        16 => Some("description"),
        17 => Some("fileversion"),
        18 => Some("targetfilename"),
        19 => Some("targetobject"),
        20 => Some("details"),
        21 => Some("destinationip"),
        22 => Some("destinationport"),
        23 => Some("destinationhostname"),
        24 => Some("sourceip"),
        25 => Some("sourceport"),
        26 => Some("protocol"),
        27 => Some("queryname"),
        28 => Some("pipename"),
        29 => Some("scriptblocktext"),
        30 => Some("scriptblockid"),
        31 => Some("targetusername"),
        32 => Some("targetdomainname"),
        33 => Some("subjectusername"),
        34 => Some("subjectdomainname"),
        35 => Some("servicename"),
        36 => Some("servicefilename"),
        37 => Some("taskname"),
        38 => Some("eventtype"),
        39 => Some("imageloaded"),
        40 => Some("sourceimage"),
        41 => Some("targetimage"),
        42 => Some("calltrace"),
        43 => Some("grantedaccess"),
        44 => Some("hostapplication"),
        45 => Some("hostname"),
        _ => None,
    }
}

/// Compute the 64-bit mask for a single folded field name.
/// Returns 0 if the field is not in the canonical bit dictionary.
#[cfg(test)]
#[inline]
pub(crate) fn single_field_mask(s: &str) -> u64 {
    field_bit(s).map_or(0, |bit| 1u64 << bit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_64_bits_unique() {
        let mut seen = [false; 64];
        let primary_fields = [
            "commandline",
            "image",
            "parentimage",
            "parentcommandline",
            "originalfilename",
            "currentdirectory",
            "user",
            "logonid",
            "integritylevel",
            "hashes",
            "processid",
            "parentprocessid",
            "processguid",
            "parentprocessguid",
            "company",
            "product",
            "description",
            "fileversion",
            "targetfilename",
            "targetobject",
            "details",
            "destinationip",
            "destinationport",
            "destinationhostname",
            "sourceip",
            "sourceport",
            "protocol",
            "queryname",
            "pipename",
            "scriptblocktext",
            "scriptblockid",
            "targetusername",
            "targetdomainname",
            "subjectusername",
            "subjectdomainname",
            "servicename",
            "servicefilename",
            "taskname",
            "eventtype",
            "imageloaded",
            "sourceimage",
            "targetimage",
            "calltrace",
            "grantedaccess",
            "hostapplication",
            "hostname",
            "newvalue",
            "oldvalue",
            "threatname",
            "path",
            "comm",
            "exe",
            "key",
            "syscall",
            "cwd",
            "proctitle",
            "md5",
            "sha1",
            "sha256",
            "imphash",
            "utctime",
            "creationutctime",
            "signature",
            "signed",
        ];

        assert_eq!(primary_fields.len(), 64);

        for (expected_bit, name) in primary_fields.iter().enumerate() {
            let bit = field_bit(name).expect("must be mapped");
            assert_eq!(bit as usize, expected_bit, "field {name} at wrong bit");
            assert!(!seen[bit as usize], "bit {bit} used multiple times");
            seen[bit as usize] = true;
        }

        assert!(seen.iter().all(|&b| b), "all 64 bits must be covered");
    }

    #[test]
    fn test_snake_case_aliases_map_to_same_bits() {
        assert_eq!(field_bit("commandline"), field_bit("command_line"));
        assert_eq!(field_bit("parentimage"), field_bit("parent_image"));
        assert_eq!(field_bit("targetfilename"), field_bit("target_filename"));
        assert_eq!(field_bit("scriptblocktext"), field_bit("script_block_text"));
    }

    #[test]
    fn test_unknown_field_returns_none() {
        assert_eq!(field_bit("totally_unknown_custom_field"), None);
        assert_eq!(single_field_mask("totally_unknown_custom_field"), 0);
    }
}
