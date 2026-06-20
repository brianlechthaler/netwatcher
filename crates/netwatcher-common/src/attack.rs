use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{ZeekLogType, ZeekLogType as LogType};

/// MITRE ATT&CK enrichment extracted from BZAR Zeek notices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackEnrichment {
    pub matched: bool,
    pub tactic: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tactic_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub technique_id: Option<String>,
    pub technique: String,
    pub notice_type: String,
    pub description: String,
    pub source: String,
}

/// Parse a Zeek notice JSON payload produced by BZAR into ATT&CK metadata.
pub fn extract_bzar_attack(
    raw: &Value,
    zeek_log_type: Option<&ZeekLogType>,
) -> Option<AttackEnrichment> {
    let is_notice = matches!(zeek_log_type, Some(LogType::Notice))
        || raw
            .get("note")
            .and_then(Value::as_str)
            .is_some_and(|n| n.starts_with("ATTACK::"));
    if !is_notice {
        return None;
    }

    let note = raw.get("note").and_then(Value::as_str)?;
    if !note.starts_with("ATTACK::") {
        return None;
    }

    let tactic_key = note.strip_prefix("ATTACK::")?;
    let tactic = tactic_key.replace('_', " ");
    let msg = raw.get("msg").and_then(Value::as_str).unwrap_or("");
    let sub = raw.get("sub").and_then(Value::as_str);

    let (technique_id, technique) = if let Some(sub_text) = sub {
        let (id, name) = parse_technique_text(sub_text);
        (id, name)
    } else {
        let (id, name) = parse_technique_text(msg);
        (
            id,
            if name.is_empty() {
                msg.to_string()
            } else {
                name
            },
        )
    };

    Some(AttackEnrichment {
        matched: true,
        tactic: tactic.clone(),
        tactic_id: tactic_to_mitre_id(tactic_key),
        technique_id,
        technique,
        notice_type: note.to_string(),
        description: msg.to_string(),
        source: "bzar".to_string(),
    })
}

fn parse_technique_text(text: &str) -> (Option<String>, String) {
    let trimmed = text.trim();
    if let Some(id) = extract_technique_id(trimmed) {
        let name = trimmed
            .strip_prefix(&id)
            .map(str::trim)
            .unwrap_or(trimmed)
            .to_string();
        (Some(id), name)
    } else {
        (None, trimmed.to_string())
    }
}

fn extract_technique_id(text: &str) -> Option<String> {
    let upper = text.to_uppercase();
    let bytes = upper.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'T' {
            let major_start = i + 1;
            let major_end = major_start + 4;
            if major_end > bytes.len() {
                break;
            }
            let major = &upper[major_start..major_end];
            if !major.chars().all(|c| c.is_ascii_digit()) {
                i += 1;
                continue;
            }
            let mut id = format!("T{major}");
            if major_end < bytes.len() && bytes[major_end] == b'.' {
                let minor_start = major_end + 1;
                let minor_end = minor_start + 3;
                if minor_end <= bytes.len() {
                    let minor = &upper[minor_start..minor_end];
                    if minor.chars().all(|c| c.is_ascii_digit()) {
                        id.push('.');
                        id.push_str(minor);
                    }
                }
            }
            return Some(id);
        }
        i += 1;
    }
    None
}

fn tactic_to_mitre_id(tactic_key: &str) -> Option<String> {
    Some(
        match tactic_key {
            "Credential_Access" => "TA0006",
            "Defense_Evasion" => "TA0005",
            "Discovery" => "TA0007",
            "Execution" => "TA0002",
            "Impact" => "TA0040",
            "Lateral_Movement"
            | "Lateral_Movement_and_Execution"
            | "Lateral_Movement_Extracted_File"
            | "Lateral_Movement_Multiple_Attempts" => "TA0008",
            "Persistence" => "TA0003",
            _ => return None,
        }
        .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_bzar_notice_with_sub_field() {
        let raw = json!({
            "ts": 1718582400.0,
            "note": "ATTACK::Credential_Access",
            "msg": "Detected DCSync against 10.0.0.5",
            "sub": "T1003.006 OS Credential Dumping: DCSync",
            "id.orig_h": "10.0.0.2",
            "id.resp_h": "10.0.0.5"
        });
        let attack = extract_bzar_attack(&raw, Some(&ZeekLogType::Notice)).unwrap();
        assert!(attack.matched);
        assert_eq!(attack.tactic, "Credential Access");
        assert_eq!(attack.tactic_id.as_deref(), Some("TA0006"));
        assert_eq!(attack.technique_id.as_deref(), Some("T1003.006"));
        assert_eq!(attack.technique, "OS Credential Dumping: DCSync");
        assert_eq!(attack.source, "bzar");
    }

    #[test]
    fn parses_sumstats_notice_from_msg() {
        let raw = json!({
            "note": "ATTACK::Discovery",
            "msg": "Detected T1018 Remote System Discovery from host 10.0.0.3"
        });
        let attack = extract_bzar_attack(&raw, Some(&ZeekLogType::Notice)).unwrap();
        assert_eq!(attack.tactic, "Discovery");
        assert_eq!(attack.technique_id.as_deref(), Some("T1018"));
    }

    #[test]
    fn ignores_non_attack_notices() {
        let raw = json!({
            "note": "SSL::Invalid_Server_Cert",
            "msg": "invalid cert"
        });
        assert!(extract_bzar_attack(&raw, Some(&ZeekLogType::Notice)).is_none());
    }

    #[test]
    fn ignores_non_notice_logs() {
        let raw = json!({"id.orig_h": "10.0.0.1"});
        assert!(extract_bzar_attack(&raw, Some(&ZeekLogType::Conn)).is_none());
    }
}
