use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::{EventSource, IngestEvent, ZeekLogType};

pub fn parse_zeek_json_line(line: &str, log_type: &str) -> Option<IngestEvent> {
    let raw: Value = serde_json::from_str(line).ok()?;
    let timestamp = extract_timestamp(&raw).unwrap_or_else(Utc::now);
    Some(IngestEvent {
        source: EventSource::Zeek,
        zeek_log_type: Some(map_zeek_log_type(log_type)),
        timestamp,
        raw,
    })
}

pub fn parse_p0f_line(line: &str) -> Option<IngestEvent> {
    if line.trim().is_empty() || line.starts_with('#') {
        return None;
    }
    let parts: Vec<&str> = line.split('|').collect();
    if parts.len() < 5 {
        return None;
    }
    let raw = serde_json::json!({
        "mod": parts.first().unwrap_or(&""),
        "src_ip": parts.get(1).unwrap_or(&""),
        "dst_ip": parts.get(2).unwrap_or(&""),
        "link": parts.get(3).unwrap_or(&""),
        "detail": parts.get(4).unwrap_or(&""),
        "raw_line": line
    });
    Some(IngestEvent {
        source: EventSource::P0f,
        zeek_log_type: None,
        timestamp: Utc::now(),
        raw,
    })
}

pub fn parse_fatt_line(line: &str) -> Option<IngestEvent> {
    let raw: Value = serde_json::from_str(line).ok()?;
    let timestamp = extract_timestamp(&raw).unwrap_or_else(Utc::now);
    Some(IngestEvent {
        source: EventSource::Fatt,
        zeek_log_type: None,
        timestamp,
        raw,
    })
}

fn extract_timestamp(raw: &Value) -> Option<DateTime<Utc>> {
    for key in ["ts", "timestamp", "@timestamp"] {
        if let Some(v) = raw.get(key) {
            if let Some(f) = v.as_f64() {
                return DateTime::from_timestamp(f as i64, 0);
            }
            if let Some(s) = v.as_str() {
                if let Ok(dt) = s.parse::<DateTime<Utc>>() {
                    return Some(dt);
                }
            }
        }
    }
    None
}

fn map_zeek_log_type(name: &str) -> ZeekLogType {
    match name {
        "conn" => ZeekLogType::Conn,
        "dns" => ZeekLogType::Dns,
        "http" => ZeekLogType::Http,
        "ssl" => ZeekLogType::Ssl,
        "files" => ZeekLogType::Files,
        "weird" => ZeekLogType::Weird,
        "notice" => ZeekLogType::Notice,
        other => ZeekLogType::Other(other.to_string()),
    }
}

/// Returns true when `data` begins with a recognized PCAP or PCAPNG magic header.
pub fn is_valid_pcap_magic(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    matches!(magic, 0xa1b2_c3d4 | 0xd4c3_b2a1 | 0xa1b2_3c4d | 0x4d3c_b2a1)
        || data.starts_with(b"\x0a\x0d\x0d\x0a")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_p0f_line_extracts_fields() {
        let line = "srv|10.0.0.1|1.2.3.4|ether|Linux 3.x";
        let event = parse_p0f_line(line).unwrap();
        assert_eq!(event.source, EventSource::P0f);
        assert_eq!(event.raw["src_ip"], "10.0.0.1");
    }

    #[test]
    fn parse_fatt_json_line() {
        let line = r#"{"ts":"2024-01-01T00:00:00Z","ja3":"abc","src_ip":"10.0.0.5"}"#;
        let event = parse_fatt_line(line).unwrap();
        assert_eq!(event.source, EventSource::Fatt);
        assert_eq!(event.raw["ja3"], "abc");
    }

    #[test]
    fn recognizes_pcap_magic() {
        assert!(is_valid_pcap_magic(&[0xd4, 0xc3, 0xb2, 0xa1, 0x00]));
        assert!(is_valid_pcap_magic(&[0xa1, 0xb2, 0xc3, 0xd4, 0x00]));
        assert!(!is_valid_pcap_magic(b"not a pcap"));
    }
}
