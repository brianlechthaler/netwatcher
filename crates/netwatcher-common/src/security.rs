use std::collections::HashSet;

use subtle::ConstantTimeEq;

use crate::IngestBatch;

/// Compare two secret strings in constant time (same-length only).
pub fn constant_time_eq_str(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Validate agent_id / hostname fields on ingest payloads.
pub fn validate_agent_identifier(value: &str, field: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if value.len() > 128 {
        return Err(format!("{field} exceeds maximum length (128 characters)"));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(format!("{field} contains invalid characters"));
    }
    Ok(())
}

const DEFAULT_MAX_EVENTS_PER_BATCH: usize = 500;
const DEFAULT_MAX_RAW_EVENT_BYTES: usize = 256 * 1024;

/// Validate an ingest batch size and embedded event payloads.
pub fn validate_ingest_batch(
    batch: &IngestBatch,
    max_events: usize,
    max_raw_bytes: usize,
) -> Result<(), String> {
    validate_agent_identifier(&batch.agent_id, "agent_id")?;
    validate_agent_identifier(&batch.hostname, "hostname")?;

    if batch.events.is_empty() {
        return Err("events must not be empty".into());
    }
    if batch.events.len() > max_events {
        return Err(format!("batch exceeds maximum event count ({max_events})"));
    }

    for (index, event) in batch.events.iter().enumerate() {
        let raw_len = serde_json::to_string(&event.raw)
            .map(|s| s.len())
            .unwrap_or(0);
        if raw_len > max_raw_bytes {
            return Err(format!(
                "event {index} raw payload exceeds maximum size ({max_raw_bytes} bytes)"
            ));
        }
    }

    Ok(())
}

pub fn default_max_events_per_batch() -> usize {
    DEFAULT_MAX_EVENTS_PER_BATCH
}

pub fn default_max_raw_event_bytes() -> usize {
    DEFAULT_MAX_RAW_EVENT_BYTES
}

/// Escape Lucene special characters so user input cannot alter query structure.
pub fn escape_lucene_query(query: &str) -> String {
    let mut escaped = String::with_capacity(query.len() * 2);
    for ch in query.chars() {
        if matches!(
            ch,
            '\\' | '+'
                | '-'
                | '!'
                | '('
                | ')'
                | '{'
                | '}'
                | '['
                | ']'
                | '^'
                | '"'
                | '~'
                | '*'
                | '?'
                | ':'
                | '/'
                | '&'
                | '|'
                | '<'
                | '>'
                | '='
        ) {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped
}

/// Reject queries that attempt field-scoped Lucene syntax or script-like payloads.
pub fn reject_lucene_injection_patterns(query: &str) -> Result<(), String> {
    if query.contains(':') {
        return Err("query must not contain field specifiers (':')".into());
    }
    let lower = query.to_ascii_lowercase();
    for token in ["_index", "_id", "_source", "script:", "query("] {
        if lower.contains(token) {
            return Err(format!("query contains disallowed pattern: {token}"));
        }
    }
    Ok(())
}

const DEFAULT_FEED_HOST_SUFFIX: &str = "emergingthreats.net";

/// Validate threat-feed URLs: HTTPS only and host must match the allowlist suffix.
pub fn validate_threat_feed_url(url: &str, allowed_host_suffix: &str) -> Result<(), String> {
    let parsed = url::Url::parse(url).map_err(|_| "invalid feed URL".to_string())?;
    if parsed.scheme() != "https" {
        return Err("feed URL must use HTTPS".into());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "feed URL must include a host".to_string())?;
    if host == allowed_host_suffix || host.ends_with(&format!(".{allowed_host_suffix}")) {
        Ok(())
    } else {
        Err(format!("feed URL host not allowed: {host}"))
    }
}

pub fn default_feed_host_suffix() -> &'static str {
    DEFAULT_FEED_HOST_SUFFIX
}

/// Reject JSON tool arguments that contain keys outside an allowlist.
pub fn reject_unknown_json_keys(args: &serde_json::Value, allowed: &[&str]) -> Result<(), String> {
    let allowed: HashSet<&str> = allowed.iter().copied().collect();
    let Some(map) = args.as_object() else {
        return Err("arguments must be a JSON object".into());
    };
    for key in map.keys() {
        if !allowed.contains(key.as_str()) {
            return Err(format!("unknown argument: {key}"));
        }
    }
    Ok(())
}

/// Truncate a string to a maximum byte length on a UTF-8 boundary.
pub fn truncate_utf8(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… [truncated, total_bytes={}]", &text[..end], text.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EventSource, IngestEvent};
    use chrono::Utc;

    #[test]
    fn constant_time_eq_matches_equal_strings() {
        assert!(constant_time_eq_str("secret-key", "secret-key"));
        assert!(!constant_time_eq_str("secret-key", "other-key"));
        assert!(!constant_time_eq_str("short", "longer-value"));
    }

    #[test]
    fn rejects_invalid_agent_id() {
        assert!(validate_agent_identifier("", "agent_id").is_err());
        assert!(validate_agent_identifier("agent/../etc", "agent_id").is_err());
    }

    #[test]
    fn rejects_oversized_batch() {
        let batch = IngestBatch {
            agent_id: "agent-1".into(),
            hostname: "host-1".into(),
            events: vec![
                IngestEvent {
                    source: EventSource::Zeek,
                    zeek_log_type: None,
                    timestamp: Utc::now(),
                    raw: serde_json::json!({"x": 1}),
                };
                3
            ],
        };
        assert!(validate_ingest_batch(&batch, 2, 1024).is_err());
    }

    #[test]
    fn escapes_lucene_special_chars() {
        let escaped = escape_lucene_query(r#"foo:bar AND (x OR y)"#);
        assert!(escaped.contains(r"foo\:bar"));
        assert!(escaped.contains(r"\("));
    }

    #[test]
    fn rejects_field_specifiers_in_query() {
        assert!(reject_lucene_injection_patterns("_index:secret").is_err());
        assert!(reject_lucene_injection_patterns("10.0.0.1").is_ok());
    }

    #[test]
    fn accepts_default_threat_feed_urls() {
        assert!(validate_threat_feed_url(
            "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            DEFAULT_FEED_HOST_SUFFIX
        )
        .is_ok());
        assert!(
            validate_threat_feed_url("http://evil.example/feed", DEFAULT_FEED_HOST_SUFFIX).is_err()
        );
    }

    #[test]
    fn rejects_unknown_tool_args() {
        let args = serde_json::json!({"query": "x", "extra": true});
        assert!(reject_unknown_json_keys(&args, &["query", "source", "limit"]).is_err());
    }
}
