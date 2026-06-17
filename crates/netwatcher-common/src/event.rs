use serde::{Deserialize, Serialize};

/// Source of a network observation event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    Zeek,
    P0f,
    Fatt,
    Enriched,
}

impl EventSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Zeek => "zeek",
            Self::P0f => "p0f",
            Self::Fatt => "fatt",
            Self::Enriched => "enriched",
        }
    }

    pub fn kafka_topic(&self, prefix: &str) -> String {
        format!("{}.{}", prefix, self.as_str())
    }

    pub fn elasticsearch_index(&self, prefix: &str) -> String {
        format!("{}-{}", prefix, self.as_str())
    }
}

/// Zeek log sub-types for routing within the zeek topic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZeekLogType {
    Conn,
    Dns,
    Http,
    Ssl,
    Files,
    Weird,
    Notice,
    Other(String),
}

impl ZeekLogType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Conn => "conn",
            Self::Dns => "dns",
            Self::Http => "http",
            Self::Ssl => "ssl",
            Self::Files => "files",
            Self::Weird => "weird",
            Self::Notice => "notice",
            Self::Other(name) => name.as_str(),
        }
    }

    /// Map a Zeek log file stem (e.g. `conn` or rotated `conn.2026-06-17-02-37-41`) to a type.
    pub fn from_log_stem(stem: &str) -> Self {
        Self::from_name(normalize_zeek_log_stem(stem))
    }

    fn from_name(name: &str) -> Self {
        match name {
            "conn" => Self::Conn,
            "dns" => Self::Dns,
            "http" => Self::Http,
            "ssl" => Self::Ssl,
            "files" => Self::Files,
            "weird" => Self::Weird,
            "notice" => Self::Notice,
            other => Self::Other(other.to_string()),
        }
    }
}

impl Serialize for ZeekLogType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ZeekLogType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(Self::from_name(&value))
    }
}

/// Strip Zeek log-rotation timestamp suffixes from a file stem.
fn normalize_zeek_log_stem(stem: &str) -> &str {
    let Some((base, suffix)) = stem.split_once('.') else {
        return stem;
    };
    if is_zeek_rotation_timestamp(suffix) {
        base
    } else {
        stem
    }
}

fn is_zeek_rotation_timestamp(suffix: &str) -> bool {
    let mut parts = suffix.split('-');
    matches!(
        (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ),
        (Some(y), Some(mo), Some(d), Some(h), Some(mi), Some(s), None)
            if y.len() == 4
                && [mo, d, h, mi, s].iter().all(|p| p.len() == 2)
                && suffix.chars().all(|c| c.is_ascii_digit() || c == '-')
    )
}

/// A normalized event envelope used across gateway, Kafka, and Elasticsearch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub source: EventSource,
    pub agent_id: String,
    pub hostname: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zeek_log_type: Option<ZeekLogType>,
    pub raw: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat: Option<ThreatEnrichment>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

/// Threat intelligence enrichment from Emerging Threats and related feeds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEnrichment {
    pub matched: bool,
    pub severity: ThreatSeverity,
    pub categories: Vec<String>,
    pub description: String,
    pub feed: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub indicator: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Batch ingest payload from capture agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestBatch {
    pub agent_id: String,
    pub hostname: String,
    pub events: Vec<IngestEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestEvent {
    pub source: EventSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zeek_log_type: Option<ZeekLogType>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub raw: serde_json::Value,
}

impl NetworkEvent {
    pub fn from_ingest(agent_id: &str, hostname: &str, event: IngestEvent) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: event.timestamp,
            source: event.source,
            agent_id: agent_id.to_string(),
            hostname: hostname.to_string(),
            zeek_log_type: event.zeek_log_type,
            raw: event.raw,
            threat: None,
            tags: Vec::new(),
        }
    }

    pub fn elasticsearch_document(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_else(|_| serde_json::json!({}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn event_source_topic_and_index_names() {
        assert_eq!(EventSource::Zeek.as_str(), "zeek");
        assert_eq!(
            EventSource::Zeek.kafka_topic("netwatcher"),
            "netwatcher.zeek"
        );
        assert_eq!(
            EventSource::P0f.elasticsearch_index("netwatcher"),
            "netwatcher-p0f"
        );
    }

    #[test]
    fn network_event_from_ingest_sets_fields() {
        let event = NetworkEvent::from_ingest(
            "agent-1",
            "host-a",
            IngestEvent {
                source: EventSource::Fatt,
                zeek_log_type: None,
                timestamp: Utc::now(),
                raw: serde_json::json!({"ja3": "abc"}),
            },
        );
        assert_eq!(event.agent_id, "agent-1");
        assert_eq!(event.hostname, "host-a");
        assert_eq!(event.source, EventSource::Fatt);
        assert!(event.threat.is_none());
    }

    #[test]
    fn elasticsearch_document_serializes() {
        let event = NetworkEvent::from_ingest(
            "a",
            "h",
            IngestEvent {
                source: EventSource::Zeek,
                zeek_log_type: Some(ZeekLogType::Conn),
                timestamp: Utc::now(),
                raw: serde_json::json!({"id.orig_h": "10.0.0.1"}),
            },
        );
        let doc = event.elasticsearch_document();
        assert_eq!(doc["source"], "zeek");
        assert_eq!(doc["zeek_log_type"], "conn");
    }

    #[test]
    fn zeek_log_type_roundtrip() {
        let value = serde_json::to_value(ZeekLogType::Other("custom".into())).unwrap();
        assert_eq!(value, "custom");
        let parsed: ZeekLogType = serde_json::from_value(value).unwrap();
        assert_eq!(parsed, ZeekLogType::Other("custom".into()));
    }

    #[test]
    fn zeek_log_type_from_rotated_stem() {
        assert_eq!(
            ZeekLogType::from_log_stem("conn.2026-06-17-02-37-41"),
            ZeekLogType::Conn
        );
        assert_eq!(
            ZeekLogType::from_log_stem("dns.2026-06-17-02-37-31"),
            ZeekLogType::Dns
        );
    }
}
