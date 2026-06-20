use std::sync::Arc;

use netwatcher_common::{extract_bzar_attack, NetworkEvent, ThreatEnrichment, ThreatStore};
use tokio::sync::RwLock;

pub struct EventEnricher {
    store: Arc<RwLock<ThreatStore>>,
}

impl EventEnricher {
    pub fn new(store: Arc<RwLock<ThreatStore>>) -> Self {
        Self { store }
    }

    pub async fn enrich(&self, event: &mut NetworkEvent) {
        if let Some(attack) = extract_bzar_attack(&event.raw, event.zeek_log_type.as_ref()) {
            if let Some(tid) = &attack.technique_id {
                event.tags.push(tid.clone());
            }
            event.tags.push("attack_match".to_string());
            event.tags.push("bzar".to_string());
            event.tags.push(attack.tactic.clone());
            event.attack = Some(attack);
        }

        let ips = extract_ips(&event.raw);
        let store = self.store.read().await;
        for ip in ips {
            if let Some(indicator) = store.lookup_ip(&ip) {
                event.threat = Some(ThreatEnrichment {
                    matched: true,
                    severity: indicator.severity,
                    categories: indicator.categories.clone(),
                    description: indicator.description.clone(),
                    feed: indicator.feed.clone(),
                    rule_id: indicator.rule_id.clone(),
                    indicator: Some(indicator.indicator.clone()),
                });
                event.tags.push("threat_match".to_string());
                event.tags.extend(indicator.categories.clone());
                break;
            }
        }
    }
}

fn extract_ips(raw: &serde_json::Value) -> Vec<String> {
    let mut ips = Vec::new();
    for key in [
        "id.orig_h",
        "id.resp_h",
        "src_ip",
        "dst_ip",
        "client_ip",
        "server_ip",
        "ip",
    ] {
        if let Some(v) = raw.get(key).or_else(|| raw.pointer(&format!("/{key}"))) {
            if let Some(s) = v.as_str() {
                if looks_like_ip(s) {
                    ips.push(s.to_string());
                }
            }
        }
    }
    if let Some(obj) = raw.as_object() {
        for (k, v) in obj {
            if k.contains("ip") || k.ends_with("_h") {
                if let Some(s) = v.as_str() {
                    if looks_like_ip(s) {
                        ips.push(s.to_string());
                    }
                }
            }
        }
    }
    ips.sort();
    ips.dedup();
    ips
}

fn looks_like_ip(s: &str) -> bool {
    s.split('.').count() == 4 && s.chars().all(|c| c.is_ascii_digit() || c == '.')
}

#[cfg(test)]
mod tests {
    use super::*;
    use netwatcher_common::{IndicatorType, ThreatIndicator, ThreatSeverity};

    #[tokio::test]
    async fn enriches_matching_ip() {
        let store = Arc::new(RwLock::new(ThreatStore::new()));
        store.write().await.upsert(ThreatIndicator {
            indicator: "1.2.3.4".to_string(),
            indicator_type: IndicatorType::Ip,
            categories: vec!["botnet".to_string()],
            severity: ThreatSeverity::Critical,
            description: "test".to_string(),
            feed: "test".to_string(),
            rule_id: None,
        });
        let enricher = EventEnricher::new(store);
        let mut event = NetworkEvent::from_ingest(
            "a1",
            "host",
            netwatcher_common::IngestEvent {
                source: netwatcher_common::EventSource::Zeek,
                zeek_log_type: None,
                timestamp: chrono::Utc::now(),
                raw: serde_json::json!({"id.orig_h": "1.2.3.4"}),
            },
        );
        enricher.enrich(&mut event).await;
        assert!(event.threat.as_ref().unwrap().matched);
        assert!(event.tags.contains(&"threat_match".to_string()));
    }

    #[tokio::test]
    async fn enriches_bzar_attack_notice() {
        let store = Arc::new(RwLock::new(ThreatStore::new()));
        let enricher = EventEnricher::new(store);
        let mut event = NetworkEvent::from_ingest(
            "a1",
            "host",
            netwatcher_common::IngestEvent {
                source: netwatcher_common::EventSource::Zeek,
                zeek_log_type: Some(netwatcher_common::ZeekLogType::Notice),
                timestamp: chrono::Utc::now(),
                raw: serde_json::json!({
                    "note": "ATTACK::Execution",
                    "msg": "Detected service execution",
                    "sub": "T1569.002 System Services: Service Execution",
                    "id.orig_h": "10.0.0.2",
                    "id.resp_h": "10.0.0.5"
                }),
            },
        );
        enricher.enrich(&mut event).await;
        let attack = event.attack.as_ref().unwrap();
        assert!(attack.matched);
        assert_eq!(attack.technique_id.as_deref(), Some("T1569.002"));
        assert!(event.tags.contains(&"attack_match".to_string()));
        assert!(event.tags.contains(&"T1569.002".to_string()));
    }

    #[tokio::test]
    async fn no_match_leaves_event_clean() {
        let store = Arc::new(RwLock::new(ThreatStore::new()));
        let enricher = EventEnricher::new(store);
        let mut event = NetworkEvent::from_ingest(
            "a1",
            "host",
            netwatcher_common::IngestEvent {
                source: netwatcher_common::EventSource::Zeek,
                zeek_log_type: None,
                timestamp: chrono::Utc::now(),
                raw: serde_json::json!({"id.orig_h": "10.0.0.1"}),
            },
        );
        enricher.enrich(&mut event).await;
        assert!(event.threat.is_none());
        assert!(event.tags.is_empty());
    }

    #[tokio::test]
    async fn enriches_from_resp_ip_field() {
        let store = Arc::new(RwLock::new(ThreatStore::new()));
        store.write().await.upsert(ThreatIndicator {
            indicator: "5.6.7.8".to_string(),
            indicator_type: IndicatorType::Ip,
            categories: vec!["c2".to_string()],
            severity: ThreatSeverity::High,
            description: "c2".to_string(),
            feed: "test".to_string(),
            rule_id: Some("99".to_string()),
        });
        let enricher = EventEnricher::new(store);
        let mut event = NetworkEvent::from_ingest(
            "a1",
            "host",
            netwatcher_common::IngestEvent {
                source: netwatcher_common::EventSource::P0f,
                zeek_log_type: None,
                timestamp: chrono::Utc::now(),
                raw: serde_json::json!({"dst_ip": "5.6.7.8"}),
            },
        );
        enricher.enrich(&mut event).await;
        assert_eq!(
            event.threat.as_ref().unwrap().indicator.as_deref(),
            Some("5.6.7.8")
        );
    }
}
