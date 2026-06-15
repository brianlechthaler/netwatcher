use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KafkaConfig {
    pub brokers: String,
    pub topic_prefix: String,
    pub client_id: String,
    #[serde(default = "default_group_id")]
    pub group_id: String,
}

fn default_group_id() -> String {
    "netwatcher".to_string()
}

impl Default for KafkaConfig {
    fn default() -> Self {
        Self {
            brokers: "kafka:9092".to_string(),
            topic_prefix: "netwatcher".to_string(),
            client_id: "netwatcher".to_string(),
            group_id: "netwatcher".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElasticsearchConfig {
    pub url: String,
    pub index_prefix: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

impl Default for ElasticsearchConfig {
    fn default() -> Self {
        Self {
            url: "http://elasticsearch:9200".to_string(),
            index_prefix: "netwatcher".to_string(),
            username: None,
            password: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    pub bind_addr: String,
    pub api_key: Option<String>,
    pub kafka: KafkaConfig,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:8080".to_string(),
            api_key: None,
            kafka: KafkaConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShipperConfig {
    pub gateway_url: String,
    pub agent_id: String,
    pub hostname: String,
    pub api_key: Option<String>,
    pub watch_dirs: Vec<String>,
    pub poll_interval_secs: u64,
}

impl Default for ShipperConfig {
    fn default() -> Self {
        Self {
            gateway_url: "http://gateway:8080".to_string(),
            agent_id: "capture-agent-1".to_string(),
            hostname: std::env::var("HOSTNAME").unwrap_or_else(|_| "capture-agent".to_string()),
            api_key: None,
            watch_dirs: vec![
                "/logs/zeek".to_string(),
                "/logs/p0f".to_string(),
                "/logs/fatt".to_string(),
            ],
            poll_interval_secs: 5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFeedConfig {
    pub et_compromised_url: String,
    pub et_botnet_url: String,
    pub refresh_interval_secs: u64,
}

impl Default for ThreatFeedConfig {
    fn default() -> Self {
        Self {
            et_compromised_url: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
                .to_string(),
            et_botnet_url: "https://rules.emergingthreats.net/blockrules/emerging-botcc.rules"
                .to_string(),
            refresh_interval_secs: 3600,
        }
    }
}

pub fn default_http_timeout() -> Duration {
    Duration::from_secs(30)
}
