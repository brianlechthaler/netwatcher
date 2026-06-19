use anyhow::Context;
use elasticsearch::{
    auth::Credentials,
    http::transport::{SingleNodeConnectionPool, TransportBuilder},
    indices::IndicesPutIndexTemplateParts,
    Elasticsearch,
};
use netwatcher_common::{ElasticsearchConfig, NetworkEvent};
use serde_json::json;
use tracing::info;

pub struct EsIndexer {
    client: Elasticsearch,
    index_prefix: String,
}

impl EsIndexer {
    pub async fn new(client: Elasticsearch, config: &ElasticsearchConfig) -> anyhow::Result<Self> {
        let indexer = Self {
            client,
            index_prefix: config.index_prefix.clone(),
        };
        indexer.ensure_index_template().await?;
        Ok(indexer)
    }

    async fn ensure_index_template(&self) -> anyhow::Result<()> {
        let template_name = format!("{}-template", self.index_prefix);
        let body = index_template_body(&self.index_prefix);

        let response = self
            .client
            .indices()
            .put_index_template(IndicesPutIndexTemplateParts::Name(&template_name))
            .body(body)
            .send()
            .await
            .context("put index template")?;

        if response.status_code().is_success() || response.status_code().as_u16() == 400 {
            info!(template = %template_name, "index template ready");
        } else {
            let status = response.status_code();
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("failed to create index template: {status} {text}");
        }
        Ok(())
    }

    pub async fn index_event(&self, event: &NetworkEvent) -> anyhow::Result<()> {
        let index = format!(
            "{}-{}-{}",
            self.index_prefix,
            event.source.as_str(),
            event.timestamp.format("%Y.%m.%d")
        );
        let response = self
            .client
            .index(elasticsearch::IndexParts::IndexId(&index, &event.id))
            .body(event.elasticsearch_document())
            .send()
            .await
            .context("index document")?;

        if !response.status_code().is_success() {
            let status = response.status_code();
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("elasticsearch index error: {status} {text}");
        }
        Ok(())
    }

    pub async fn search(
        &self,
        index_pattern: &str,
        query: serde_json::Value,
        size: u64,
    ) -> anyhow::Result<serde_json::Value> {
        let response = self
            .client
            .search(elasticsearch::SearchParts::Index(&[index_pattern]))
            .body(json!({
                "size": size,
                "query": query,
                "sort": [{ "timestamp": "desc" }]
            }))
            .send()
            .await
            .context("search")?;

        let body: serde_json::Value = response.json().await.context("parse search response")?;
        Ok(body)
    }
}

pub fn build_client(config: &ElasticsearchConfig) -> anyhow::Result<Elasticsearch> {
    let url = url::Url::parse(&config.url).context("parse elasticsearch url")?;
    let pool = SingleNodeConnectionPool::new(url);
    let mut builder = TransportBuilder::new(pool);

    if let (Some(user), Some(pass)) = (&config.username, &config.password) {
        builder = builder.auth(Credentials::Basic(user.clone(), pass.clone()));
    }

    let transport = builder.build().context("build elasticsearch transport")?;
    Ok(Elasticsearch::new(transport))
}

fn keyword_field() -> serde_json::Value {
    json!({ "type": "keyword" })
}

fn index_template_body(index_prefix: &str) -> serde_json::Value {
    let raw_fields = [
        "id.orig_h",
        "id.resp_h",
        "proto",
        "service",
        "conn_state",
        "query",
        "qtype_name",
        "rcode_name",
        "host",
        "method",
        "uri",
        "user_agent",
        "src_ip",
        "dst_ip",
        "detail",
        "link",
        "mod",
        "ja3",
        "ja3s",
        "protocol",
        "sourceIp",
        "destinationIp",
        "sourcePort",
        "destinationPort",
        "qclass_name",
        "server_name",
        "cipher",
        "version",
        "history",
        "status_msg",
        "referrer",
        "note",
        "sub",
        "msg",
    ];
    let mut raw_properties = serde_json::Map::new();
    for field in raw_fields {
        raw_properties.insert(field.to_string(), keyword_field());
    }
    raw_properties.insert("id.orig_p".to_string(), json!({ "type": "integer" }));
    raw_properties.insert("id.resp_p".to_string(), json!({ "type": "integer" }));
    raw_properties.insert("orig_bytes".to_string(), json!({ "type": "long" }));
    raw_properties.insert("resp_bytes".to_string(), json!({ "type": "long" }));
    raw_properties.insert("orig_ip_bytes".to_string(), json!({ "type": "long" }));
    raw_properties.insert("resp_ip_bytes".to_string(), json!({ "type": "long" }));
    raw_properties.insert("orig_pkts".to_string(), json!({ "type": "long" }));
    raw_properties.insert("resp_pkts".to_string(), json!({ "type": "long" }));
    raw_properties.insert("request_body_len".to_string(), json!({ "type": "long" }));
    raw_properties.insert("response_body_len".to_string(), json!({ "type": "long" }));
    raw_properties.insert("status_code".to_string(), json!({ "type": "integer" }));
    raw_properties.insert("established".to_string(), json!({ "type": "boolean" }));
    raw_properties.insert("rejected".to_string(), json!({ "type": "boolean" }));
    raw_properties.insert(
        "tls".to_string(),
        json!({
            "properties": {
                "ja3": keyword_field(),
                "ja3s": keyword_field(),
                "ja3Algorithms": keyword_field(),
                "ja3sAlgorithms": keyword_field()
            }
        }),
    );
    raw_properties.insert(
        "ssh".to_string(),
        json!({
            "properties": {
                "hassh": keyword_field(),
                "client": keyword_field(),
                "server": keyword_field()
            }
        }),
    );
    raw_properties.insert(
        "http".to_string(),
        json!({
            "properties": {
                "userAgent": keyword_field(),
                "requestMethod": keyword_field(),
                "requestURI": keyword_field(),
                "clientHeaderHash": keyword_field(),
                "clientHeaderOrder": keyword_field(),
                "serverHeaderHash": keyword_field()
            }
        }),
    );

    json!({
        "index_patterns": [format!("{}-*", index_prefix)],
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0
            },
            "mappings": {
                "properties": {
                    "id": { "type": "keyword" },
                    "timestamp": { "type": "date" },
                    "source": { "type": "keyword" },
                    "agent_id": { "type": "keyword" },
                    "hostname": { "type": "keyword" },
                    "zeek_log_type": { "type": "keyword" },
                    "tags": { "type": "keyword" },
                    "raw": {
                        "type": "object",
                        "properties": raw_properties
                    },
                    "threat": {
                        "properties": {
                            "matched": { "type": "boolean" },
                            "severity": { "type": "keyword" },
                            "categories": { "type": "keyword" },
                            "description": { "type": "text" },
                            "feed": { "type": "keyword" },
                            "rule_id": { "type": "keyword" },
                            "indicator": { "type": "keyword" }
                        }
                    },
                    "attack": {
                        "properties": {
                            "matched": { "type": "boolean" },
                            "tactic": { "type": "keyword" },
                            "tactic_id": { "type": "keyword" },
                            "technique_id": { "type": "keyword" },
                            "technique": { "type": "text" },
                            "notice_type": { "type": "keyword" },
                            "description": { "type": "text" },
                            "source": { "type": "keyword" }
                        }
                    }
                }
            }
        }
    })
}
