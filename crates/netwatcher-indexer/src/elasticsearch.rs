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
        let body = json!({
            "index_patterns": [format!("{}-*", self.index_prefix)],
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
                        "raw": { "type": "object", "enabled": true },
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
                        }
                    }
                }
            }
        });

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
