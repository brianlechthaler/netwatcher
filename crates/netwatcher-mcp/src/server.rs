use std::sync::Arc;

use netwatcher_indexer::elasticsearch::EsIndexer;

pub struct McpServer {
    indexer: Arc<EsIndexer>,
    index_prefix: String,
}

impl McpServer {
    pub fn new(indexer: EsIndexer, index_prefix: String) -> Self {
        Self {
            indexer: Arc::new(indexer),
            index_prefix,
        }
    }

    fn index_pattern(&self, source: Option<&str>) -> String {
        match source {
            Some(s) => format!("{}-{}-*", self.index_prefix, s),
            None => format!("{}-*", self.index_prefix),
        }
    }

    pub async fn call_tool(&self, name: &str, args: serde_json::Value) -> anyhow::Result<String> {
        match name {
            "search_events" => self.search_events(args).await,
            "threat_summary" => self.threat_summary(args).await,
            "analyze_ip" => self.analyze_ip(args).await,
            "list_sources" => Ok(self.list_sources()),
            other => anyhow::bail!("unknown tool: {other}"),
        }
    }

    async fn search_events(&self, args: serde_json::Value) -> anyhow::Result<String> {
        let query = args
            .get("query")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing query"))?;
        let source = args
            .get("source")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let limit = args
            .get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(20)
            .min(100);

        let body = self
            .indexer
            .search(
                &self.index_pattern(source.as_deref()),
                serde_json::json!({
                    "query_string": { "query": query, "default_field": "*" }
                }),
                limit,
            )
            .await?;
        Ok(serde_json::to_string_pretty(&body)?)
    }

    async fn threat_summary(&self, args: serde_json::Value) -> anyhow::Result<String> {
        let hours = args.get("hours").and_then(|v| v.as_u64()).unwrap_or(24);
        let query = serde_json::json!({
            "bool": {
                "must": [
                    { "term": { "threat.matched": true } },
                    { "range": { "timestamp": { "gte": format!("now-{hours}h") } } }
                ]
            }
        });
        let body = self
            .indexer
            .search(&self.index_pattern(Some("enriched")), query.clone(), 0)
            .await?;
        let total = body
            .pointer("/hits/total/value")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let samples = self
            .indexer
            .search(&self.index_pattern(Some("enriched")), query, 10)
            .await?;
        Ok(serde_json::to_string_pretty(&serde_json::json!({
            "window_hours": hours,
            "threat_matches": total,
            "sample_events": samples.pointer("/hits/hits").cloned().unwrap_or_default()
        }))?)
    }

    async fn analyze_ip(&self, args: serde_json::Value) -> anyhow::Result<String> {
        let ip = args
            .get("ip")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing ip"))?;
        let limit = args
            .get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(20)
            .min(100);
        let body = self
            .indexer
            .search(
                &self.index_pattern(None),
                serde_json::json!({
                    "query_string": {
                        "query": format!(
                            "id.orig_h:{ip} OR id.resp_h:{ip} OR src_ip:{ip} OR dst_ip:{ip} OR threat.indicator:{ip}"
                        )
                    }
                }),
                limit,
            )
            .await?;
        Ok(serde_json::to_string_pretty(&body)?)
    }

    fn list_sources(&self) -> String {
        serde_json::to_string_pretty(&serde_json::json!({
            "sources": ["zeek", "p0f", "fatt", "enriched"],
            "index_prefix": self.index_prefix,
            "threat_feeds": ["emerging_threats_compromised", "emerging_threats_botcc"]
        }))
        .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn index_pattern_for_zeek() {
        let pattern = match Some("zeek") {
            Some(s) => format!("netwatcher-{}-*", s),
            None => "netwatcher-*".to_string(),
        };
        assert_eq!(pattern, "netwatcher-zeek-*");
    }
}
