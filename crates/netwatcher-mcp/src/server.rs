use std::collections::HashSet;
use std::sync::Arc;

use netwatcher_indexer::elasticsearch::EsIndexer;

use crate::security::{clamp_limit, SecurityConfig, SecurityError, ToolError};

pub struct McpServer {
    indexer: Arc<EsIndexer>,
    index_prefix: String,
    security: SecurityConfig,
}

impl McpServer {
    pub fn new(indexer: EsIndexer, index_prefix: String, security: SecurityConfig) -> Self {
        Self {
            indexer: Arc::new(indexer),
            index_prefix,
            security,
        }
    }

    pub fn security(&self) -> &SecurityConfig {
        &self.security
    }

    fn index_pattern(&self, source: Option<&str>) -> Result<String, ToolError> {
        match source {
            Some(s) => {
                validate_source(s, &self.security.allowed_sources)?;
                Ok(format!("{}-{}-*", self.index_prefix, s))
            }
            None => Ok(format!("{}-*", self.index_prefix)),
        }
    }

    pub async fn call_tool(&self, name: &str, args: serde_json::Value) -> Result<String, ToolError> {
        match name {
            "search_events" => self.search_events(args).await,
            "threat_summary" => self.threat_summary(args).await,
            "analyze_ip" => self.analyze_ip(args).await,
            "list_sources" => Ok(self.list_sources()),
            other => Err(ToolError::Validation(format!("unknown tool: {other}"))),
        }
    }

    async fn search_events(&self, args: serde_json::Value) -> Result<String, ToolError> {
        let query = args
            .get("query")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::Validation("missing query".into()))?;
        validate_query(query, self.security.max_query_length)?;

        let source = args
            .get("source")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        if let Some(ref source_name) = source {
            validate_source(source_name, &self.security.allowed_sources)?;
        }

        let limit = args
            .get("limit")
            .and_then(|v| v.as_u64())
            .map(|value| clamp_limit(value, self.security.max_results_limit))
            .unwrap_or(20);

        let body = self
            .indexer
            .search(
                &self.index_pattern(source.as_deref())?,
                serde_json::json!({
                    "query_string": { "query": query, "default_field": "*" }
                }),
                limit,
            )
            .await
            .map_err(|_| ToolError::Backend)?;
        serde_json::to_string_pretty(&body).map_err(|_| ToolError::Backend)
    }

    async fn threat_summary(&self, args: serde_json::Value) -> Result<String, ToolError> {
        let hours = args
            .get("hours")
            .and_then(|v| v.as_u64())
            .map(|value| validate_hours(value, self.security.max_hours))
            .transpose()?
            .unwrap_or(24);
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
            .search(
                &self.index_pattern(Some("enriched"))?,
                query.clone(),
                0,
            )
            .await
            .map_err(|_| ToolError::Backend)?;
        let total = body
            .pointer("/hits/total/value")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let samples = self
            .indexer
            .search(&self.index_pattern(Some("enriched"))?, query, 10)
            .await
            .map_err(|_| ToolError::Backend)?;
        serde_json::to_string_pretty(&serde_json::json!({
            "window_hours": hours,
            "threat_matches": total,
            "sample_events": samples.pointer("/hits/hits").cloned().unwrap_or_default()
        }))
        .map_err(|_| ToolError::Backend)
    }

    async fn analyze_ip(&self, args: serde_json::Value) -> Result<String, ToolError> {
        let ip = args
            .get("ip")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::Validation("missing ip".into()))?;
        validate_ip(ip)?;

        let limit = args
            .get("limit")
            .and_then(|v| v.as_u64())
            .map(|value| clamp_limit(value, self.security.max_results_limit))
            .unwrap_or(20);

        let body = self
            .indexer
            .search(
                &self.index_pattern(None)?,
                ip_lookup_query(ip),
                limit,
            )
            .await
            .map_err(|_| ToolError::Backend)?;
        serde_json::to_string_pretty(&body).map_err(|_| ToolError::Backend)
    }

    fn list_sources(&self) -> String {
        let sources: Vec<&str> = self
            .security
            .allowed_sources
            .iter()
            .map(String::as_str)
            .collect();
        serde_json::to_string_pretty(&serde_json::json!({
            "sources": sources,
            "index_prefix": self.index_prefix,
            "threat_feeds": ["emerging_threats_compromised", "emerging_threats_botcc"]
        }))
        .unwrap_or_default()
    }
}

fn ip_lookup_query(ip: &str) -> serde_json::Value {
    let fields = [
        "id.orig_h",
        "id.resp_h",
        "src_ip",
        "dst_ip",
        "threat.indicator",
    ];
    serde_json::json!({
        "bool": {
            "should": fields.iter().map(|field| {
                serde_json::json!({ "term": { *field: ip } })
            }).collect::<Vec<_>>(),
            "minimum_should_match": 1
        }
    })
}

fn validate_source(source: &str, allowed: &HashSet<String>) -> Result<(), ToolError> {
    crate::security::validate_source(source, allowed).map_err(map_security_error)
}

fn validate_query(query: &str, max_len: usize) -> Result<(), ToolError> {
    crate::security::validate_query(query, max_len).map_err(map_security_error)
}

fn validate_ip(ip: &str) -> Result<(), ToolError> {
    crate::security::validate_ip(ip).map_err(map_security_error)
}

fn validate_hours(hours: u64, max: u64) -> Result<u64, ToolError> {
    crate::security::validate_hours(hours, max).map_err(map_security_error)
}

fn map_security_error(err: SecurityError) -> ToolError {
    ToolError::Validation(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_pattern_for_zeek() {
        let security = SecurityConfig::default();
        let allowed = security.allowed_sources.clone();
        validate_source("zeek", &allowed).unwrap();
        let pattern = format!("netwatcher-{}-*", "zeek");
        assert_eq!(pattern, "netwatcher-zeek-*");
    }

    #[test]
    fn ip_lookup_query_uses_term_filters() {
        let query = ip_lookup_query("10.0.0.1");
        let serialized = serde_json::to_string(&query).unwrap();
        assert!(serialized.contains("id.orig_h"));
        assert!(!serialized.contains("query_string"));
    }
}
