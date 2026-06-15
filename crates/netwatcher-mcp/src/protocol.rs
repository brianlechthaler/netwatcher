use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::AsyncWriteExt;

#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    #[allow(dead_code)]
    pub jsonrpc: String,
    pub id: Option<Value>,
    pub method: String,
    pub params: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
}

impl JsonRpcResponse {
    pub fn success(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: Option<Value>, code: i32, message: String) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(JsonRpcError { code, message }),
        }
    }

    pub fn empty() -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id: None,
            result: None,
            error: None,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct McpTool {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

impl McpTool {
    pub fn all() -> Vec<Self> {
        vec![
            Self {
                name: "search_events".into(),
                description: "Search NetWatcher events in Elasticsearch using Lucene syntax".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string" },
                        "source": { "type": "string" },
                        "limit": { "type": "integer" }
                    },
                    "required": ["query"]
                }),
            },
            Self {
                name: "threat_summary".into(),
                description: "Summarize threat matches from enriched events".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "hours": { "type": "integer", "default": 24 }
                    }
                }),
            },
            Self {
                name: "analyze_ip".into(),
                description: "Analyze traffic and fingerprints for an IP".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "ip": { "type": "string" },
                        "limit": { "type": "integer" }
                    },
                    "required": ["ip"]
                }),
            },
            Self {
                name: "list_sources".into(),
                description: "List NetWatcher data sources and index patterns".into(),
                input_schema: serde_json::json!({ "type": "object", "properties": {} }),
            },
        ]
    }
}

pub async fn write_message(
    writer: &mut (impl tokio::io::AsyncWrite + Unpin),
    response: &JsonRpcResponse,
) -> anyhow::Result<()> {
    let payload = serde_json::to_string(response)?;
    writer.write_all(payload.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_serializes() {
        let resp =
            JsonRpcResponse::success(Some(serde_json::json!(1)), serde_json::json!({"ok": true}));
        let s = serde_json::to_string(&resp).unwrap();
        assert!(s.contains("result"));
    }
}
