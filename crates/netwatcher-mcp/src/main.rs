mod protocol;
mod server;

use std::sync::Arc;

use clap::Parser;
use netwatcher_common::ElasticsearchConfig;
use netwatcher_indexer::elasticsearch::{build_client, EsIndexer};
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::protocol::{write_message, JsonRpcRequest, JsonRpcResponse, McpTool};
use crate::server::McpServer;

#[derive(Parser, Debug)]
#[command(name = "netwatcher-mcp", about = "MCP server for NetWatcher data")]
struct Args {
    #[arg(
        long,
        env = "ELASTICSEARCH_URL",
        default_value = "http://elasticsearch:9200"
    )]
    elasticsearch_url: String,

    #[arg(long, env = "ELASTICSEARCH_INDEX_PREFIX", default_value = "netwatcher")]
    elasticsearch_index_prefix: String,

    #[arg(long, env = "ELASTICSEARCH_USERNAME")]
    elasticsearch_username: Option<String>,

    #[arg(long, env = "ELASTICSEARCH_PASSWORD")]
    elasticsearch_password: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    let args = Args::parse();
    let es_config = ElasticsearchConfig {
        url: args.elasticsearch_url,
        index_prefix: args.elasticsearch_index_prefix,
        username: args.elasticsearch_username,
        password: args.elasticsearch_password,
    };

    let client = build_client(&es_config)?;
    let indexer = EsIndexer::new(client, &es_config).await?;
    let server = Arc::new(McpServer::new(indexer, es_config.index_prefix));

    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin).lines();
    let mut stdout = tokio::io::stdout();

    while let Some(line) = reader.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let request: JsonRpcRequest = match serde_json::from_str(&line) {
            Ok(req) => req,
            Err(err) => {
                let response = JsonRpcResponse::error(None, -32700, err.to_string());
                write_message(&mut stdout, &response).await?;
                continue;
            }
        };

        let response = handle_request(server.clone(), request).await;
        write_message(&mut stdout, &response).await?;
    }

    Ok(())
}

async fn handle_request(server: Arc<McpServer>, request: JsonRpcRequest) -> JsonRpcResponse {
    let id = request.id.clone();
    match request.method.as_str() {
        "initialize" => JsonRpcResponse::success(
            id,
            serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "netwatcher-mcp", "version": "0.1.0" }
            }),
        ),
        "notifications/initialized" => JsonRpcResponse::empty(),
        "tools/list" => {
            JsonRpcResponse::success(id, serde_json::json!({ "tools": McpTool::all() }))
        }
        "tools/call" => {
            let name = request
                .params
                .as_ref()
                .and_then(|p| p.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let args = request
                .params
                .as_ref()
                .and_then(|p| p.get("arguments"))
                .cloned()
                .unwrap_or_else(|| serde_json::json!({}));

            match server.call_tool(name, args).await {
                Ok(text) => JsonRpcResponse::success(
                    id,
                    serde_json::json!({
                        "content": [{ "type": "text", "text": text }],
                        "isError": false
                    }),
                ),
                Err(err) => JsonRpcResponse::success(
                    id,
                    serde_json::json!({
                        "content": [{ "type": "text", "text": err.to_string() }],
                        "isError": true
                    }),
                ),
            }
        }
        _ => JsonRpcResponse::error(id, -32601, format!("method not found: {}", request.method)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_json_rpc_request() {
        let req: JsonRpcRequest =
            serde_json::from_str(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#).unwrap();
        assert_eq!(req.method, "tools/list");
    }

    #[test]
    fn tools_list_has_four_tools() {
        assert_eq!(McpTool::all().len(), 4);
    }
}
