mod protocol;
mod security;
mod server;

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use netwatcher_common::ElasticsearchConfig;
use netwatcher_indexer::elasticsearch::{build_client, EsIndexer};
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::protocol::{write_message, JsonRpcRequest, JsonRpcResponse, McpTool};
use crate::security::{
    log_audit, tool_catalog_fingerprint, validate_index_prefix, validate_method,
    validate_request_size, validate_tool_enabled, RateLimiter, SecurityConfig, SecurityError,
};
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

    #[arg(long, env = "MCP_MAX_REQUEST_BYTES", default_value_t = 64 * 1024)]
    max_request_bytes: usize,

    #[arg(long, env = "MCP_MAX_QUERY_LENGTH", default_value_t = 1024)]
    max_query_length: usize,

    #[arg(long, env = "MCP_MAX_RESULTS_LIMIT", default_value_t = 100)]
    max_results_limit: u64,

    #[arg(long, env = "MCP_MAX_HOURS", default_value_t = 168)]
    max_hours: u64,

    #[arg(long, env = "MCP_RATE_LIMIT_PER_MINUTE", default_value_t = 120)]
    rate_limit_per_minute: u32,

    #[arg(long, env = "MCP_ALLOWED_SOURCES", value_delimiter = ',')]
    allowed_sources: Option<Vec<String>>,

    #[arg(long, env = "MCP_ENABLED_TOOLS", value_delimiter = ',')]
    enabled_tools: Option<Vec<String>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    let args = Args::parse();
    validate_index_prefix(&args.elasticsearch_index_prefix)?;

    let mut security = SecurityConfig::from_lists(args.allowed_sources, args.enabled_tools);
    security.max_request_bytes = args.max_request_bytes;
    security.max_query_length = args.max_query_length;
    security.max_results_limit = args.max_results_limit;
    security.max_hours = args.max_hours;
    security.rate_limit_per_minute = args.rate_limit_per_minute;

    let es_config = ElasticsearchConfig {
        url: args.elasticsearch_url,
        index_prefix: args.elasticsearch_index_prefix,
        username: args.elasticsearch_username,
        password: args.elasticsearch_password,
    };

    let client = build_client(&es_config)?;
    let indexer = EsIndexer::new(client, &es_config).await?;
    let server = Arc::new(McpServer::new(indexer, es_config.index_prefix, security));
    let rate_limiter = Arc::new(RateLimiter::new(
        server.security().rate_limit_per_minute,
        Duration::from_secs(60),
    ));

    let tools = McpTool::all(server.security());
    let fingerprint = tool_catalog_fingerprint(
        &serde_json::to_value(&tools).unwrap_or_else(|_| serde_json::json!([])),
    );
    tracing::info!(
        target: "mcp_audit",
        event = "startup",
        tool_catalog_fingerprint = %fingerprint,
        enabled_tools = ?server.security().enabled_tools,
        allowed_sources = ?server.security().allowed_sources,
        "netwatcher-mcp started with security controls"
    );

    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin).lines();
    let mut stdout = tokio::io::stdout();

    while let Some(line) = reader.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }

        let started = std::time::Instant::now();
        let response =
            match process_line(server.clone(), rate_limiter.clone(), &line, &fingerprint).await {
                Ok(response) => response,
                Err(err) => security_error_response(None, &err),
            };
        log_audit(
            "request",
            None,
            None,
            None,
            if response.error.is_some() {
                "error"
            } else {
                "ok"
            },
            Some(started.elapsed().as_millis() as u64),
            None,
        );
        write_message(&mut stdout, &response).await?;
    }

    Ok(())
}

async fn process_line(
    server: Arc<McpServer>,
    rate_limiter: Arc<RateLimiter>,
    line: &str,
    tool_fingerprint: &str,
) -> Result<JsonRpcResponse, SecurityError> {
    validate_request_size(line.len(), server.security().max_request_bytes)?;

    let request: JsonRpcRequest =
        serde_json::from_str(line).map_err(|err| SecurityError::Parse(err.to_string()))?;

    validate_method(&request.method)?;
    rate_limiter.check()?;

    Ok(handle_request(server, request, tool_fingerprint).await)
}

async fn handle_request(
    server: Arc<McpServer>,
    request: JsonRpcRequest,
    tool_fingerprint: &str,
) -> JsonRpcResponse {
    let id = request.id.clone();
    let method = request.method.as_str();
    let started = std::time::Instant::now();

    match method {
        "initialize" => {
            log_audit("initialize", Some(method), None, None, "ok", None, None);
            JsonRpcResponse::success(
                id,
                serde_json::json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": { "tools": {} },
                    "serverInfo": {
                        "name": "netwatcher-mcp",
                        "version": "0.1.0",
                        "toolCatalogFingerprint": tool_fingerprint
                    }
                }),
            )
        }
        "notifications/initialized" => {
            log_audit("initialized", Some(method), None, None, "ok", None, None);
            JsonRpcResponse::empty()
        }
        "tools/list" => {
            let tools = McpTool::all(server.security());
            log_audit("tools_list", Some(method), None, None, "ok", None, None);
            JsonRpcResponse::success(id, serde_json::json!({ "tools": tools }))
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

            if let Err(err) = validate_tool_enabled(name, &server.security().enabled_tools) {
                log_audit(
                    "tool_call",
                    Some(method),
                    Some(name),
                    Some(&args),
                    "denied",
                    Some(started.elapsed().as_millis() as u64),
                    Some(&err.to_string()),
                );
                return JsonRpcResponse::success(
                    id,
                    serde_json::json!({
                        "content": [{ "type": "text", "text": err.to_string() }],
                        "isError": true
                    }),
                );
            }

            match server.call_tool(name, args.clone()).await {
                Ok(text) => {
                    log_audit(
                        "tool_call",
                        Some(method),
                        Some(name),
                        Some(&args),
                        "ok",
                        Some(started.elapsed().as_millis() as u64),
                        None,
                    );
                    JsonRpcResponse::success(
                        id,
                        serde_json::json!({
                            "content": [{ "type": "text", "text": text }],
                            "isError": false
                        }),
                    )
                }
                Err(err) => {
                    log_audit(
                        "tool_call",
                        Some(method),
                        Some(name),
                        Some(&args),
                        "error",
                        Some(started.elapsed().as_millis() as u64),
                        Some(&err.client_message()),
                    );
                    JsonRpcResponse::success(
                        id,
                        serde_json::json!({
                            "content": [{ "type": "text", "text": err.client_message() }],
                            "isError": true
                        }),
                    )
                }
            }
        }
        _ => JsonRpcResponse::error(id, -32601, format!("method not found: {}", request.method)),
    }
}

fn security_error_response(id: Option<serde_json::Value>, err: &SecurityError) -> JsonRpcResponse {
    log_audit(
        "request_denied",
        None,
        None,
        None,
        "denied",
        None,
        Some(&err.to_string()),
    );
    let (code, message) = match err {
        SecurityError::Parse(msg) => (-32700, format!("parse error: {msg}")),
        SecurityError::Validation(msg) => (-32602, msg.clone()),
        SecurityError::RateLimit => (-32000, "rate limit exceeded".into()),
        SecurityError::RequestTooLarge { .. } => (-32600, err.to_string()),
        SecurityError::MethodNotAllowed(method) => {
            (-32601, format!("method not allowed: {method}"))
        }
        SecurityError::ToolDisabled(tool) => (-32602, format!("tool not enabled: {tool}")),
    };
    JsonRpcResponse::error(id, code, message)
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
    fn tools_list_respects_enabled_tools() {
        let mut security = SecurityConfig::default();
        security.enabled_tools.retain(|tool| tool == "list_sources");
        assert_eq!(McpTool::all(&security).len(), 1);
    }

    #[test]
    fn rejects_disallowed_method() {
        assert!(validate_method("resources/list").is_err());
    }
}
