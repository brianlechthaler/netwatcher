# Security

NetWatcher applies layered controls on the gateway ingest path and the MCP query surface.

## Gateway

| Control | Configuration |
|---------|---------------|
| API key auth | `GATEWAY_API_KEY` on gateway and capture agents; `X-API-Key` header |
| Require auth in production | `GATEWAY_REQUIRE_API_KEY=true` rejects unauthenticated ingest |
| Constant-time key compare | Built into gateway authorization |
| Request size limits | `GATEWAY_MAX_BODY_BYTES`, `GATEWAY_MAX_PCAP_BYTES`, per-event payload caps |
| Batch limits | `GATEWAY_MAX_EVENTS_PER_BATCH` |
| Rate limiting | `GATEWAY_RATE_LIMIT_PER_MINUTE` (default 600) |
| Localhost binding | Compose publishes Kafka, ES, Kibana, gateway on `127.0.0.1` only |

## MCP server

| Control | Description |
|---------|-------------|
| Input screening | Validates queries, IPs, sources, request size; rejects control characters, Unicode direction overrides, Lucene field-specifier injection |
| Least privilege | `MCP_ENABLED_TOOLS` and `MCP_ALLOWED_SOURCES` limit exposed surface |
| Rate limiting | `MCP_RATE_LIMIT_PER_MINUTE` (default 120) |
| Response caps | `MCP_MAX_RESPONSE_BYTES` (default 512 KiB) truncates oversized output |
| Strict tool args | Unknown JSON keys rejected |
| Audit logging | Structured `mcp_audit` events on stderr for every method and tool call |
| Tool catalog fingerprint | Returned at `initialize` as `toolCatalogFingerprint` |
| Container isolation | Read-only root, `cap_drop: ALL`, `no-new-privileges`, resource limits |

### MCP environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `MCP_RATE_LIMIT_PER_MINUTE` | 120 | Requests per minute |
| `MCP_MAX_REQUEST_BYTES` | 65536 | Max stdin message size |
| `MCP_MAX_QUERY_LENGTH` | 1024 | Max Lucene query length |
| `MCP_MAX_RESULTS_LIMIT` | 100 | Max `limit` parameter |
| `MCP_MAX_HOURS` | 168 | Max lookback for threat summary |
| `MCP_MAX_RESPONSE_BYTES` | 524288 | Max tool response size |
| `MCP_ENABLED_TOOLS` | all four tools | Comma-separated allow list |
| `MCP_ALLOWED_SOURCES` | zeek,p0f,fatt,enriched | Comma-separated source filter |

## Production checklist

1. Set `GATEWAY_API_KEY` on gateway and all capture agents
2. Set `GATEWAY_REQUIRE_API_KEY=true`
3. Restrict network access to Kafka, Elasticsearch, and Kibana (Compose defaults to localhost)
4. Review MCP tool allow lists before exposing to untrusted agents
5. Monitor `mcp_audit` stderr output from the MCP container

## Related

- [Gateway](gateway.md)
- [MCP server](mcp-server.md)
- [Configuration](configuration.md)
