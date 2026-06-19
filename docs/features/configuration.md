# Configuration

Environment variables for Docker Compose. Copy `.env.example` to `.env` and edit as needed.

## Gateway

| Variable | Default | Description |
|----------|---------|-------------|
| `GATEWAY_API_KEY` | (empty) | Shared secret for ingest auth |
| `GATEWAY_REQUIRE_API_KEY` | `false` | Reject ingest when key unset |
| `GATEWAY_MAX_BODY_BYTES` | `10485760` | Max JSON body (10 MB) |
| `GATEWAY_MAX_PCAP_BYTES` | `52428800` | Max PCAP upload (50 MB) |
| `GATEWAY_MAX_EVENTS_PER_BATCH` | `500` | Events per JSON batch |
| `GATEWAY_RATE_LIMIT_PER_MINUTE` | `600` | Ingest rate limit |

## Capture agent

| Variable | Default | Description |
|----------|---------|-------------|
| `CAPTURE_INTERFACE` | `auto` | NIC name or auto-detect |
| `GATEWAY_URL` | `http://127.0.0.1:8080` | Gateway base URL |
| `AGENT_ID` | `capture-agent-1` | Agent identifier |
| `GATEWAY_API_KEY` | (empty) | Must match gateway key |
| `PCAP_DIR` | `/pcap` | PCAP output directory |
| `PCAP_ROTATE_SECS` | `30` | Rotation interval |
| `PCAP_ROTATE_COUNT` | `20` | Max PCAP files retained |
| `PCAP_ROTATE_SIZE_MB` | `10` | Size trigger for rotation |

## MCP server

| Variable | Default | Description |
|----------|---------|-------------|
| `ELASTICSEARCH_URL` | `http://elasticsearch:9200` | ES cluster |
| `ELASTICSEARCH_INDEX_PREFIX` | `netwatcher` | Index prefix |
| `MCP_RATE_LIMIT_PER_MINUTE` | `120` | Rate limit |
| `MCP_MAX_REQUEST_BYTES` | `65536` | Max request size |
| `MCP_MAX_QUERY_LENGTH` | `1024` | Max query string |
| `MCP_MAX_RESULTS_LIMIT` | `100` | Max result count |
| `MCP_MAX_HOURS` | `168` | Max threat summary window |
| `MCP_MAX_RESPONSE_BYTES` | `524288` | Max response size |
| `MCP_ENABLED_TOOLS` | (all) | Comma-separated tool list |
| `MCP_ALLOWED_SOURCES` | (all) | Comma-separated sources |

## Internal service defaults

These are set in Compose and usually do not need changes:

| Variable | Default | Service |
|----------|---------|---------|
| `KAFKA_BROKERS` | `kafka:9092` | gateway, enricher, indexer |
| `KAFKA_TOPIC_PREFIX` | `netwatcher` | all Kafka producers/consumers |
| `THREAT_REFRESH_SECS` | `3600` | enricher |

## Related

- [Getting started](../getting-started.md)
- [Security](security.md)
- [Capture agent](capture-agent.md)
