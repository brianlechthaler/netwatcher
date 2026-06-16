# NetWatcher

Modular network traffic monitoring system. Capture agents run Zeek and lightweight PCAP capture; the gateway analyzes PCAPs with p0f and fatt, then ships events through Kafka, enriches with Emerging Threats intelligence, indexes to Elasticsearch, and provides Kibana dashboards plus an MCP server for AI-assisted analysis.

## Architecture

```
[Capture Agent]  Zeek logs ──HTTP JSON──┐
  tcpdump PCAP ──HTTP multipart─────────┼──> [Gateway + p0f/fatt] --> [Kafka]
                                        |
                              [Enricher (ET feeds)]
                                        |
                                   [Kafka enriched]
                                        |
                                   [Indexer] --> [Elasticsearch] --> [Kibana]
                                                                --> [MCP Server]
```

### Components

| Component | Role |
|-----------|------|
| **capture-agent** | Zeek + tcpdump PCAP capture + shipper (lightweight; runs on any host) |
| **gateway** | HTTP ingest API, p0f/fatt PCAP analysis, publishes to Kafka |
| **enricher** | Emerging Threats IP reputation enrichment |
| **indexer** | Kafka consumer → Elasticsearch |
| **mcp** | Stdio MCP server for AI agent queries |
| **kibana** | Human analyst dashboards |

### Extension points

- **New analyzers**: Add a supervisor program in `docker/capture/scripts/`, write logs to `/logs/<source>/`, extend `netwatcher-shipper` parser
- **New event sources**: Add variant to `EventSource` in `netwatcher-common`, Kafka topic auto-created by gateway
- **New threat feeds**: Implement parser in `netwatcher-common/src/threat.rs`, register in enricher `feed.rs`
- **New MCP tools**: Add handler in `crates/netwatcher-mcp/src/server.rs` and register in `protocol.rs`

## Quick start (Docker Compose)

```bash
# Start core pipeline (Kafka, ES, Kibana, gateway, enricher, indexer)
make up

# Optional: start local capture agent (requires CAP_NET_RAW, host network)
make up-capture
```

The capture agent auto-selects the default-route network interface. To capture on a specific NIC instead:

```bash
# One-shot override
CAPTURE_INTERFACE=enp4s0 make up-capture

# Or set in .env (copy from .env.example) and restart
echo 'CAPTURE_INTERFACE=wlo1' >> .env
make up-capture
```

List interfaces on the host with `ip -br link show`.

Services:

- Gateway: http://localhost:8080
- Kibana: http://localhost:5601
- Elasticsearch: http://localhost:9200

### CAP_NET_RAW for local capture

Zeek and tcpdump need raw packet capture on a network interface. That requires `CAP_NET_RAW` (and `CAP_NET_ADMIN` to bind to the interface). p0f and fatt analysis runs on the gateway after PCAP upload — agents no longer run those tools locally.

**Docker Compose (recommended)** — `make up-capture` grants the needed capabilities automatically via `cap_add` in `deploy/docker-compose/compose.yaml`:

```yaml
cap_add:
  - NET_ADMIN   # CAP_NET_ADMIN
  - NET_RAW     # CAP_NET_RAW
```

No manual `setcap` is required on a normal rootful Docker install. Confirm the running container has them:

```bash
docker inspect netwatcher-capture-agent --format '{{.HostConfig.CapAdd}}'
# Expected: [NET_ADMIN NET_RAW]

# Or run the helper script:
./scripts/verify-capture-caps.sh
```

**Capture binaries on the host (without Docker)** — grant file capabilities on Zeek and tcpdump:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip /usr/local/zeek/bin/zeek
sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/tcpdump
```

Verify:

```bash
getcap /usr/local/zeek/bin/zeek
# /usr/local/zeek/bin/zeek cap_net_admin,cap_net_raw=eip
```

To remove capabilities later: `sudo setcap -r /path/to/binary`.

**Troubleshooting**

- Rootless Docker often cannot add `NET_RAW`; use rootful Docker or run capture on the host with `setcap` as above.
- If capture fails with permission errors inside the container, ensure you are not overriding `cap_add` (for example with `--cap-drop=all`).
- Pick an interface that carries traffic; the default `eth0` may not exist on all hosts.

## Remote capture agent

On a remote machine that can reach the central gateway:

```bash
export GATEWAY_URL=http://<gateway-host>:8080
export AGENT_ID=edge-sensor-01
# Optional: defaults to auto-detect; set explicitly if needed
export CAPTURE_INTERFACE=enp4s0
docker compose -f deploy/docker-compose/compose.capture.yaml up -d
```

## Kubernetes

```bash
make k8s-apply
```

Capture agents deploy as a `DaemonSet` with host networking. Update image references in `deploy/kubernetes/` after CI publishes to GHCR.

## MCP integration (Cursor)

Copy or merge `mcp/mcp.json` into your Cursor MCP config:

```json
{
  "mcpServers": {
    "netwatcher": {
      "command": "netwatcher-mcp",
      "env": {
        "ELASTICSEARCH_URL": "http://localhost:9200",
        "ELASTICSEARCH_INDEX_PREFIX": "netwatcher"
      }
    }
  }
}
```

Tools: `search_events`, `threat_summary`, `analyze_ip`, `list_sources`

### MCP security controls

The MCP server follows [NSA MCP security design considerations](https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf) with defense-in-depth controls:

- **Input screening**: Validates queries, IPs, sources, and request size before Elasticsearch access; rejects control characters, Unicode direction overrides, and Lucene field-specifier injection patterns.
- **Least privilege**: Enable only required tools and sources via `MCP_ENABLED_TOOLS` and `MCP_ALLOWED_SOURCES` (comma-separated).
- **Rate limiting**: `MCP_RATE_LIMIT_PER_MINUTE` (default 120) mitigates overload/DoS against the stdio server.
- **Response caps**: `MCP_MAX_RESPONSE_BYTES` (default 512 KiB) truncates oversized tool output before returning to the agent.
- **Strict tool args**: Unknown JSON keys in tool arguments are rejected at runtime.
- **Audit logging**: Structured `mcp_audit` events on stderr for every method and tool call (tool name, redacted args, outcome, duration).
- **Tool catalog fingerprint**: Returned at `initialize` as `toolCatalogFingerprint` to detect tool-definition drift.
- **Container isolation**: The `mcp` Compose service runs read-only with `cap_drop: ALL`, `no-new-privileges`, and memory/CPU limits.

Optional environment variables: `MCP_MAX_REQUEST_BYTES`, `MCP_MAX_QUERY_LENGTH`, `MCP_MAX_RESULTS_LIMIT`, `MCP_MAX_HOURS`, `MCP_MAX_RESPONSE_BYTES`.

### Gateway security controls

- **API key authentication**: Set `GATEWAY_API_KEY` on the gateway and capture agents. Comparison uses constant-time equality.
- **Require auth in production**: Set `GATEWAY_REQUIRE_API_KEY=true` to reject unauthenticated ingest when no key is configured.
- **Request limits**: `GATEWAY_MAX_BODY_BYTES`, `GATEWAY_MAX_EVENTS_PER_BATCH`, and per-event raw payload size caps.
- **Rate limiting**: `GATEWAY_RATE_LIMIT_PER_MINUTE` (default 600) on ingest endpoints.
- **Localhost binding**: Docker Compose publishes Kafka, Elasticsearch, Kibana, and the gateway on `127.0.0.1` only.

## Development

All builds, tests, and lint run inside Docker (host needs only Docker):

```bash
make test    # cargo test --workspace
make lint    # cargo fmt --check && cargo clippy
make build   # Rust service images
```

## Kibana dashboards

Imported automatically on startup via `kibana-setup` service. Regenerate saved objects with:

```bash
python3 kibana/build-dashboards.py
```

| Dashboard | What it shows |
|-----------|----------------|
| **Traffic Overview** | Connection summary metrics, timelines by protocol, top IPs/ports, services, IP pairs, conn log search |
| **Threat Intelligence** | Match summary, severity timelines, categories/feeds, indicator matrix, affected agents/hosts/IPs, threat log search |
| **p0f Fingerprints** | Summary metrics, OS/link timelines, distributions, src/dst IPs, agent/hostname breakdown, raw log search |
| **fatt TLS/SSH/HTTP** | Summary metrics (JA3/JA3S/HASSH/HTTP hashes), protocol timelines, TLS/SSH/HTTP tables and IP correlation pies, raw log search |
| **DNS, HTTP and SSL** | Per-protocol summaries, timelines, top domains/hosts/SNI, query types, ciphers, status codes, per-protocol log searches |
| **Operations** | Pipeline summary, source/agent timelines, source breakdown, Zeek log types, pipeline log search |

Open Kibana at http://localhost:5601 → **Analytics → Dashboard**.

## Configuration

See `.env.example` for environment variables. Set `GATEWAY_API_KEY` on gateway and capture agents for authenticated ingest.

## License

MIT
