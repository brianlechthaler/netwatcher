# NetWatcher

Modular network traffic monitoring system that captures packets with Zeek, p0f, and fatt, ships logs through a Rust gateway to Kafka, enriches with Emerging Threats intelligence, indexes to Elasticsearch, and provides Kibana dashboards plus an MCP server for AI-assisted analysis.

## Architecture

```
[Capture Agent] --HTTP--> [Gateway] --> [Kafka]
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
| **capture-agent** | Zeek + p0f + fatt + log shipper (runs on any host) |
| **gateway** | HTTP ingest API, publishes to Kafka |
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

Services:

- Gateway: http://localhost:8080
- Kibana: http://localhost:5601
- Elasticsearch: http://localhost:9200

### CAP_NET_RAW for local capture

Zeek, p0f, and fatt need raw packet capture on a network interface. That requires `CAP_NET_RAW` (and `CAP_NET_ADMIN` to bind to the interface). Set `CAPTURE_INTERFACE` in `.env` to the interface you want to monitor (see `ip link`).

**Docker Compose (recommended)** — `make up-capture` grants the needed capabilities automatically via `cap_add` in `deploy/docker-compose/compose.yaml`:

```yaml
cap_add:
  - NET_ADMIN   # CAP_NET_ADMIN
  - NET_RAW     # CAP_NET_RAW
  - SYS_ADMIN
```

No manual `setcap` is required on a normal rootful Docker install. Confirm the running container has them:

```bash
docker inspect netwatcher-capture-agent --format '{{.HostConfig.CapAdd}}'
# Expected: [NET_ADMIN NET_RAW SYS_ADMIN]

# Or run the helper script:
./scripts/verify-capture-caps.sh
```

**Capture binaries on the host (without Docker)** — grant file capabilities on each binary that opens the capture interface:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip /usr/local/zeek/bin/zeek
sudo setcap cap_net_raw,cap_net_admin+eip /usr/local/bin/p0f
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
export CAPTURE_INTERFACE=eth0
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

## Development

All builds, tests, and lint run inside Docker (host needs only Docker):

```bash
make test    # cargo test --workspace
make lint    # cargo fmt --check && cargo clippy
make build   # Rust service images
```

## Kibana dashboards

Imported automatically on startup via `kibana-setup` service:

- Traffic overview (Zeek connections)
- Threat intelligence matches
- p0f OS fingerprinting
- fatt TLS/SSH fingerprints
- DNS/HTTP analysis

## Configuration

See `.env.example` for environment variables. Set `GATEWAY_API_KEY` on gateway and capture agents for authenticated ingest.

## License

MIT
