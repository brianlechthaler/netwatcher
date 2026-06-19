# NetWatcher

Modular network traffic monitoring. Capture agents record PCAP on edge hosts; the gateway analyzes traffic with Zeek, p0f, and fatt; events flow through Kafka, get enriched with Emerging Threats intelligence, and land in Elasticsearch for Kibana dashboards and MCP-based analysis.

## Quick start

```bash
make up              # Kafka, ES, Kibana, gateway, enricher, indexer, MCP
make up-capture      # optional local capture agent (CAP_NET_RAW)
./scripts/verify-stack.sh
```

| Service | URL |
|---------|-----|
| Gateway | http://localhost:8080 |
| Kibana | http://localhost:5601 |
| Elasticsearch | http://localhost:9200 |

Copy `.env.example` to `.env` for capture interface, API keys, and limits. See [Getting started](docs/getting-started.md) for remote agents, interface selection, and troubleshooting.

## Documentation

- [Documentation index](docs/index.md)
- [Getting started](docs/getting-started.md)
- [Architecture](docs/architecture.md)
- [Features](docs/features/)
  - [Capture agent](docs/features/capture-agent.md)
  - [Gateway](docs/features/gateway.md)
  - [Kibana dashboards](docs/features/kibana-dashboards.md)
  - [MCP server](docs/features/mcp-server.md)
  - [Security](docs/features/security.md)
  - [Configuration](docs/features/configuration.md)
  - [Kubernetes](docs/features/kubernetes-deployment.md)
  - [Development](docs/features/development.md)

## Requirements

- Docker Engine 24+ with Compose v2
- 4 GB RAM minimum
- Rootful Docker for local packet capture (`NET_RAW`, `NET_ADMIN`)

## License

MIT — see [LICENSE](LICENSE).
