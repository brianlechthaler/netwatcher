# NetWatcher documentation

NetWatcher is a modular network traffic monitoring system. Capture agents record PCAP on edge hosts; the gateway analyzes traffic with Zeek, p0f, and fatt; events flow through Kafka, get enriched with threat intelligence, and land in Elasticsearch for Kibana dashboards and MCP-based analysis.

## Guides

- [Getting started](getting-started.md) — install, run with Docker Compose, verify the stack
- [Architecture](architecture.md) — components, data flow, extension points

## Features

- [Capture agent](features/capture-agent.md) — local and remote PCAP collection
- [Gateway](features/gateway.md) — ingest API and PCAP analysis
- [Enricher](features/enricher.md) — Emerging Threats IP reputation
- [Indexer](features/indexer.md) — Kafka to Elasticsearch
- [Kibana dashboards](features/kibana-dashboards.md) — analyst views
- [MCP server](features/mcp-server.md) — AI-assisted queries in Cursor
- [Kubernetes deployment](features/kubernetes-deployment.md) — cluster manifests
- [Security](features/security.md) — gateway and MCP hardening
- [Configuration](features/configuration.md) — environment variables
- [Development](features/development.md) — build, test, lint in Docker

## Screenshots

Dashboard and health-check images live under [images/](images/).
