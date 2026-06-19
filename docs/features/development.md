# Development

All builds, tests, and lint run inside Docker. The host needs only Docker.

## Commands

```bash
make test      # cargo test --workspace
make lint      # cargo fmt --check && cargo clippy
make build     # Rust service images (netwatcher-rust:local)
make build-gateway   # Gateway image with Zeek/p0f/fatt
make build-capture   # Capture agent image
make fmt       # auto-format
make coverage  # tarpaulin on selected crates (80% threshold)
```

## Workspace crates

| Crate | Binary | Purpose |
|-------|--------|---------|
| `netwatcher-common` | (library) | Shared types, config, parsers |
| `netwatcher-capturer` | `netwatcher-capturer` | PCAP capture |
| `netwatcher-shipper` | `netwatcher-shipper` | PCAP upload |
| `netwatcher-gateway` | `netwatcher-gateway` | Ingest and analysis |
| `netwatcher-enricher` | `netwatcher-enricher` | Threat enrichment |
| `netwatcher-indexer` | `netwatcher-indexer` | ES indexing |
| `netwatcher-mcp` | `netwatcher-mcp` | MCP server |

## Interactive shell

```bash
make shell-rust
# Opens bash in rust:1.88-bookworm with workspace mounted at /workspace
```

## Stack verification

After `make up`:

```bash
./scripts/verify-stack.sh
make verify   # same script via Makefile target (if added) or direct invocation
```

Checks gateway health, Elasticsearch, Kibana, index patterns, MCP handshake, and Kubernetes manifest validity.

## CI

GitHub Actions workflows:

| Workflow | Purpose |
|----------|---------|
| `.github/workflows/test.yml` | Unit tests |
| `.github/workflows/lint.yml` | fmt and clippy |
| `.github/workflows/integration.yml` | Stack integration |
| `.github/workflows/container.yml` | GHCR image publish |

## Kibana dashboard development

```bash
python3 kibana/build-dashboards.py
```

Edits go in `kibana/build-dashboards.py`. Output NDJSON lands in `kibana/dashboards/`.

## Related

- [Architecture](../architecture.md)
- [Getting started](../getting-started.md)
