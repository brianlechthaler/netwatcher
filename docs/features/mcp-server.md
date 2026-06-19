# MCP server

NetWatcher includes a stdio MCP server (`netwatcher-mcp`) that lets AI agents query Elasticsearch for network events and threat context.

## Cursor setup

With the Docker Compose stack running, merge `mcp/mcp.json` into your Cursor MCP config:

```json
{
  "mcpServers": {
    "netwatcher": {
      "command": "docker",
      "args": ["exec", "-i", "netwatcher-mcp", "netwatcher-mcp"],
      "env": {
        "ELASTICSEARCH_URL": "http://elasticsearch:9200",
        "ELASTICSEARCH_INDEX_PREFIX": "netwatcher",
        "RUST_LOG": "info"
      }
    }
  }
}
```

For a host-installed binary instead of Docker:

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

## Tools

| Tool | Description |
|------|-------------|
| `search_events` | Lucene search across indices; optional `source` filter |
| `threat_summary` | Summarize threat matches from enriched events |
| `analyze_ip` | Traffic and fingerprints for a single IP |
| `list_sources` | List data sources and index patterns |

### search_events

```json
{
  "query": "source:zeek AND id.resp_p:443",
  "source": "zeek",
  "limit": 20
}
```

### threat_summary

```json
{
  "hours": 24
}
```

### analyze_ip

```json
{
  "ip": "192.0.2.10",
  "limit": 50
}
```

## Security

The MCP server implements defense-in-depth controls aligned with [NSA MCP security guidance](https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf). See [Security](security.md#mcp-server) for the full list.

The Compose `mcp` service runs read-only with `cap_drop: ALL`, `no-new-privileges`, and CPU/memory limits.

## Related

- [Security](security.md)
- [Indexer](indexer.md)
- [Configuration](configuration.md)
