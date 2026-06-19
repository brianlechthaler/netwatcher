# Indexer

The indexer consumes all NetWatcher Kafka topics and writes documents to Elasticsearch with daily index rotation.

## Index naming

Pattern: `{ELASTICSEARCH_INDEX_PREFIX}-{source}-{YYYY.MM.DD}`

Examples with default prefix `netwatcher`:

- `netwatcher-zeek-2026.06.18`
- `netwatcher-p0f-2026.06.18`
- `netwatcher-fatt-2026.06.18`
- `netwatcher-enriched-2026.06.18`

Kibana uses the index pattern `netwatcher-*`.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `KAFKA_BROKERS` | `kafka:9092` | Broker list |
| `KAFKA_TOPIC_PREFIX` | `netwatcher` | Topic prefix |
| `KAFKA_GROUP_ID` | `netwatcher-indexer` | Consumer group |
| `ELASTICSEARCH_URL` | `http://elasticsearch:9200` | ES cluster URL |
| `ELASTICSEARCH_INDEX_PREFIX` | `netwatcher` | Index name prefix |

## Health

The indexer starts after Kafka and Elasticsearch are healthy. Check document counts:

```bash
curl -s 'http://localhost:9200/netwatcher-*/_count' | jq .
```

## Related

- [Architecture](../architecture.md)
- [Kibana dashboards](kibana-dashboards.md)
- [MCP server](mcp-server.md)
