# Enricher

The enricher consumes raw events from Kafka, matches source and destination IPs against Emerging Threats feeds, and publishes enriched events to the `netwatcher.enriched` topic.

## Feeds

Default feeds (configured in `netwatcher-common`):

| Feed | URL pattern | Parser |
|------|-------------|--------|
| ET compromised IPs | Emerging Threats compromised hosts list | `parse_et_compromised_ips` |
| ET botnet C&C | Emerging Threats botcc rules | `parse_et_botcc_rules` |

Feeds refresh on a timer (`THREAT_REFRESH_SECS`, default 3600).

## Behavior

1. Read events from Kafka topics for zeek, p0f, and fatt
2. Look up IPs in the in-memory threat store
3. Attach match metadata (category, severity, feed name)
4. Publish to `netwatcher.enriched`

If no indicators load from any feed on refresh, the enricher logs a warning and retries on the next cycle.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `KAFKA_BROKERS` | `kafka:9092` | Broker list |
| `KAFKA_TOPIC_PREFIX` | `netwatcher` | Topic prefix |
| `KAFKA_GROUP_ID` | `netwatcher-enricher` | Consumer group |
| `THREAT_REFRESH_SECS` | `3600` | Feed refresh interval |

## Viewing enriched data

- Kibana: [Threat Intelligence dashboard](kibana-dashboards.md#threat-intelligence)
- MCP: `threat_summary` and `search_events` with `source: enriched`

## Related

- [Architecture](../architecture.md)
- [Indexer](indexer.md)
- [Kibana dashboards](kibana-dashboards.md)
