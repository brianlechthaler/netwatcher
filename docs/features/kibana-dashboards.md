# Kibana dashboards

NetWatcher ships six Kibana dashboards. They import automatically when the stack starts via the `kibana-setup` Compose service (`kibana/import-dashboards.sh`).

Open Kibana at http://localhost:5601 → **Analytics → Dashboard**.

![Kibana home with NetWatcher dashboards available](../images/kibana-home.png)

## Dashboards

### Traffic Overview

Connection summary metrics, timelines by protocol, top IPs and ports, services, IP pairs, and conn log search.

![Traffic Overview dashboard showing Zeek conn metrics and top IP panels](../images/kibana-traffic-overview.png)

### Threat Intelligence

Match summary, severity timelines, categories and feeds, indicator matrix, affected agents and hosts, threat log search.

![Threat Intelligence dashboard with severity and feed breakdown panels](../images/kibana-threat-intelligence.png)

### p0f Fingerprints

OS and link-layer fingerprint metrics, timelines, distributions, source and destination IPs, agent breakdown, raw log search.

![p0f Fingerprints dashboard with OS distribution and timeline panels](../images/kibana-p0f-fingerprints.png)

### fatt TLS/SSH/HTTP

JA3, JA3S, HASSH, and HTTP hash metrics, protocol timelines, TLS/SSH/HTTP tables, IP correlation, raw log search.

![fatt TLS SSH HTTP dashboard with protocol hash and timeline panels](../images/kibana-fatt-tls-ssh-http.png)

### DNS, HTTP and SSL

Per-protocol summaries, timelines, top domains and SNI, query types, ciphers, HTTP status codes, per-protocol log searches.

![DNS HTTP SSL dashboard with protocol-specific summary panels](../images/kibana-dns-http-ssl.png)

### Operations

Pipeline summary, source and agent timelines, source breakdown, Zeek log types, pipeline log search.

![Operations dashboard showing pipeline source and agent metrics](../images/kibana-operations.png)

## Regenerating dashboards

Saved objects are generated from Python and stored as NDJSON:

```bash
python3 kibana/build-dashboards.py
# Output: kibana/dashboards/netwatcher-dashboards.ndjson
```

Restart the stack or re-run the import script to apply changes.

## Time range and data

Dashboards default to **Last 15 minutes**. If panels show no data:

1. Confirm the capture agent is running (`make up-capture`)
2. Widen the time picker (e.g. Last 24 hours)
3. Check Elasticsearch: `curl -s 'http://localhost:9200/netwatcher-*/_count'`

## Related

- [Getting started](../getting-started.md)
- [Indexer](indexer.md)
- [Enricher](enricher.md)
