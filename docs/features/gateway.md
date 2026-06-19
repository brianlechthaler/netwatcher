# Gateway

The gateway accepts PCAP uploads and JSON event batches from capture agents, runs traffic analysis, and publishes normalized events to Kafka.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Liveness check |
| `POST` | `/api/v1/agents/register` | Register agent metadata |
| `POST` | `/api/v1/ingest` | JSON event batch ingest |
| `POST` | `/api/v1/ingest/pcap` | PCAP multipart upload |

Default bind: `http://127.0.0.1:8080` (Compose publishes on localhost only).

![Gateway health JSON response](../images/gateway-health.png)

## PCAP analysis pipeline

On PCAP ingest the gateway:

1. Validates magic bytes and file size limits
2. Runs Zeek offline on the PCAP
3. Runs p0f for passive OS fingerprinting
4. Runs fatt for TLS, SSH, and HTTP metadata extraction
5. Parses analyzer output and publishes to Kafka topics (`netwatcher.zeek`, `netwatcher.p0f`, `netwatcher.fatt`)

Analyzers run as the unprivileged `zeek-analyzer` user (UID/GID 999) inside the gateway image.

## Authentication

When `GATEWAY_API_KEY` is set, agents must send the key in the `X-API-Key` header. Comparison uses constant-time equality.

Set `GATEWAY_REQUIRE_API_KEY=true` to reject unauthenticated ingest in production even when no key is configured (fail-closed).

## Rate and size limits

| Variable | Default | Purpose |
|----------|---------|---------|
| `GATEWAY_MAX_BODY_BYTES` | 10 MB | JSON ingest body cap |
| `GATEWAY_MAX_PCAP_BYTES` | 50 MB | PCAP upload cap |
| `GATEWAY_MAX_EVENTS_PER_BATCH` | 500 | Events per JSON batch |
| `GATEWAY_RATE_LIMIT_PER_MINUTE` | 600 | Ingest rate limit |

## Example: health check

```bash
curl -s http://localhost:8080/health
# {"status":"ok","service":"netwatcher-gateway"}
```

## Example: PCAP upload

```bash
curl -X POST http://localhost:8080/api/v1/ingest/pcap \
  -H "X-Agent-Id: test-agent" \
  -H "X-API-Key: $GATEWAY_API_KEY" \
  -F "pcap=@capture.pcap"
```

## Related

- [Architecture](../architecture.md)
- [Capture agent](capture-agent.md)
- [Security](security.md)
