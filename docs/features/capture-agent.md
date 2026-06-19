# Capture agent

The capture agent records network traffic as rotating PCAP files and uploads them to the gateway for analysis. It runs `netwatcher-capturer` (Rust, libpcap) under supervisord in a minimal Debian children.

## What runs on the agent

| Binary | Purpose |
|--------|---------|
| `netwatcher-capturer` | Rotates PCAP on a network interface |
| `netwatcher-shipper` | Uploads completed PCAP files to the gateway via HTTP multipart |

Zeek, p0f, and fatt run on the **gateway**, not on the agent. This keeps the edge footprint small.

## Local capture (Compose profile)

```bash
make up-capture
```

Uses `deploy/docker-compose/compose.yaml` with the `capture` profile. The agent uses host networking and requires raw capture capabilities.

## Remote capture

On a machine that can reach the central gateway:

```bash
export GATEWAY_URL=http://<gateway-host>:8080
export AGENT_ID=edge-sensor-01
export CAPTURE_INTERFACE=auto
docker compose -f deploy/docker-compose/compose.capture.yaml up -d
```

File: `deploy/docker-compose/compose.capture.yaml`

## Interface selection

| Value | Behavior |
|-------|----------|
| `auto` (default) | Pick the interface for the default route |
| `enp4s0`, `eth0`, etc. | Capture on that interface |

Set via `CAPTURE_INTERFACE` in `.env` or the environment. List interfaces: `ip -br link show`.

## CAP_NET_RAW requirements

Packet capture needs `CAP_NET_RAW` and `CAP_NET_ADMIN`.

**Docker Compose** — `make up-capture` adds capabilities via `cap_add`:

```yaml
cap_add:
  - NET_ADMIN
  - NET_RAW
```

Verify:

```bash
docker inspect netwatcher-capture-agent --format '{{.HostConfig.CapAdd}}'
# Expected: [NET_ADMIN NET_RAW]

./scripts/verify-capture-caps.sh
```

**Host binary** — without Docker:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip /usr/local/bin/netwatcher-capturer
getcap /usr/local/bin/netwatcher-capturer
```

Remove later: `sudo setcap -r /path/to/binary`.

## PCAP rotation

Defaults (override in `.env`):

| Variable | Default | Description |
|----------|---------|-------------|
| `PCAP_DIR` | `/pcap` | Output directory |
| `PCAP_ROTATE_SECS` | `30` | Time-based rotation |
| `PCAP_ROTATE_COUNT` | `20` | Max files kept |
| `PCAP_ROTATE_SIZE_MB` | `10` | Size-based rotation |

## Troubleshooting

- **Rootless Docker** often cannot add `NET_RAW`. Use rootful Docker or run the capturer on the host with `setcap`.
- **Permission errors** inside the container — confirm `cap_add` is not overridden (e.g. `--cap-drop=all`).
- **No traffic in dashboards** — pick an interface that carries traffic; `eth0` may not exist on all hosts.
- **401 on upload** — set matching `GATEWAY_API_KEY` on gateway and agent.

## Related

- [Gateway ingest](gateway.md)
- [Configuration](configuration.md)
- [Getting started](../getting-started.md)
