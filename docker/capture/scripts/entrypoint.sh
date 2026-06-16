#!/usr/bin/env bash
set -euo pipefail

validate_identifier() {
    local value="$1"
    local field="$2"
    if [[ -z "${value}" || "${#value}" -gt 128 ]]; then
        echo "Invalid ${field}" >&2
        exit 1
    fi
    if [[ ! "${value}" =~ ^[a-zA-Z0-9._-]+$ ]]; then
        echo "Invalid characters in ${field}" >&2
        exit 1
    fi
}

INTERFACE="$(/opt/netwatcher/scripts/detect-interface.sh "${CAPTURE_INTERFACE:-auto}")"
GATEWAY_URL="${GATEWAY_URL:-http://gateway:8080}"
AGENT_ID="${AGENT_ID:-capture-agent-1}"
API_KEY="${GATEWAY_API_KEY:-}"
PCAP_DIR="${PCAP_DIR:-/pcap}"

validate_identifier "${AGENT_ID}" "AGENT_ID"
validate_identifier "${INTERFACE}" "CAPTURE_INTERFACE"
validate_identifier "${PCAP_DIR#/}" "PCAP_DIR"

export GATEWAY_URL AGENT_ID GATEWAY_API_KEY="${API_KEY}" PCAP_DIR CAPTURE_INTERFACE="${INTERFACE}"

mkdir -p "${PCAP_DIR}"

cat > /etc/supervisor/conf.d/netwatcher-runtime.conf <<SUPERVISOR_EOF
[program:capturer]
command=/usr/local/bin/netwatcher-capturer --interface %(ENV_CAPTURE_INTERFACE)s --pcap-dir %(ENV_PCAP_DIR)s
autostart=true
autorestart=true
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0

[program:shipper]
command=/usr/local/bin/netwatcher-shipper
environment=GATEWAY_URL="%(ENV_GATEWAY_URL)s",AGENT_ID="%(ENV_AGENT_ID)s",GATEWAY_API_KEY="%(ENV_GATEWAY_API_KEY)s",PCAP_DIR="%(ENV_PCAP_DIR)s",CAPTURE_INTERFACE="%(ENV_CAPTURE_INTERFACE)s",WATCH_DIRS=""
autostart=true
autorestart=true
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0
SUPERVISOR_EOF

echo "NetWatcher lightweight capture agent on ${INTERFACE} (Rust PCAP → gateway Zeek/p0f/fatt analysis)"
exec /usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf
