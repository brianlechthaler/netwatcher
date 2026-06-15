#!/usr/bin/env bash
set -euo pipefail

INTERFACE="${CAPTURE_INTERFACE:-eth0}"
GATEWAY_URL="${GATEWAY_URL:-http://gateway:8080}"
AGENT_ID="${AGENT_ID:-capture-agent-1}"
API_KEY="${GATEWAY_API_KEY:-}"

mkdir -p /logs/zeek /logs/p0f /logs/fatt

cat > /etc/supervisor/conf.d/netwatcher-runtime.conf <<EOF
[program:zeek]
command=/opt/netwatcher/scripts/run-zeek.sh ${INTERFACE}
autostart=true
autorestart=true
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0

[program:p0f]
command=/opt/netwatcher/scripts/run-p0f.sh ${INTERFACE}
autostart=true
autorestart=true
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0

[program:fatt]
command=/opt/netwatcher/scripts/run-fatt.sh ${INTERFACE}
autostart=true
autorestart=true
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0

[program:shipper]
command=/usr/local/bin/netwatcher-shipper --gateway-url ${GATEWAY_URL} --agent-id ${AGENT_ID} --watch-dirs /logs/zeek,/logs/p0f,/logs/fatt
environment=GATEWAY_API_KEY="${API_KEY}"
autostart=true
autorestart=true
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0
EOF

echo "NetWatcher capture agent starting on interface ${INTERFACE}, reporting to ${GATEWAY_URL}"
exec /usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf
