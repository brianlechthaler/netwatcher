#!/usr/bin/env bash
set -euo pipefail
INTERFACE="${1:-eth0}"
ZEEK_LOG_PATH="${ZEEK_LOG_PATH:-/logs/zeek}"

exec zeek -i "${INTERFACE}" local "Log::default_rotation_interval=1day" "LogAscii::use_json=T" "Log::path=${ZEEK_LOG_PATH}"
