#!/usr/bin/env bash
set -euo pipefail
INTERFACE="${1:-eth0}"

exec python3 /opt/fatt/fatt.py -i "${INTERFACE}" -j -p -o /logs/fatt/fatt.log
