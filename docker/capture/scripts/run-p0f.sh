#!/usr/bin/env bash
set -euo pipefail
INTERFACE="${1:-eth0}"

exec p0f -i "${INTERFACE}" -p -o /logs/p0f/p0f.log -0
