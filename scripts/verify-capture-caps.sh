#!/usr/bin/env bash
set -euo pipefail

CONTAINER="${1:-netwatcher-capture-agent}"
REQUIRED=(NET_ADMIN NET_RAW)

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not found" >&2
  exit 1
fi

if ! docker inspect "$CONTAINER" >/dev/null 2>&1; then
  echo "container not found: $CONTAINER (start with: make up-capture)" >&2
  exit 1
fi

caps="$(docker inspect "$CONTAINER" --format '{{.HostConfig.CapAdd}}')"
echo "CapAdd: ${caps}"

for cap in "${REQUIRED[@]}"; do
  if [[ "$caps" != *"$cap"* ]]; then
    echo "missing capability: $cap" >&2
    exit 1
  fi
done

echo "capture capabilities OK"
