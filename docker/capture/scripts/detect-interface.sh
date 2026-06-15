#!/usr/bin/env bash
set -euo pipefail

# Resolve the capture interface: honor an explicit name, otherwise pick the
# default-route NIC or the first UP non-loopback interface with IPv4.

default_iface() {
  ip -4 route show default 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit }}'
}

first_up_iface() {
  local dev
  while read -r dev _; do
    [[ "$dev" == "lo" ]] && continue
    if ip link show dev "$dev" 2>/dev/null | grep -q 'state UP'; then
      if ip -4 addr show dev "$dev" 2>/dev/null | grep -q 'inet '; then
        echo "$dev"
        return 0
      fi
    fi
  done < <(ip -o link show | awk -F': ' '{print $2}')
  return 1
}

requested="${1:-auto}"

if [[ -n "$requested" && "$requested" != "auto" ]]; then
  if ip link show "$requested" &>/dev/null; then
    echo "$requested"
    exit 0
  fi
  echo "warning: interface '${requested}' not found, auto-detecting" >&2
fi

iface="$(default_iface || true)"
if [[ -n "$iface" ]] && ip link show "$iface" &>/dev/null; then
  echo "$iface"
  exit 0
fi

if iface="$(first_up_iface)"; then
  echo "$iface"
  exit 0
fi

echo "eth0"
