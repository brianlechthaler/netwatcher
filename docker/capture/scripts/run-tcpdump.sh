#!/usr/bin/env bash
set -euo pipefail
INTERFACE="${1:-eth0}"
ROTATE_SECS="${PCAP_ROTATE_SECS:-30}"
ROTATE_COUNT="${PCAP_ROTATE_COUNT:-20}"
ROTATE_SIZE_MB="${PCAP_ROTATE_SIZE_MB:-10}"

exec tcpdump -i "${INTERFACE}" -s 0 -U \
    -w "/pcap/capture.pcap" \
    -G "${ROTATE_SECS}" \
    -W "${ROTATE_COUNT}" \
    -C "${ROTATE_SIZE_MB}" \
    -Z root
