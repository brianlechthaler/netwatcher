#!/usr/bin/env bash
# Seed sample BZAR ATT&CK alerts into Elasticsearch for dashboard verification.
set -euo pipefail

ES_URL="${ES_URL:-http://127.0.0.1:9200}"
INDEX_PREFIX="${INDEX_PREFIX:-netwatcher}"
TODAY="$(date -u +%Y.%m.%d)"
INDEX="${INDEX_PREFIX}-enriched-${TODAY}"

now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

seed_event() {
  local id="$1"
  local payload="$2"
  curl -sf -X PUT "${ES_URL}/${INDEX}/_doc/${id}" \
    -H "Content-Type: application/json" \
    -d "${payload}" >/dev/null
  echo "  indexed ${id}"
}

echo "Seeding ATT&CK sample events into ${INDEX}..."

seed_event "attack-seed-001" "$(cat <<EOF
{
  "id": "attack-seed-001",
  "timestamp": "${now}",
  "source": "enriched",
  "agent_id": "seed-agent",
  "hostname": "seed-host",
  "zeek_log_type": "notice",
  "tags": ["attack_match", "bzar", "Execution", "T1569.002"],
  "raw": {
    "ts": 1718582400.0,
    "note": "ATTACK::Execution",
    "msg": "Detected service execution via DCE-RPC",
    "sub": "T1569.002 System Services: Service Execution",
    "id.orig_h": "10.0.0.2",
    "id.resp_h": "10.0.0.5"
  },
  "attack": {
    "matched": true,
    "tactic": "Execution",
    "tactic_id": "TA0002",
    "technique_id": "T1569.002",
    "technique": "System Services: Service Execution",
    "notice_type": "ATTACK::Execution",
    "description": "Detected service execution via DCE-RPC",
    "source": "bzar"
  }
}
EOF
)"

seed_event "attack-seed-002" "$(cat <<EOF
{
  "id": "attack-seed-002",
  "timestamp": "${now}",
  "source": "enriched",
  "agent_id": "seed-agent",
  "hostname": "seed-host",
  "zeek_log_type": "notice",
  "tags": ["attack_match", "bzar", "Credential Access", "T1003.006"],
  "raw": {
    "note": "ATTACK::Credential_Access",
    "msg": "Detected DCSync against domain controller",
    "sub": "T1003.006 OS Credential Dumping: DCSync",
    "id.orig_h": "10.0.0.8",
    "id.resp_h": "10.0.0.10"
  },
  "attack": {
    "matched": true,
    "tactic": "Credential Access",
    "tactic_id": "TA0006",
    "technique_id": "T1003.006",
    "technique": "OS Credential Dumping: DCSync",
    "notice_type": "ATTACK::Credential_Access",
    "description": "Detected DCSync against domain controller",
    "source": "bzar"
  }
}
EOF
)"

seed_event "attack-seed-003" "$(cat <<EOF
{
  "id": "attack-seed-003",
  "timestamp": "${now}",
  "source": "enriched",
  "agent_id": "seed-agent-2",
  "hostname": "seed-host-2",
  "zeek_log_type": "notice",
  "tags": ["attack_match", "bzar", "Discovery", "T1018"],
  "raw": {
    "note": "ATTACK::Discovery",
    "msg": "Detected T1018 Remote System Discovery from host 10.0.0.3",
    "id.orig_h": "10.0.0.3",
    "id.resp_h": "10.0.0.20"
  },
  "attack": {
    "matched": true,
    "tactic": "Discovery",
    "tactic_id": "TA0007",
    "technique_id": "T1018",
    "technique": "Remote System Discovery",
    "notice_type": "ATTACK::Discovery",
    "description": "Detected T1018 Remote System Discovery from host 10.0.0.3",
    "source": "bzar"
  }
}
EOF
)"

curl -sf -X POST "${ES_URL}/${INDEX}/_refresh" >/dev/null
echo "Done. Open Kibana → Analytics → Dashboard → NetWatcher ATT&CK Coverage"
