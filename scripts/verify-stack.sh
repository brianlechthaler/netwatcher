#!/usr/bin/env bash
# Verify NetWatcher stack health for PR checklist items.
set -euo pipefail

COMPOSE="docker compose -f deploy/docker-compose/compose.yaml"
GATEWAY_URL="${GATEWAY_URL:-http://localhost:8080}"
KIBANA_URL="${KIBANA_URL:-http://localhost:5601}"
ES_URL="${ES_URL:-http://localhost:9200}"

echo "==> Checking gateway health"
curl -sf "${GATEWAY_URL}/health" | grep -q '"status":"ok"'

echo "==> Checking Elasticsearch"
curl -sf "${ES_URL}/_cluster/health" | grep -q '"status"'

echo "==> Checking Kibana"
curl -sf "${KIBANA_URL}/api/status" | grep -q '"level"'

echo "==> Checking Kibana index patterns"
for pattern in netwatcher netwatcher-zeek netwatcher-enriched; do
  curl -sf "${KIBANA_URL}/api/index_patterns/_fields_for_wildcard?pattern=${pattern}-*" \
    -H "kbn-xsrf: true" >/dev/null || echo "  note: pattern ${pattern} may not exist yet"
done

echo "==> Testing MCP initialize handshake"
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  | docker run --rm -i --network docker-compose_netwatcher \
      -e ELASTICSEARCH_URL=http://elasticsearch:9200 \
      -e ELASTICSEARCH_INDEX_PREFIX=netwatcher \
      netwatcher-rust:local netwatcher-mcp 2>/dev/null \
  | grep -q '"protocolVersion"'

echo "==> Validating Kubernetes manifests"
docker run --rm \
  -v "$(pwd)/deploy/kubernetes:/work" -w /work \
  alpine/k8s:1.30.2 kustomize build . >/dev/null

echo "All verification checks passed."
