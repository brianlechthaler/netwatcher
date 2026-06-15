#!/bin/sh
set -eu

KIBANA_URL="${KIBANA_URL:-http://kibana:5601}"
ES_URL="${ES_URL:-http://elasticsearch:9200}"

echo "Waiting for Kibana at ${KIBANA_URL}..."
until curl -sf "${KIBANA_URL}/api/status" >/dev/null 2>&1; do
  sleep 5
done

echo "Creating Kibana index patterns..."
for pattern in "netwatcher-*" "netwatcher-zeek-*" "netwatcher-enriched-*" "netwatcher-p0f-*" "netwatcher-fatt-*"; do
  curl -sf -X POST "${KIBANA_URL}/api/index_patterns/index_pattern" \
    -H "kbn-xsrf: true" \
    -H "Content-Type: application/json" \
    -d "{\"index_pattern\":{\"title\":\"${pattern}\",\"timeFieldName\":\"timestamp\"}}" \
    >/dev/null 2>&1 || true
done

echo "Importing saved objects..."
for file in /kibana/dashboards/*.ndjson; do
  [ -f "$file" ] || continue
  echo "  importing $(basename "$file")"
  curl -sf -X POST "${KIBANA_URL}/api/saved_objects/_import?overwrite=true" \
    -H "kbn-xsrf: true" \
    --form "file=@${file}" >/dev/null || echo "  warning: import failed for ${file}"
done

echo "Kibana setup complete."
