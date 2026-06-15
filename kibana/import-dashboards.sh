#!/bin/sh
set -eu

KIBANA_URL="${KIBANA_URL:-http://kibana:5601}"
ES_URL="${ES_URL:-http://elasticsearch:9200}"

if command -v python3 >/dev/null 2>&1 && [ -f /kibana/build-dashboards.py ]; then
  echo "Regenerating dashboard saved objects..."
  python3 /kibana/build-dashboards.py
fi

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
    --form "file=@${file}" | tee /tmp/kibana-import.json || echo "  warning: import failed for ${file}"
  if ! grep -q '"success":true' /tmp/kibana-import.json 2>/dev/null; then
    echo "  warning: import reported errors for ${file}"
    grep -o '"message":"[^"]*"' /tmp/kibana-import.json 2>/dev/null | head -3 || true
  fi
done

echo "Refreshing index pattern fields..."
curl -sf -X POST "${KIBANA_URL}/api/index_patterns/index_pattern/netwatcher-index-pattern/fields/_refresh" \
  -H "kbn-xsrf: true" >/dev/null 2>&1 || true

echo "Kibana setup complete."
