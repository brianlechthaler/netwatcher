#!/usr/bin/env python3
"""Generate Kibana saved-object NDJSON for NetWatcher monitoring dashboards."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

INDEX_PATTERN_ID = "netwatcher-index-pattern"
INDEX_PATTERN_TITLE = "netwatcher-*"
CORE_MIGRATION = "8.8.0"
OUTPUT = Path(__file__).resolve().parent / "dashboards" / "netwatcher-dashboards.ndjson"


def kw(field: str) -> str:
    """Use the keyword subfield for terms aggregations on dynamic text mappings."""
    if field.endswith(".keyword") or field in {"raw.status_code", "raw.id.orig_p", "raw.id.resp_p"}:
        return field
    return f"{field}.keyword"


def count_agg(agg_id: str = "1") -> dict[str, Any]:
    return {
        "id": agg_id,
        "enabled": True,
        "type": "count",
        "schema": "metric",
        "params": {},
    }


def date_histogram_agg(field: str = "timestamp", agg_id: str = "2") -> dict[str, Any]:
    return {
        "id": agg_id,
        "enabled": True,
        "type": "date_histogram",
        "schema": "segment",
        "params": {
            "field": field,
            "interval": "auto",
            "min_doc_count": 1,
            "extended_bounds": {},
        },
    }


def terms_agg(
    field: str,
    size: int = 10,
    schema: str = "segment",
    agg_id: str = "2",
    order_by: str = "1",
) -> dict[str, Any]:
    return {
        "id": agg_id,
        "enabled": True,
        "type": "terms",
        "schema": schema,
        "params": {
            "field": field,
            "size": size,
            "orderBy": order_by,
            "order": "desc",
            "missing": "__missing__",
        },
    }


def sum_agg(field: str, agg_id: str = "1") -> dict[str, Any]:
    return {
        "id": agg_id,
        "enabled": True,
        "type": "sum",
        "schema": "metric",
        "params": {"field": field},
    }


def histogram_params(stacked: bool = False) -> dict[str, Any]:
    return {
        "type": "histogram",
        "grid": {"categoryLines": False},
        "categoryAxes": [
            {
                "id": "CategoryAxis-1",
                "type": "category",
                "position": "bottom",
                "show": True,
                "style": {},
                "scale": {"type": "linear"},
                "labels": {"show": True, "truncate": 100},
                "title": {},
            }
        ],
        "valueAxes": [
            {
                "id": "ValueAxis-1",
                "name": "LeftAxis-1",
                "type": "value",
                "position": "left",
                "show": True,
                "style": {},
                "scale": {"type": "linear", "mode": "normal"},
                "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                "title": {"text": "Count"},
            }
        ],
        "seriesParams": [
            {
                "show": True,
                "type": "histogram",
                "mode": "stacked" if stacked else "normal",
                "data": {"label": "Count", "id": "1"},
                "valueAxis": "ValueAxis-1",
                "drawLinesBetweenPoints": True,
                "showCircles": True,
            }
        ],
        "addTooltip": True,
        "addLegend": True,
        "legendPosition": "right",
        "times": [],
        "addTimeMarker": False,
    }


def pie_params(donut: bool = True) -> dict[str, Any]:
    return {
        "type": "pie",
        "addTooltip": True,
        "addLegend": True,
        "legendPosition": "right",
        "isDonut": donut,
        "labels": {"show": False, "values": True, "last_level": True, "truncate": 100},
    }


def table_params(per_page: int = 10) -> dict[str, Any]:
    return {
        "type": "table",
        "perPage": per_page,
        "showPartialRows": False,
        "showMetricsAtAllLevels": False,
        "showTotal": False,
        "showToolbar": True,
        "sort": {"columnIndex": None, "direction": None},
        "totalFunc": "sum",
    }


def metric_params(label: str = "") -> dict[str, Any]:
    return {
        "type": "metric",
        "addTooltip": True,
        "addLegend": False,
        "metric": {
            "percentageMode": False,
            "useRanges": False,
            "style": {
                "bgFill": "#000",
                "bgColor": False,
                "labelColor": False,
                "subText": label,
                "fontSize": 60,
            },
            "labels": {"show": True},
            "colorSchema": "Green to Red",
            "invertColors": False,
            "colorsRange": [{"from": 0, "to": 100000}],
            "metricColorMode": "None",
        },
    }


def horizontal_bar_params() -> dict[str, Any]:
    return {
        "type": "horizontal_bar",
        "grid": {"categoryLines": False},
        "categoryAxes": [
            {
                "id": "CategoryAxis-1",
                "type": "category",
                "position": "left",
                "show": True,
                "style": {},
                "scale": {"type": "linear"},
                "labels": {"show": True, "truncate": 100},
                "title": {},
            }
        ],
        "valueAxes": [
            {
                "id": "ValueAxis-1",
                "name": "LeftAxis-1",
                "type": "value",
                "position": "bottom",
                "show": True,
                "style": {},
                "scale": {"type": "linear", "mode": "normal"},
                "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                "title": {"text": "Count"},
            }
        ],
        "seriesParams": [
            {
                "show": True,
                "type": "histogram",
                "mode": "normal",
                "data": {"label": "Count", "id": "1"},
                "valueAxis": "ValueAxis-1",
                "drawLinesBetweenPoints": True,
                "showCircles": True,
            }
        ],
        "addTooltip": True,
        "addLegend": True,
        "legendPosition": "right",
        "times": [],
        "addTimeMarker": False,
    }


def search_source(query: str = "", index_ref: str = INDEX_PATTERN_ID) -> str:
    payload = {
        "query": {"language": "kuery", "query": query},
        "filter": [],
        "indexRefName": f"kibanaSavedObjectMeta:indexPattern:{index_ref}",
    }
    return json.dumps(payload)


def saved_object(
    obj_id: str,
    obj_type: str,
    attributes: dict[str, Any],
    references: list[dict[str, Any]],
    type_migration_version: str,
) -> dict[str, Any]:
    return {
        "id": obj_id,
        "type": obj_type,
        "coreMigrationVersion": CORE_MIGRATION,
        "typeMigrationVersion": type_migration_version,
        "references": references,
        "attributes": attributes,
    }


def make_visualization(
    vis_id: str,
    title: str,
    vis_type: str,
    params: dict[str, Any],
    aggs: list[dict[str, Any]],
    query: str = "",
) -> dict[str, Any]:
    vis_state = {
        "title": title,
        "type": vis_type,
        "params": params,
        "aggs": aggs,
    }
    return saved_object(
        vis_id,
        "visualization",
        {
            "title": title,
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "description": "",
            "kibanaSavedObjectMeta": {"searchSourceJSON": search_source(query)},
        },
        [
            {
                "id": INDEX_PATTERN_ID,
                "name": f"kibanaSavedObjectMeta:indexPattern:{INDEX_PATTERN_ID}",
                "type": "index-pattern",
            }
        ],
        "8.5.0",
    )


def make_dashboard(
    dash_id: str,
    title: str,
    description: str,
    query: str,
    panels: list[tuple[str, int, int, int, int]],
) -> dict[str, Any]:
    panel_objects: list[dict[str, Any]] = []
    references: list[dict[str, Any]] = [
        {
            "id": INDEX_PATTERN_ID,
            "name": "kibanaSavedObjectMeta:indexPattern:netwatcher-index-pattern",
            "type": "index-pattern",
        }
    ]

    for index, (vis_id, x, y, w, h) in enumerate(panels, start=1):
        panel_ref = f"panel_{index}"
        panel_objects.append(
            {
                "version": CORE_MIGRATION,
                "type": "visualization",
                "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(index)},
                "panelIndex": str(index),
                "embeddableConfig": {"title": vis_id},
                "panelRefName": panel_ref,
            }
        )
        references.append({"id": vis_id, "name": panel_ref, "type": "visualization"})

    return saved_object(
        dash_id,
        "dashboard",
        {
            "title": title,
            "description": description,
            "hits": 0,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": search_source(
                    query, index_ref="netwatcher-index-pattern"
                )
            },
            "optionsJSON": json.dumps({"useMargins": True, "syncColors": False}),
            "panelsJSON": json.dumps(panel_objects),
            "timeRestore": False,
        },
        references,
        "8.7.0",
    )


def index_pattern() -> dict[str, Any]:
    field_attrs = {
        "timestamp": {"count": 1},
        "source": {"count": 1},
        "agent_id": {"count": 1},
        "hostname": {"count": 1},
        "zeek_log_type": {"count": 1},
        "threat.matched": {"count": 1},
        "threat.severity": {"count": 1},
        "threat.categories": {"count": 1},
        "threat.indicator": {"count": 1},
        "threat.feed": {"count": 1},
        "raw.id.orig_h": {"count": 1},
        "raw.id.resp_h": {"count": 1},
        "raw.proto": {"count": 1},
        "raw.service": {"count": 1},
        "raw.conn_state": {"count": 1},
        "raw.query": {"count": 1},
        "raw.host": {"count": 1},
        "raw.method": {"count": 1},
        "raw.status_code": {"count": 1},
        "raw.src_ip": {"count": 1},
        "raw.dst_ip": {"count": 1},
        "raw.detail": {"count": 1},
        "raw.ja3": {"count": 1},
    }
    return saved_object(
        INDEX_PATTERN_ID,
        "index-pattern",
        {
            "title": INDEX_PATTERN_TITLE,
            "name": INDEX_PATTERN_TITLE,
            "timeFieldName": "timestamp",
            "allowHidden": False,
            "fieldAttrs": json.dumps(field_attrs),
            "fieldFormatMap": "{}",
            "fields": "[]",
            "runtimeFieldMap": "{}",
            "sourceFilters": "[]",
        },
        [],
        "8.0.0",
    )


def build_visualizations() -> list[dict[str, Any]]:
    conn_filter = "source:zeek AND zeek_log_type:conn AND NOT source:enriched"
    threat_filter = "source:enriched AND threat.matched:true"
    p0f_filter = "source:p0f AND NOT source:enriched"
    fatt_filter = "source:fatt AND NOT source:enriched"
    dns_filter = "source:zeek AND zeek_log_type:dns AND NOT source:enriched"
    http_filter = "source:zeek AND zeek_log_type:http AND NOT source:enriched"
    ops_filter = "NOT source:enriched"

    return [
        # Traffic overview
        make_visualization(
          "nw-vis-total-events",
          "Total Zeek Events",
          "metric",
          metric_params("conn logs"),
          [count_agg()],
          conn_filter,
      ),
      make_visualization(
          "nw-vis-conn-over-time",
          "Connection Volume Over Time",
          "histogram",
          histogram_params(),
          [count_agg(), date_histogram_agg()],
          conn_filter,
      ),
      make_visualization(
          "nw-vis-top-src-ips",
          "Top Source IPs",
          "table",
          table_params(15),
          [count_agg(), terms_agg(kw("raw.id.orig_h"), 15, "bucket")],
          conn_filter,
      ),
      make_visualization(
          "nw-vis-top-dst-ips",
          "Top Destination IPs",
          "table",
          table_params(15),
          [count_agg(), terms_agg(kw("raw.id.resp_h"), 15, "bucket")],
          conn_filter,
      ),
      make_visualization(
          "nw-vis-proto-breakdown",
          "Protocol Breakdown",
          "pie",
          pie_params(),
          [count_agg(), terms_agg(kw("raw.proto"), 8)],
          conn_filter,
      ),
      make_visualization(
          "nw-vis-conn-state",
          "Connection States",
          "horizontal_bar",
          horizontal_bar_params(),
          [count_agg(), terms_agg(kw("raw.conn_state"), 10)],
          conn_filter,
      ),
      make_visualization(
          "nw-vis-services",
          "Services Observed",
          "table",
          table_params(12),
          [count_agg(), terms_agg(kw("raw.service"), 12, "bucket")],
          conn_filter,
      ),
      make_visualization(
          "nw-vis-by-agent",
          "Events by Capture Agent",
          "pie",
          pie_params(donut=False),
          [count_agg(), terms_agg("agent_id", 10)],
          conn_filter,
      ),
      # Threat intel
      make_visualization(
          "nw-vis-threat-count",
          "Threat Matches",
          "metric",
          metric_params("matched events"),
          [count_agg()],
          threat_filter,
      ),
      make_visualization(
          "nw-vis-threat-over-time",
          "Threat Matches Over Time",
          "histogram",
          histogram_params(),
          [count_agg(), date_histogram_agg()],
          threat_filter,
      ),
      make_visualization(
          "nw-vis-threat-severity",
          "Matches by Severity",
          "pie",
          pie_params(),
          [count_agg(), terms_agg("threat.severity", 6)],
          threat_filter,
      ),
      make_visualization(
          "nw-vis-threat-categories",
          "Threat Categories",
          "horizontal_bar",
          horizontal_bar_params(),
          [count_agg(), terms_agg("threat.categories", 12)],
          threat_filter,
      ),
      make_visualization(
          "nw-vis-threat-feeds",
          "Matches by Feed",
          "pie",
          pie_params(donut=False),
          [count_agg(), terms_agg("threat.feed", 6)],
          threat_filter,
      ),
      make_visualization(
          "nw-vis-threat-indicators",
          "Top Indicators",
          "table",
          table_params(15),
          [count_agg(), terms_agg("threat.indicator", 15, "bucket")],
          threat_filter,
      ),
      make_visualization(
          "nw-vis-threat-agents",
          "Affected Capture Agents",
          "table",
          table_params(10),
          [
              count_agg(),
              terms_agg("agent_id", 10, "bucket"),
          ],
          threat_filter,
      ),
      # p0f
      make_visualization(
          "nw-vis-p0f-over-time",
          "p0f Events Over Time",
          "histogram",
          histogram_params(),
          [count_agg(), date_histogram_agg()],
          p0f_filter,
      ),
      make_visualization(
          "nw-vis-p0f-detail",
          "OS / Fingerprint Detail",
          "horizontal_bar",
          horizontal_bar_params(),
          [count_agg(), terms_agg(kw("raw.detail"), 12)],
          p0f_filter,
      ),
      make_visualization(
          "nw-vis-p0f-link",
          "Link Types",
          "pie",
          pie_params(),
          [count_agg(), terms_agg(kw("raw.link"), 8)],
          p0f_filter,
      ),
      make_visualization(
          "nw-vis-p0f-mode",
          "Detection Mode",
          "pie",
          pie_params(donut=False),
          [count_agg(), terms_agg(kw("raw.mod"), 6)],
          p0f_filter,
      ),
      make_visualization(
          "nw-vis-p0f-src",
          "Top p0f Source IPs",
          "table",
          table_params(12),
          [count_agg(), terms_agg(kw("raw.src_ip"), 12, "bucket")],
          p0f_filter,
      ),
      # fatt
      make_visualization(
          "nw-vis-fatt-over-time",
          "fatt Events Over Time",
          "histogram",
          histogram_params(),
          [count_agg(), date_histogram_agg()],
          fatt_filter,
      ),
      make_visualization(
          "nw-vis-fatt-ja3",
          "Top JA3 Fingerprints",
          "table",
          table_params(15),
          [count_agg(), terms_agg(kw("raw.ja3"), 15, "bucket")],
          fatt_filter,
      ),
      make_visualization(
          "nw-vis-fatt-src",
          "Top fatt Source IPs",
          "table",
          table_params(12),
          [count_agg(), terms_agg(kw("raw.src_ip"), 12, "bucket")],
          fatt_filter,
      ),
      make_visualization(
          "nw-vis-fatt-protocol",
          "fatt Protocol Split",
          "pie",
          pie_params(),
          [count_agg(), terms_agg(kw("raw.protocol"), 8)],
          fatt_filter,
      ),
      # DNS
      make_visualization(
          "nw-vis-dns-over-time",
          "DNS Queries Over Time",
          "histogram",
          histogram_params(),
          [count_agg(), date_histogram_agg()],
          dns_filter,
      ),
      make_visualization(
          "nw-vis-dns-queries",
          "Top Queried Domains",
          "table",
          table_params(15),
          [count_agg(), terms_agg(kw("raw.query"), 15, "bucket")],
          dns_filter,
      ),
      make_visualization(
          "nw-vis-dns-qtype",
          "DNS Query Types",
          "pie",
          pie_params(),
          [count_agg(), terms_agg(kw("raw.qtype_name"), 10)],
          dns_filter,
      ),
      make_visualization(
          "nw-vis-dns-rcode",
          "DNS Response Codes",
          "pie",
          pie_params(donut=False),
          [count_agg(), terms_agg(kw("raw.rcode_name"), 8)],
          dns_filter,
      ),
      # HTTP
      make_visualization(
          "nw-vis-http-over-time",
          "HTTP Requests Over Time",
          "histogram",
          histogram_params(),
          [count_agg(), date_histogram_agg()],
          http_filter,
      ),
      make_visualization(
          "nw-vis-http-hosts",
          "Top HTTP Hosts",
          "table",
          table_params(15),
          [count_agg(), terms_agg(kw("raw.host"), 15, "bucket")],
          http_filter,
      ),
      make_visualization(
          "nw-vis-http-methods",
          "HTTP Methods",
          "pie",
          pie_params(),
          [count_agg(), terms_agg(kw("raw.method"), 8)],
          http_filter,
      ),
      make_visualization(
          "nw-vis-http-status",
          "HTTP Status Codes",
          "horizontal_bar",
          horizontal_bar_params(),
          [count_agg(), terms_agg("raw.status_code", 12)],
          http_filter,
      ),
      # Operations
      make_visualization(
          "nw-vis-ops-by-source",
          "Event Volume by Source",
          "histogram",
          histogram_params(stacked=True),
          [
              count_agg(),
              date_histogram_agg(agg_id="2"),
              terms_agg("source", 6, schema="group", agg_id="3"),
          ],
          ops_filter,
      ),
      make_visualization(
          "nw-vis-ops-by-agent",
          "Events by Agent",
          "table",
          table_params(15),
          [count_agg(), terms_agg("agent_id", 15, "bucket")],
          ops_filter,
      ),
      make_visualization(
          "nw-vis-ops-by-host",
          "Events by Hostname",
          "table",
          table_params(15),
          [count_agg(), terms_agg("hostname", 15, "bucket")],
          ops_filter,
      ),
      make_visualization(
          "nw-vis-ops-zeek-types",
          "Zeek Log Types",
          "pie",
          pie_params(),
          [count_agg(), terms_agg("zeek_log_type", 10)],
          'source:zeek AND NOT source:enriched',
      ),
  ]


def build_dashboards() -> list[dict[str, Any]]:
    return [
        make_dashboard(
            "netwatcher-traffic-overview",
            "NetWatcher Traffic Overview",
            "Zeek connection volume, top talkers, and protocol breakdown",
            "source:zeek AND zeek_log_type:conn AND NOT source:enriched",
            [
                ("nw-vis-total-events", 0, 0, 24, 8),
                ("nw-vis-by-agent", 24, 0, 24, 8),
                ("nw-vis-conn-over-time", 0, 8, 48, 12),
                ("nw-vis-top-src-ips", 0, 20, 24, 12),
                ("nw-vis-top-dst-ips", 24, 20, 24, 12),
                ("nw-vis-proto-breakdown", 0, 32, 16, 12),
                ("nw-vis-conn-state", 16, 32, 16, 12),
                ("nw-vis-services", 32, 32, 16, 12),
            ],
        ),
        make_dashboard(
            "netwatcher-threat-intel",
            "NetWatcher Threat Intelligence",
            "Emerging Threats enriched matches by severity, category, and indicator",
            "source:enriched AND threat.matched:true",
            [
                ("nw-vis-threat-count", 0, 0, 16, 8),
                ("nw-vis-threat-severity", 16, 0, 16, 8),
                ("nw-vis-threat-feeds", 32, 0, 16, 8),
                ("nw-vis-threat-over-time", 0, 8, 48, 12),
                ("nw-vis-threat-categories", 0, 20, 24, 12),
                ("nw-vis-threat-indicators", 24, 20, 24, 12),
                ("nw-vis-threat-agents", 0, 32, 48, 10),
            ],
        ),
        make_dashboard(
            "netwatcher-p0f",
            "NetWatcher p0f Fingerprints",
            "OS and stack fingerprinting from passive p0f observations",
            "source:p0f AND NOT source:enriched",
            [
                ("nw-vis-p0f-over-time", 0, 0, 48, 12),
                ("nw-vis-p0f-detail", 0, 12, 24, 14),
                ("nw-vis-p0f-src", 24, 12, 24, 14),
                ("nw-vis-p0f-link", 0, 26, 24, 10),
                ("nw-vis-p0f-mode", 24, 26, 24, 10),
            ],
        ),
        make_dashboard(
            "netwatcher-fatt",
            "NetWatcher fatt TLS/SSH",
            "TLS JA3 and protocol fingerprints from fatt",
            "source:fatt AND NOT source:enriched",
            [
                ("nw-vis-fatt-over-time", 0, 0, 48, 12),
                ("nw-vis-fatt-ja3", 0, 12, 28, 14),
                ("nw-vis-fatt-src", 28, 12, 20, 14),
                ("nw-vis-fatt-protocol", 0, 26, 48, 10),
            ],
        ),
        make_dashboard(
            "netwatcher-dns-http",
            "NetWatcher DNS and HTTP",
            "Zeek DNS query analysis and HTTP request monitoring",
            "source:zeek AND (zeek_log_type:dns OR zeek_log_type:http) AND NOT source:enriched",
            [
                ("nw-vis-dns-over-time", 0, 0, 24, 12),
                ("nw-vis-http-over-time", 24, 0, 24, 12),
                ("nw-vis-dns-queries", 0, 12, 24, 12),
                ("nw-vis-http-hosts", 24, 12, 24, 12),
                ("nw-vis-dns-qtype", 0, 24, 16, 10),
                ("nw-vis-dns-rcode", 16, 24, 16, 10),
                ("nw-vis-http-methods", 32, 24, 16, 10),
                ("nw-vis-http-status", 0, 34, 48, 10),
            ],
        ),
        make_dashboard(
            "netwatcher-operations",
            "NetWatcher Operations",
            "Pipeline health: event rates by source, agent, and hostname",
            "NOT source:enriched",
            [
                ("nw-vis-ops-by-source", 0, 0, 48, 14),
                ("nw-vis-ops-by-agent", 0, 14, 24, 12),
                ("nw-vis-ops-by-host", 24, 14, 24, 12),
                ("nw-vis-ops-zeek-types", 0, 26, 48, 10),
            ],
        ),
    ]


def main() -> None:
    objects: list[dict[str, Any]] = [index_pattern()]
    objects.extend(build_visualizations())
    objects.extend(build_dashboards())

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w", encoding="utf-8") as handle:
        for obj in objects:
            handle.write(json.dumps(obj, separators=(",", ":")))
            handle.write("\n")

    print(f"Wrote {len(objects)} saved objects to {OUTPUT}")


if __name__ == "__main__":
    main()
