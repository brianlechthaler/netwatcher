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


def sum_agg(field: str, agg_id: str = "1", label: str = "") -> dict[str, Any]:
    params: dict[str, Any] = {"field": field}
    if label:
        params["customLabel"] = label
    return {
        "id": agg_id,
        "enabled": True,
        "type": "sum",
        "schema": "metric",
        "params": params,
    }


def cardinality_agg(
    field: str, agg_id: str = "1", label: str = ""
) -> dict[str, Any]:
    params: dict[str, Any] = {"field": field}
    if label:
        params["customLabel"] = label
    return {
        "id": agg_id,
        "enabled": True,
        "type": "cardinality",
        "schema": "metric",
        "params": params,
    }


def multi_metric_params(font_size: int = 22) -> dict[str, Any]:
    return {
        "type": "metric",
        "addTooltip": True,
        "addLegend": False,
        "metric": {
            "percentageMode": False,
            "useRanges": False,
            "colorSchema": "Yellow to Red",
            "metricColorMode": "Labels",
            "colorsRange": [
                {"from": 1, "to": 10},
                {"from": 11, "to": 100},
                {"from": 101, "to": 1000},
                {"from": 1001, "to": 10000},
            ],
            "labels": {"show": True},
            "invertColors": False,
            "style": {
                "bgFill": "#000",
                "bgColor": False,
                "labelColor": False,
                "subText": "",
                "fontSize": font_size,
            },
        },
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
    panels: list[tuple[str, int, int, int, int, str]],
) -> dict[str, Any]:
    panel_objects: list[dict[str, Any]] = []
    references: list[dict[str, Any]] = [
        {
            "id": INDEX_PATTERN_ID,
            "name": "kibanaSavedObjectMeta:indexPattern:netwatcher-index-pattern",
            "type": "index-pattern",
        }
    ]

    for index, (obj_id, x, y, w, h, panel_type) in enumerate(panels, start=1):
        panel_ref = f"panel_{index}"
        panel_objects.append(
            {
                "version": CORE_MIGRATION,
                "type": panel_type,
                "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(index)},
                "panelIndex": str(index),
                "embeddableConfig": {"title": obj_id},
                "panelRefName": panel_ref,
            }
        )
        references.append({"id": obj_id, "name": panel_ref, "type": panel_type})

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


def make_search(
    search_id: str,
    title: str,
    columns: list[str],
    query: str,
) -> dict[str, Any]:
    return saved_object(
        search_id,
        "search",
        {
            "title": title,
            "columns": columns,
            "sort": [["timestamp", "desc"]],
            "kibanaSavedObjectMeta": {"searchSourceJSON": search_source(query)},
        },
        [
            {
                "id": INDEX_PATTERN_ID,
                "name": f"kibanaSavedObjectMeta:indexPattern:{INDEX_PATTERN_ID}",
                "type": "index-pattern",
            }
        ],
        "8.0.0",
    )


def panel(
    obj_id: str, x: int, y: int, w: int, h: int, panel_type: str = "visualization"
) -> tuple[str, int, int, int, int, str]:
    return (obj_id, x, y, w, h, panel_type)


def build_p0f_visualizations(p0f_filter: str) -> list[dict[str, Any]]:
    p0f_os = f'{p0f_filter} AND raw.detail : "os="'
    p0f_link = f'{p0f_filter} AND raw.detail : "link="'
    return [
        make_visualization(
            "nw-vis-p0f-summary",
            "p0f Observation Summary",
            "metric",
            multi_metric_params(),
            [
                {**count_agg("1"), "params": {"customLabel": "Observations"}},
                cardinality_agg(kw("raw.src_ip"), "2", "Unique Src IPs"),
                cardinality_agg(kw("raw.dst_ip"), "3", "Unique Dst IPs"),
                cardinality_agg(kw("raw.detail"), "4", "Unique Details"),
            ],
            p0f_filter,
        ),
        make_visualization(
            "nw-vis-p0f-over-time",
            "p0f Events Over Time",
            "histogram",
            histogram_params(),
            [count_agg(), date_histogram_agg()],
            p0f_filter,
        ),
        make_visualization(
            "nw-vis-p0f-over-time-by-link",
            "p0f Events by Link Type",
            "histogram",
            histogram_params(stacked=True),
            [
                count_agg(),
                date_histogram_agg(agg_id="2"),
                terms_agg(kw("raw.link"), 8, schema="group", agg_id="3"),
            ],
            p0f_filter,
        ),
        make_visualization(
            "nw-vis-p0f-os-dist",
            "p0f OS Distribution",
            "pie",
            pie_params(),
            [count_agg(), terms_agg(kw("raw.detail"), 12)],
            p0f_os,
        ),
        make_visualization(
            "nw-vis-p0f-link-dist",
            "p0f Link Types",
            "pie",
            pie_params(donut=False),
            [count_agg(), terms_agg(kw("raw.detail"), 10)],
            p0f_link,
        ),
        make_visualization(
            "nw-vis-p0f-detail",
            "OS / Fingerprint Detail",
            "horizontal_bar",
            horizontal_bar_params(),
            [count_agg(), terms_agg(kw("raw.detail"), 15)],
            p0f_os,
        ),
        make_visualization(
            "nw-vis-p0f-link-bar",
            "Link Type Breakdown",
            "horizontal_bar",
            horizontal_bar_params(),
            [count_agg(), terms_agg(kw("raw.link"), 10)],
            p0f_filter,
        ),
        make_visualization(
            "nw-vis-p0f-mod",
            "Detection Mode",
            "pie",
            pie_params(donut=False),
            [count_agg(), terms_agg(kw("raw.mod"), 8)],
            p0f_filter,
        ),
        make_visualization(
            "nw-vis-p0f-src",
            "Top p0f Source IPs",
            "table",
            table_params(15),
            [count_agg(), terms_agg(kw("raw.src_ip"), 15, "bucket")],
            p0f_filter,
        ),
        make_visualization(
            "nw-vis-p0f-dst",
            "Top p0f Destination IPs",
            "table",
            table_params(15),
            [count_agg(), terms_agg(kw("raw.dst_ip"), 15, "bucket")],
            p0f_filter,
        ),
        make_visualization(
            "nw-vis-p0f-src-dst-detail",
            "Source IP / Fingerprint Detail",
            "table",
            table_params(15),
            [
                count_agg(),
                terms_agg(kw("raw.src_ip"), 10, "bucket", agg_id="2"),
                terms_agg(kw("raw.detail"), 5, "bucket", agg_id="3", order_by="1"),
            ],
            p0f_os,
        ),
        make_search(
            "nw-search-p0f-logs",
            "p0f Logs",
            ["timestamp", "raw.mod", "raw.src_ip", "raw.dst_ip", "raw.link", "raw.detail"],
            p0f_filter,
        ),
        make_visualization(
            "nw-vis-p0f-by-agent",
            "p0f Events by Agent",
            "pie",
            pie_params(donut=False),
            [count_agg(), terms_agg("agent_id", 8)],
            p0f_filter,
        ),
        make_visualization(
            "nw-vis-p0f-by-host",
            "p0f Events by Hostname",
            "table",
            table_params(10),
            [count_agg(), terms_agg("hostname", 10, "bucket")],
            p0f_filter,
        ),
    ]


def build_fatt_visualizations(fatt_filter: str) -> list[dict[str, Any]]:
    fatt_tls = f"{fatt_filter} AND raw.protocol:tls"
    fatt_ssh = f"{fatt_filter} AND raw.protocol:ssh"
    fatt_http = f"{fatt_filter} AND raw.protocol:http"
    return [
        make_visualization(
            "nw-vis-fatt-summary",
            "Fatt Fingerprint Summary",
            "metric",
            multi_metric_params(),
            [
                {**count_agg("1"), "params": {"customLabel": "Fingerprints"}},
                cardinality_agg(kw("raw.sourceIp"), "2", "Unique Src IPs"),
                cardinality_agg(kw("raw.tls.ja3s"), "3", "Unique JA3S"),
                cardinality_agg(kw("raw.tls.ja3"), "4", "Unique JA3"),
                cardinality_agg(kw("raw.ssh.hassh"), "5", "Unique SSH HASSH"),
                cardinality_agg(kw("raw.http.clientHeaderHash"), "6", "Unique HTTP Hashes"),
            ],
            fatt_filter,
        ),
        make_visualization(
            "nw-vis-fatt-over-time",
            "Fatt Events Over Time",
            "histogram",
            histogram_params(),
            [count_agg(), date_histogram_agg()],
            fatt_filter,
        ),
        make_visualization(
            "nw-vis-fatt-over-time-by-proto",
            "Fatt Events by Protocol",
            "histogram",
            histogram_params(stacked=True),
            [
                count_agg(),
                date_histogram_agg(agg_id="2"),
                terms_agg(kw("raw.protocol"), 6, schema="group", agg_id="3"),
            ],
            fatt_filter,
        ),
        make_visualization(
            "nw-vis-fatt-protocol",
            "Protocol Split",
            "pie",
            pie_params(),
            [count_agg(), terms_agg(kw("raw.protocol"), 8)],
            fatt_filter,
        ),
        make_visualization(
            "nw-vis-fatt-ja3s",
            "Top TLS JA3S (Server)",
            "table",
            table_params(15),
            [count_agg(), terms_agg(kw("raw.tls.ja3s"), 15, "bucket")],
            fatt_tls,
        ),
        make_visualization(
            "nw-vis-fatt-ja3",
            "Top TLS JA3 (Client)",
            "table",
            table_params(15),
            [count_agg(), terms_agg(kw("raw.tls.ja3"), 15, "bucket")],
            fatt_tls,
        ),
        make_visualization(
            "nw-vis-fatt-ip-ja3s",
            "Source IP / JA3S",
            "pie",
            pie_params(donut=False),
            [
                count_agg(),
                terms_agg(kw("raw.sourceIp"), 10, "segment", "2"),
                terms_agg(kw("raw.tls.ja3s"), 8, "segment", "3"),
            ],
            fatt_tls,
        ),
        make_visualization(
            "nw-vis-fatt-ssh-hassh",
            "Top SSH HASSH",
            "table",
            table_params(12),
            [count_agg(), terms_agg(kw("raw.ssh.hassh"), 12, "bucket")],
            fatt_ssh,
        ),
        make_visualization(
            "nw-vis-fatt-ssh-client",
            "Top SSH Clients",
            "table",
            table_params(12),
            [count_agg(), terms_agg(kw("raw.ssh.client"), 12, "bucket")],
            fatt_ssh,
        ),
        make_visualization(
            "nw-vis-fatt-ip-hassh",
            "Source IP / SSH HASSH",
            "pie",
            pie_params(donut=False),
            [
                count_agg(),
                terms_agg(kw("raw.sourceIp"), 10, "segment", "2"),
                terms_agg(kw("raw.ssh.hassh"), 8, "segment", "3"),
            ],
            fatt_ssh,
        ),
        make_visualization(
            "nw-vis-fatt-http-methods",
            "HTTP Request Methods",
            "horizontal_bar",
            horizontal_bar_params(),
            [count_agg(), terms_agg(kw("raw.http.requestMethod"), 10)],
            fatt_http,
        ),
        make_visualization(
            "nw-vis-fatt-http-ua",
            "HTTP User Agents",
            "table",
            table_params(12),
            [count_agg(), terms_agg(kw("raw.http.userAgent"), 12, "bucket")],
            fatt_http,
        ),
        make_visualization(
            "nw-vis-fatt-http-uri",
            "HTTP Request URIs",
            "table",
            table_params(12),
            [count_agg(), terms_agg(kw("raw.http.requestURI"), 12, "bucket")],
            fatt_http,
        ),
        make_visualization(
            "nw-vis-fatt-http-hash",
            "HTTP Client Header Hashes",
            "table",
            table_params(12),
            [count_agg(), terms_agg(kw("raw.http.clientHeaderHash"), 12, "bucket")],
            fatt_http,
        ),
        make_visualization(
            "nw-vis-fatt-ip-http-hash",
            "Source IP / HTTP Header Hash",
            "pie",
            pie_params(donut=False),
            [
                count_agg(),
                terms_agg(kw("raw.sourceIp"), 10, "segment", "2"),
                terms_agg(kw("raw.http.clientHeaderHash"), 8, "segment", "3"),
            ],
            fatt_http,
        ),
        make_visualization(
            "nw-vis-fatt-src",
            "Top Source IPs",
            "table",
            table_params(15),
            [count_agg(), terms_agg(kw("raw.sourceIp"), 15, "bucket")],
            fatt_filter,
        ),
        make_visualization(
            "nw-vis-fatt-dst",
            "Top Destination IPs",
            "table",
            table_params(15),
            [count_agg(), terms_agg(kw("raw.destinationIp"), 15, "bucket")],
            fatt_filter,
        ),
        make_search(
            "nw-search-fatt-logs",
            "Fatt Logs",
            [
                "timestamp",
                "raw.sourceIp",
                "raw.destinationIp",
                "raw.protocol",
                "raw.tls.ja3s",
                "raw.ssh.hassh",
            ],
            fatt_filter,
        ),
    ]


def build_traffic_visualizations(conn_filter: str) -> list[dict[str, Any]]:
    return [
        make_visualization(
            "nw-vis-traffic-summary",
            "Connection Summary",
            "metric",
            multi_metric_params(),
            [
                {**count_agg("1"), "params": {"customLabel": "Connections"}},
                cardinality_agg(kw("raw.id.orig_h"), "2", "Unique Src IPs"),
                cardinality_agg(kw("raw.id.resp_h"), "3", "Unique Dst IPs"),
                cardinality_agg(kw("raw.service"), "4", "Unique Services"),
                sum_agg("raw.orig_ip_bytes", "5", "Orig Bytes"),
                sum_agg("raw.resp_ip_bytes", "6", "Resp Bytes"),
            ],
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
            "nw-vis-conn-over-time-by-proto",
            "Connections by Protocol Over Time",
            "histogram",
            histogram_params(stacked=True),
            [
                count_agg(),
                date_histogram_agg(agg_id="2"),
                terms_agg(kw("raw.proto"), 8, schema="group", agg_id="3"),
            ],
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
            "nw-vis-top-src-ports",
            "Top Source Ports",
            "table",
            table_params(12),
            [count_agg(), terms_agg("raw.id.orig_p", 12, "bucket")],
            conn_filter,
        ),
        make_visualization(
            "nw-vis-top-dst-ports",
            "Top Destination Ports",
            "table",
            table_params(12),
            [count_agg(), terms_agg("raw.id.resp_p", 12, "bucket")],
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
        make_visualization(
            "nw-vis-traffic-by-hostname",
            "Events by Hostname",
            "table",
            table_params(12),
            [count_agg(), terms_agg("hostname", 12, "bucket")],
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
            "nw-vis-src-dst-pairs",
            "Source / Destination IP Pairs",
            "table",
            table_params(15),
            [
                count_agg(),
                terms_agg(kw("raw.id.orig_h"), 10, "bucket", agg_id="2"),
                terms_agg(kw("raw.id.resp_h"), 10, "bucket", agg_id="3", order_by="1"),
            ],
            conn_filter,
        ),
        make_search(
            "nw-search-conn-logs",
            "Zeek Conn Logs",
            [
                "timestamp",
                "agent_id",
                "raw.id.orig_h",
                "raw.id.resp_h",
                "raw.proto",
                "raw.service",
                "raw.conn_state",
            ],
            conn_filter,
        ),
    ]


def build_threat_visualizations(threat_filter: str) -> list[dict[str, Any]]:
    return [
        make_visualization(
            "nw-vis-threat-summary",
            "Threat Match Summary",
            "metric",
            multi_metric_params(),
            [
                {**count_agg("1"), "params": {"customLabel": "Matches"}},
                cardinality_agg("threat.indicator", "2", "Unique Indicators"),
                cardinality_agg(kw("raw.id.orig_h"), "3", "Unique Src IPs"),
                cardinality_agg("threat.categories", "4", "Unique Categories"),
                cardinality_agg("agent_id", "5", "Affected Agents"),
            ],
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
            "nw-vis-threat-over-time-by-severity",
            "Matches by Severity Over Time",
            "histogram",
            histogram_params(stacked=True),
            [
                count_agg(),
                date_histogram_agg(agg_id="2"),
                terms_agg("threat.severity", 6, schema="group", agg_id="3"),
            ],
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
            "nw-vis-threat-feeds",
            "Matches by Feed",
            "pie",
            pie_params(donut=False),
            [count_agg(), terms_agg("threat.feed", 6)],
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
            "nw-vis-threat-indicators",
            "Top Indicators",
            "table",
            table_params(15),
            [count_agg(), terms_agg("threat.indicator", 15, "bucket")],
            threat_filter,
        ),
        make_visualization(
            "nw-vis-threat-severity-category",
            "Severity / Category Matrix",
            "table",
            table_params(15),
            [
                count_agg(),
                terms_agg("threat.severity", 6, "bucket", agg_id="2"),
                terms_agg("threat.categories", 8, "bucket", agg_id="3", order_by="1"),
            ],
            threat_filter,
        ),
        make_visualization(
            "nw-vis-threat-agents",
            "Affected Capture Agents",
            "table",
            table_params(10),
            [count_agg(), terms_agg("agent_id", 10, "bucket")],
            threat_filter,
        ),
        make_visualization(
            "nw-vis-threat-hostnames",
            "Affected Hostnames",
            "table",
            table_params(10),
            [count_agg(), terms_agg("hostname", 10, "bucket")],
            threat_filter,
        ),
        make_visualization(
            "nw-vis-threat-src-ips",
            "Threat Source IPs",
            "table",
            table_params(12),
            [count_agg(), terms_agg(kw("raw.id.orig_h"), 12, "bucket")],
            threat_filter,
        ),
        make_visualization(
            "nw-vis-threat-dst-ips",
            "Threat Destination IPs",
            "table",
            table_params(12),
            [count_agg(), terms_agg(kw("raw.id.resp_h"), 12, "bucket")],
            threat_filter,
        ),
        make_search(
            "nw-search-threat-logs",
            "Threat Enrichment Logs",
            [
                "timestamp",
                "agent_id",
                "threat.severity",
                "threat.categories",
                "threat.indicator",
                "threat.feed",
                "raw.id.orig_h",
            ],
            threat_filter,
        ),
    ]


def build_dns_visualizations(dns_filter: str) -> list[dict[str, Any]]:
    return [
        make_visualization(
            "nw-vis-dns-summary",
            "DNS Query Summary",
            "metric",
            multi_metric_params(),
            [
                {**count_agg("1"), "params": {"customLabel": "Queries"}},
                cardinality_agg(kw("raw.query"), "2", "Unique Domains"),
                cardinality_agg(kw("raw.id.orig_h"), "3", "Unique Clients"),
                cardinality_agg(kw("raw.qtype_name"), "4", "Query Types"),
            ],
            dns_filter,
        ),
        make_visualization(
            "nw-vis-dns-over-time",
            "DNS Queries Over Time",
            "histogram",
            histogram_params(),
            [count_agg(), date_histogram_agg()],
            dns_filter,
        ),
        make_visualization(
            "nw-vis-dns-over-time-by-qtype",
            "DNS Queries by Type Over Time",
            "histogram",
            histogram_params(stacked=True),
            [
                count_agg(),
                date_histogram_agg(agg_id="2"),
                terms_agg(kw("raw.qtype_name"), 8, schema="group", agg_id="3"),
            ],
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
            "nw-vis-dns-top-src",
            "Top DNS Client IPs",
            "table",
            table_params(12),
            [count_agg(), terms_agg(kw("raw.id.orig_h"), 12, "bucket")],
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
            "nw-vis-dns-qclass",
            "DNS Query Classes",
            "pie",
            pie_params(donut=False),
            [count_agg(), terms_agg(kw("raw.qclass_name"), 8)],
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
        make_search(
            "nw-search-dns-logs",
            "Zeek DNS Logs",
            [
                "timestamp",
                "raw.id.orig_h",
                "raw.query",
                "raw.qtype_name",
                "raw.qclass_name",
                "raw.rcode_name",
            ],
            dns_filter,
        ),
    ]


def build_http_visualizations(http_filter: str) -> list[dict[str, Any]]:
    return [
        make_visualization(
            "nw-vis-http-summary",
            "HTTP Request Summary",
            "metric",
            multi_metric_params(),
            [
                {**count_agg("1"), "params": {"customLabel": "Requests"}},
                cardinality_agg(kw("raw.host"), "2", "Unique Hosts"),
                cardinality_agg(kw("raw.uri"), "3", "Unique URIs"),
                cardinality_agg(kw("raw.method"), "4", "Methods"),
            ],
            http_filter,
        ),
        make_visualization(
            "nw-vis-http-over-time",
            "HTTP Requests Over Time",
            "histogram",
            histogram_params(),
            [count_agg(), date_histogram_agg()],
            http_filter,
        ),
        make_visualization(
            "nw-vis-http-over-time-by-method",
            "HTTP Requests by Method Over Time",
            "histogram",
            histogram_params(stacked=True),
            [
                count_agg(),
                date_histogram_agg(agg_id="2"),
                terms_agg(kw("raw.method"), 8, schema="group", agg_id="3"),
            ],
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
            "nw-vis-http-uris",
            "Top HTTP URIs",
            "table",
            table_params(15),
            [count_agg(), terms_agg(kw("raw.uri"), 15, "bucket")],
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
        make_visualization(
            "nw-vis-http-status-table",
            "HTTP Status Detail",
            "table",
            table_params(12),
            [
                count_agg(),
                terms_agg("raw.status_code", 8, "bucket", agg_id="2"),
                terms_agg(kw("raw.status_msg"), 8, "bucket", agg_id="3", order_by="1"),
            ],
            http_filter,
        ),
        make_search(
            "nw-search-http-logs",
            "Zeek HTTP Logs",
            [
                "timestamp",
                "raw.id.orig_h",
                "raw.host",
                "raw.method",
                "raw.uri",
                "raw.status_code",
            ],
            http_filter,
        ),
    ]


def build_ssl_visualizations(ssl_filter: str) -> list[dict[str, Any]]:
    return [
        make_visualization(
            "nw-vis-ssl-summary",
            "SSL/TLS Session Summary",
            "metric",
            multi_metric_params(),
            [
                {**count_agg("1"), "params": {"customLabel": "Sessions"}},
                cardinality_agg(kw("raw.server_name"), "2", "Unique SNI"),
                cardinality_agg(kw("raw.cipher"), "3", "Ciphers"),
                cardinality_agg(kw("raw.version"), "4", "TLS Versions"),
            ],
            ssl_filter,
        ),
        make_visualization(
            "nw-vis-ssl-over-time",
            "SSL Sessions Over Time",
            "histogram",
            histogram_params(),
            [count_agg(), date_histogram_agg()],
            ssl_filter,
        ),
        make_visualization(
            "nw-vis-ssl-server-names",
            "Top TLS Server Names (SNI)",
            "table",
            table_params(15),
            [count_agg(), terms_agg(kw("raw.server_name"), 15, "bucket")],
            ssl_filter,
        ),
        make_visualization(
            "nw-vis-ssl-ciphers",
            "TLS Cipher Suites",
            "horizontal_bar",
            horizontal_bar_params(),
            [count_agg(), terms_agg(kw("raw.cipher"), 12)],
            ssl_filter,
        ),
        make_visualization(
            "nw-vis-ssl-versions",
            "TLS Versions",
            "pie",
            pie_params(),
            [count_agg(), terms_agg(kw("raw.version"), 8)],
            ssl_filter,
        ),
        make_visualization(
            "nw-vis-ssl-established",
            "TLS Session Established",
            "pie",
            pie_params(donut=False),
            [count_agg(), terms_agg("raw.established", 4)],
            ssl_filter,
        ),
        make_search(
            "nw-search-ssl-logs",
            "Zeek SSL Logs",
            [
                "timestamp",
                "raw.id.orig_h",
                "raw.id.resp_h",
                "raw.server_name",
                "raw.cipher",
                "raw.version",
            ],
            ssl_filter,
        ),
    ]


def build_ops_visualizations(ops_filter: str) -> list[dict[str, Any]]:
    zeek_filter = "source:zeek AND NOT source:enriched"
    return [
        make_visualization(
            "nw-vis-ops-summary",
            "Pipeline Event Summary",
            "metric",
            multi_metric_params(),
            [
                {**count_agg("1"), "params": {"customLabel": "Total Events"}},
                cardinality_agg("agent_id", "2", "Agents"),
                cardinality_agg("hostname", "3", "Hostnames"),
                cardinality_agg("source", "4", "Sources"),
            ],
            ops_filter,
        ),
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
            "nw-vis-ops-over-time-by-agent",
            "Events by Agent Over Time",
            "histogram",
            histogram_params(stacked=True),
            [
                count_agg(),
                date_histogram_agg(agg_id="2"),
                terms_agg("agent_id", 8, schema="group", agg_id="3"),
            ],
            ops_filter,
        ),
        make_visualization(
            "nw-vis-ops-source-pie",
            "Events by Source",
            "pie",
            pie_params(),
            [count_agg(), terms_agg("source", 8)],
            ops_filter,
        ),
        make_visualization(
            "nw-vis-ops-by-source-table",
            "Source Volume Breakdown",
            "table",
            table_params(10),
            [count_agg(), terms_agg("source", 10, "bucket")],
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
            pie_params(donut=False),
            [count_agg(), terms_agg("zeek_log_type", 10)],
            zeek_filter,
        ),
        make_search(
            "nw-search-ops-logs",
            "Pipeline Event Logs",
            ["timestamp", "source", "agent_id", "hostname", "zeek_log_type"],
            ops_filter,
        ),
    ]


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
        "raw.link": {"count": 1},
        "raw.mod": {"count": 1},
        "raw.protocol": {"count": 1},
        "raw.sourceIp": {"count": 1},
        "raw.destinationIp": {"count": 1},
        "raw.tls.ja3": {"count": 1},
        "raw.tls.ja3s": {"count": 1},
        "raw.ssh.hassh": {"count": 1},
        "raw.ssh.client": {"count": 1},
        "raw.http.userAgent": {"count": 1},
        "raw.http.requestMethod": {"count": 1},
        "raw.http.requestURI": {"count": 1},
        "raw.http.clientHeaderHash": {"count": 1},
        "raw.orig_ip_bytes": {"count": 1},
        "raw.resp_ip_bytes": {"count": 1},
        "raw.id.orig_p": {"count": 1},
        "raw.id.resp_p": {"count": 1},
        "raw.uri": {"count": 1},
        "raw.server_name": {"count": 1},
        "raw.cipher": {"count": 1},
        "raw.version": {"count": 1},
        "raw.qclass_name": {"count": 1},
        "raw.rcode_name": {"count": 1},
        "raw.status_msg": {"count": 1},
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
    ssl_filter = "source:zeek AND zeek_log_type:ssl AND NOT source:enriched"
    ops_filter = "NOT source:enriched"

    return (
        build_traffic_visualizations(conn_filter)
        + build_threat_visualizations(threat_filter)
        + build_p0f_visualizations(p0f_filter)
        + build_fatt_visualizations(fatt_filter)
        + build_dns_visualizations(dns_filter)
        + build_http_visualizations(http_filter)
        + build_ssl_visualizations(ssl_filter)
        + build_ops_visualizations(ops_filter)
    )


def build_dashboards() -> list[dict[str, Any]]:
    return [
        make_dashboard(
            "netwatcher-traffic-overview",
            "NetWatcher Traffic Overview",
            "Zeek connection volume, talkers, ports, and protocol breakdown (tpotce-style)",
            "source:zeek AND zeek_log_type:conn AND NOT source:enriched",
            [
                panel("nw-vis-traffic-summary", 0, 0, 48, 10),
                panel("nw-vis-conn-over-time", 0, 10, 24, 10),
                panel("nw-vis-conn-over-time-by-proto", 24, 10, 24, 10),
                panel("nw-vis-top-src-ips", 0, 20, 16, 12),
                panel("nw-vis-top-dst-ips", 16, 20, 16, 12),
                panel("nw-vis-top-src-ports", 32, 20, 16, 12),
                panel("nw-vis-top-dst-ports", 0, 32, 16, 12),
                panel("nw-vis-by-agent", 16, 32, 16, 12),
                panel("nw-vis-traffic-by-hostname", 32, 32, 16, 12),
                panel("nw-vis-proto-breakdown", 0, 44, 12, 10),
                panel("nw-vis-conn-state", 12, 44, 12, 10),
                panel("nw-vis-services", 24, 44, 12, 10),
                panel("nw-vis-src-dst-pairs", 36, 44, 12, 10),
                panel("nw-search-conn-logs", 0, 54, 48, 14, "search"),
            ],
        ),
        make_dashboard(
            "netwatcher-threat-intel",
            "NetWatcher Threat Intelligence",
            "Emerging Threats matches by severity, category, indicator, and endpoint (Suricata-style)",
            "source:enriched AND threat.matched:true",
            [
                panel("nw-vis-threat-summary", 0, 0, 48, 10),
                panel("nw-vis-threat-over-time", 0, 10, 48, 12),
                panel("nw-vis-threat-over-time-by-severity", 0, 22, 48, 12),
                panel("nw-vis-threat-severity", 0, 34, 16, 12),
                panel("nw-vis-threat-feeds", 16, 34, 16, 12),
                panel("nw-vis-threat-categories", 32, 34, 16, 12),
                panel("nw-vis-threat-indicators", 0, 46, 24, 12),
                panel("nw-vis-threat-severity-category", 24, 46, 24, 12),
                panel("nw-vis-threat-agents", 0, 58, 16, 10),
                panel("nw-vis-threat-hostnames", 16, 58, 16, 10),
                panel("nw-vis-threat-src-ips", 32, 58, 16, 10),
                panel("nw-vis-threat-dst-ips", 0, 68, 48, 10),
                panel("nw-search-threat-logs", 0, 78, 48, 14, "search"),
            ],
        ),
        make_dashboard(
            "netwatcher-p0f",
            "NetWatcher p0f Fingerprints",
            "OS and stack fingerprinting from passive p0f observations (tpotce-style detail)",
            "source:p0f AND NOT source:enriched",
            [
                panel("nw-vis-p0f-summary", 0, 0, 48, 8),
                panel("nw-vis-p0f-over-time", 0, 8, 24, 10),
                panel("nw-vis-p0f-over-time-by-link", 24, 8, 24, 10),
                panel("nw-vis-p0f-os-dist", 0, 18, 16, 12),
                panel("nw-vis-p0f-link-dist", 16, 18, 16, 12),
                panel("nw-vis-p0f-mod", 32, 18, 16, 12),
                panel("nw-vis-p0f-detail", 0, 30, 24, 12),
                panel("nw-vis-p0f-link-bar", 24, 30, 24, 12),
                panel("nw-vis-p0f-src", 0, 42, 16, 12),
                panel("nw-vis-p0f-dst", 16, 42, 16, 12),
                panel("nw-vis-p0f-by-agent", 32, 42, 16, 12),
                panel("nw-vis-p0f-src-dst-detail", 0, 54, 32, 12),
                panel("nw-vis-p0f-by-host", 32, 54, 16, 12),
                panel("nw-search-p0f-logs", 0, 66, 48, 14, "search"),
            ],
        ),
        make_dashboard(
            "netwatcher-fatt",
            "NetWatcher fatt TLS/SSH/HTTP",
            "TLS JA3, SSH HASSH, and HTTP fingerprints from fatt (tpotce-style detail)",
            "source:fatt AND NOT source:enriched",
            [
                panel("nw-vis-fatt-summary", 0, 0, 48, 10),
                panel("nw-vis-fatt-over-time", 0, 10, 24, 10),
                panel("nw-vis-fatt-over-time-by-proto", 24, 10, 24, 10),
                panel("nw-vis-fatt-protocol", 0, 20, 12, 10),
                panel("nw-vis-fatt-ja3s", 12, 20, 18, 12),
                panel("nw-vis-fatt-ja3", 30, 20, 18, 12),
                panel("nw-vis-fatt-ip-ja3s", 0, 32, 24, 12),
                panel("nw-vis-fatt-ssh-hassh", 24, 32, 12, 10),
                panel("nw-vis-fatt-ssh-client", 36, 32, 12, 10),
                panel("nw-vis-fatt-ip-hassh", 0, 44, 16, 12),
                panel("nw-vis-fatt-http-methods", 16, 44, 16, 10),
                panel("nw-vis-fatt-http-ua", 32, 44, 16, 10),
                panel("nw-vis-fatt-http-uri", 0, 56, 24, 10),
                panel("nw-vis-fatt-http-hash", 24, 56, 12, 10),
                panel("nw-vis-fatt-ip-http-hash", 36, 56, 12, 10),
                panel("nw-vis-fatt-src", 0, 66, 24, 10),
                panel("nw-vis-fatt-dst", 24, 66, 24, 10),
                panel("nw-search-fatt-logs", 0, 76, 48, 14, "search"),
            ],
        ),
        make_dashboard(
            "netwatcher-dns-http",
            "NetWatcher DNS, HTTP and SSL",
            "Zeek DNS, HTTP, and TLS/SSL analysis (NGINX/Suricata-style detail)",
            "source:zeek AND (zeek_log_type:dns OR zeek_log_type:http OR zeek_log_type:ssl) AND NOT source:enriched",
            [
                panel("nw-vis-dns-summary", 0, 0, 16, 8),
                panel("nw-vis-http-summary", 16, 0, 16, 8),
                panel("nw-vis-ssl-summary", 32, 0, 16, 8),
                panel("nw-vis-dns-over-time", 0, 8, 16, 10),
                panel("nw-vis-http-over-time", 16, 8, 16, 10),
                panel("nw-vis-ssl-over-time", 32, 8, 16, 10),
                panel("nw-vis-dns-queries", 0, 18, 16, 12),
                panel("nw-vis-http-hosts", 16, 18, 16, 12),
                panel("nw-vis-ssl-server-names", 32, 18, 16, 12),
                panel("nw-vis-dns-qtype", 0, 30, 12, 10),
                panel("nw-vis-dns-qclass", 12, 30, 12, 10),
                panel("nw-vis-http-methods", 24, 30, 12, 10),
                panel("nw-vis-http-status", 36, 30, 12, 10),
                panel("nw-vis-dns-top-src", 0, 40, 16, 10),
                panel("nw-vis-dns-rcode", 16, 40, 16, 10),
                panel("nw-vis-ssl-established", 32, 40, 16, 10),
                panel("nw-vis-http-uris", 0, 50, 24, 10),
                panel("nw-vis-ssl-ciphers", 24, 50, 12, 10),
                panel("nw-vis-ssl-versions", 36, 50, 12, 10),
                panel("nw-vis-dns-over-time-by-qtype", 0, 60, 16, 10),
                panel("nw-vis-http-over-time-by-method", 16, 60, 16, 10),
                panel("nw-vis-http-status-table", 32, 60, 16, 10),
                panel("nw-search-dns-logs", 0, 70, 16, 14, "search"),
                panel("nw-search-http-logs", 16, 70, 16, 14, "search"),
                panel("nw-search-ssl-logs", 32, 70, 16, 14, "search"),
            ],
        ),
        make_dashboard(
            "netwatcher-operations",
            "NetWatcher Operations",
            "Pipeline health: rates by source, agent, and hostname (tpotce honeypot overview style)",
            "NOT source:enriched",
            [
                panel("nw-vis-ops-summary", 0, 0, 48, 8),
                panel("nw-vis-ops-by-source", 0, 8, 48, 14),
                panel("nw-vis-ops-over-time-by-agent", 0, 22, 48, 12),
                panel("nw-vis-ops-source-pie", 0, 34, 16, 12),
                panel("nw-vis-ops-zeek-types", 16, 34, 16, 12),
                panel("nw-vis-ops-by-source-table", 32, 34, 16, 12),
                panel("nw-vis-ops-by-agent", 0, 46, 24, 12),
                panel("nw-vis-ops-by-host", 24, 46, 24, 12),
                panel("nw-search-ops-logs", 0, 58, 48, 14, "search"),
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
