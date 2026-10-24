# File: dashboards/kibana/create_dashboard.py
# Purpose: Creates the complete SHIELD network security dashboard and its visualizations.

import json
import sys

import requests

from packages.config.settings import settings
from packages.schemas.network import LOGS_INDEX, RESULTS_INDEX


KIBANA = settings.kibana_url

HEADERS = {
    "kbn-xsrf": "true",
    "Content-Type": "application/json",
}

LOGS_VIEW = "75ce9249-fc92-48f3-87a9-29e4f25787d0"
ML_VIEW = "cabb1875-67ae-4343-ad04-bac763cfecb0"

DASHBOARD_ID = "shield-live-traffic"
DASHBOARD_TITLE = "SHIELD Security Dashboard"


def _upsert_data_view(view_id: str, title: str, name: str) -> str:
    """Create or update a Kibana data view."""

    payload = {
        "data_view": {
            "id": view_id,
            "title": title,
            "name": name,
            "timeFieldName": "@timestamp",
            "allowNoIndex": True,
        },
        "override": True,
    }

    response = requests.post(
        f"{KIBANA}/api/data_views/data_view",
        headers=HEADERS,
        json=payload,
        timeout=20,
    )

    if response.status_code not in (200, 409):
        response.raise_for_status()

    if response.status_code == 200:
        return response.json()["data_view"]["id"]

    return view_id


def ensure_data_views() -> tuple[str, str]:
    """Ensure the SHIELD Elasticsearch data views exist."""

    logs_id = _upsert_data_view(
        LOGS_VIEW,
        f"{LOGS_INDEX}*",
        "Live packets",
    )

    ml_id = _upsert_data_view(
        ML_VIEW,
        f"{RESULTS_INDEX}*",
        "Anomaly results",
    )

    requests.post(
        f"{KIBANA}/api/data_views/default",
        headers=HEADERS,
        json={
            "data_view_id": logs_id,
            "force": True,
        },
        timeout=15,
    )

    return logs_id, ml_id


def _context_url(index: str, aggregations: dict) -> dict:
    """Build a Vega Elasticsearch query using the dashboard time/filter context."""

    return {
        "%context%": True,
        "%timefield%": "@timestamp",
        "index": index,
        "body": {
            "size": 0,
            "aggs": aggregations,
        },
    }


def _filtered_url(index: str, query: dict, size: int = 500) -> dict:
    """Build a Vega Elasticsearch query with an explicit filter."""

    return {
        "index": index,
        "body": {
            "size": size,
            "query": {
                "bool": {
                    "filter": [
                        {
                            "range": {
                                "@timestamp": {
                                    "%timefilter%": True,
                                }
                            }
                        },
                        "%dashboard_context-filter_clause%",
                        query,
                    ]
                }
            },
            "sort": [
                {
                    "@timestamp": {
                        "order": "asc",
                    }
                }
            ],
        },
    }


def _save_visualization(
    visualization_id: str,
    title: str,
    spec: dict,
    description: str,
) -> None:
    """Create or replace a Kibana Vega visualization."""

    vis_state = {
        "title": title,
        "type": "vega",
        "aggs": [],
        "params": {
            "spec": json.dumps(
                spec,
                separators=(",", ":"),
            ),
        },
    }

    payload = {
        "attributes": {
            "title": title,
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "description": description,
            "version": 1,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps(
                    {
                        "query": {
                            "query": "",
                            "language": "kuery",
                        },
                        "filter": [],
                    }
                ),
            },
        },
        "references": [],
    }

    response = requests.post(
        f"{KIBANA}/api/saved_objects/visualization/"
        f"{visualization_id}?overwrite=true",
        headers=HEADERS,
        json=payload,
        timeout=30,
    )

    response.raise_for_status()


def traffic_packets_spec() -> dict:
    return {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "title": "Network packets over time",
        "data": {
            "url": _context_url(
                f"{LOGS_INDEX}*",
                {
                    "traffic": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "fixed_interval": "10s",
                            "min_doc_count": 0,
                        }
                    }
                },
            ),
            "format": {
                "property": "aggregations.traffic.buckets",
            },
        },
        "transform": [
            {
                "calculate": "toDate(datum.key)",
                "as": "time",
            },
        ],
        "mark": {
            "type": "line",
            "point": True,
            "tooltip": True,
        },
        "encoding": {
            "x": {
                "field": "time",
                "type": "temporal",
                "title": "Time",
            },
            "y": {
                "field": "doc_count",
                "type": "quantitative",
                "title": "Packets",
            },
            "tooltip": [
                {
                    "field": "time",
                    "type": "temporal",
                    "title": "Time",
                },
                {
                    "field": "doc_count",
                    "type": "quantitative",
                    "title": "Packets",
                },
            ],
        },
    }


def traffic_bytes_spec() -> dict:
    return {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "title": "Traffic volume",
        "data": {
            "url": _context_url(
                f"{LOGS_INDEX}*",
                {
                    "traffic": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "fixed_interval": "10s",
                            "min_doc_count": 0,
                        },
                        "aggs": {
                            "bytes": {
                                "sum": {
                                    "field": "packet_size",
                            }
                            }
                        },
                    }
                },
            ),
            "format": {
                "property": "aggregations.traffic.buckets",
            },
        },
        "transform": [
            {
                "calculate": "toDate(datum.key)",
                "as": "time",
            },
            {
                "calculate": "datum.bytes.value",
                "as": "bytes",
            },
        ],
        "mark": {
            "type": "area",
            "line": True,
            "tooltip": True,
        },
        "encoding": {
            "x": {
                "field": "time",
                "type": "temporal",
                "title": "Time",
            },
            "y": {
                "field": "bytes",
                "type": "quantitative",
                "title": "Bytes",
            },
            "tooltip": [
                {
                    "field": "time",
                    "type": "temporal",
                    "title": "Time",
                },
                {
                    "field": "bytes",
                    "type": "quantitative",
                    "title": "Bytes",
                },
            ],
        },
    }


def protocol_spec() -> dict:
    return {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "title": "Protocol breakdown",
        "data": {
            "url": _context_url(
                f"{LOGS_INDEX}*",
                {
                    "protocols": {
                        "terms": {
                            "field": "protocol.keyword",
                            "size": 10,
                        }
                    }
                },
            ),
            "format": {
                "property": "aggregations.protocols.buckets",
            },
        },
        "mark": {
            "type": "bar",
            "tooltip": True,
        },
        "encoding": {
            "x": {
                "field": "key",
                "type": "nominal",
                "title": "Protocol",
            },
            "y": {
                "field": "doc_count",
                "type": "quantitative",
                "title": "Packets",
            },
            "tooltip": [
                {
                    "field": "key",
                    "type": "nominal",
                    "title": "Protocol",
                },
                {
                    "field": "doc_count",
                    "type": "quantitative",
                    "title": "Packets",
                },
            ],
        },
    }


def destination_ports_spec() -> dict:
    return {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "title": "Top destination ports",
        "data": {
            "url": _context_url(
                f"{LOGS_INDEX}*",
                {
                    "ports": {
                        "terms": {
                            "field": "dst_port",
                            "size": 15,
                        }
                    }
                },
            ),
            "format": {
                "property": "aggregations.ports.buckets",
            },
        },
        "mark": {
            "type": "bar",
            "tooltip": True,
        },
        "encoding": {
            "y": {
                "field": "key",
                "type": "nominal",
                "sort": "-x",
                "title": "Destination port",
            },
            "x": {
                "field": "doc_count",
                "type": "quantitative",
                "title": "Packets",
            },
            "tooltip": [
                {
                    "field": "key",
                    "type": "nominal",
                    "title": "Port",
                },
                {
                    "field": "doc_count",
                    "type": "quantitative",
                    "title": "Packets",
                },
            ],
        },
    }


def destination_ips_spec() -> dict:
    return {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "title": "Top destination IPs",
        "data": {
            "url": _context_url(
                f"{LOGS_INDEX}*",
                {
                    "ips": {
                        "terms": {
                            "field": "dst_ip.keyword",
                            "size": 15,
                        }
                    }
                },
            ),
            "format": {
                "property": "aggregations.ips.buckets",
            },
        },
        "mark": {
            "type": "bar",
            "tooltip": True,
        },
        "encoding": {
            "y": {
                "field": "key",
                "type": "nominal",
                "sort": "-x",
                "title": "Destination IP",
            },
            "x": {
                "field": "doc_count",
                "type": "quantitative",
                "title": "Packets",
            },
            "tooltip": [
                {
                    "field": "key",
                    "type": "nominal",
                    "title": "Destination IP",
                },
                {
                    "field": "doc_count",
                    "type": "quantitative",
                    "title": "Packets",
                },
            ],
        },
    }


def detector_traffic_spec() -> dict:
    return {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "title": "Detection activity — normal traffic vs anomalies",
        "data": {
            "url": {
                "index": f"{RESULTS_INDEX}*",
                "body": {
                    "size": 500,
                    "query": {
                        "bool": {
                            "filter": [
                                {
                                    "range": {
                                        "@timestamp": {
                                            "%timefilter%": True,
                                        }
                                    }
                                },
                                "%dashboard_context-filter_clause%",
                            ]
                        }
                    },
                    "sort": [
                        {
                            "@timestamp": {
                                "order": "asc",
                            }
                        }
                    ],
                },
            },
            "format": {
                "property": "hits.hits",
            },
        },
        "transform": [
            {
                "calculate": "datum._source['@timestamp']",
                "as": "time",
            },
            {
                "calculate": "datum._source.packets",
                "as": "packets",
            },
            {
                "calculate": "datum._source.anomaly_score",
                "as": "score",
            },
            {
                "calculate": "datum._source.threshold",
                "as": "threshold",
            },
            {
                "calculate": "datum._source.status",
                "as": "status",
            },
            {
                "calculate": "datum._source.reason",
                "as": "reason",
            },
            {
                "calculate": "datum._source.unique_dst_ports",
                "as": "ports",
            },
            {
                "calculate": "datum._source.unique_dst_ips",
                "as": "unique_ips",
            },
            {
                "calculate": "datum._source.sample_src_ip",
                "as": "src_ip",
            },
            {
                "calculate": "datum._source.sample_dst_ip",
                "as": "dst_ip",
            },
        ],
        "mark": {
            "type": "line",
            "point": True,
            "tooltip": True,
        },
        "encoding": {
            "x": {
                "field": "time",
                "type": "temporal",
                "title": "Detection window",
            },
            "y": {
                "field": "packets",
                "type": "quantitative",
                "title": "Packets in 10-second window",
            },
            "color": {
                "field": "status",
                "type": "nominal",
                "title": "Detection",
            },
            "tooltip": [
                {
                    "field": "time",
                    "type": "temporal",
                    "title": "Window",
                },
                {
                    "field": "status",
                    "type": "nominal",
                    "title": "Status",
                },
                {
                    "field": "packets",
                    "type": "quantitative",
                    "title": "Packets",
                },
                {
                    "field": "score",
                    "type": "quantitative",
                    "title": "Anomaly score",
                    "format": ".4f",
                },
                {
                    "field": "threshold",
                    "type": "quantitative",
                    "title": "Threshold",
                    "format": ".4f",
                },
                {
                    "field": "ports",
                    "type": "quantitative",
                    "title": "Unique destination ports",
                },
                {
                    "field": "unique_ips",
                    "type": "quantitative",
                    "title": "Unique destination IPs",
                },
                {
                    "field": "reason",
                    "type": "nominal",
                    "title": "Reason",
                },
                {
                    "field": "src_ip",
                    "type": "nominal",
                    "title": "Source IP",
                },
                {
                    "field": "dst_ip",
                    "type": "nominal",
                    "title": "Destination IP",
                },
            ],
        },
    }


def anomaly_reasons_spec() -> dict:
    return {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "title": "Why SHIELD detected anomalies",
        "data": {
            "url": _filtered_url(
                f"{RESULTS_INDEX}*",
                {
                    "term": {
                        "anomaly": -1,
                    }
                },
                size=0,
            ),
            "format": {
                "property": "aggregations.reasons.buckets",
            },
        },
        "mark": {
            "type": "bar",
            "tooltip": True,
        },
        "encoding": {
            "y": {
                "field": "key",
                "type": "nominal",
                "sort": "-x",
                "title": "Detection reason",
            },
            "x": {
                "field": "doc_count",
                "type": "quantitative",
                "title": "Occurrences",
            },
            "tooltip": [
                {
                    "field": "key",
                    "type": "nominal",
                    "title": "Reason",
                },
                {
                    "field": "doc_count",
                    "type": "quantitative",
                    "title": "Occurrences",
                },
            ],
        },
    }


def normal_vs_anomaly_spec() -> dict:
    return {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "title": "Detection results",
        "data": {
            "url": _context_url(
                f"{RESULTS_INDEX}*",
                {
                    "status": {
                        "terms": {
                            "field": "status.keyword",
                            "size": 5,
                        }
                    }
                },
            ),
            "format": {
                "property": "aggregations.status.buckets",
            },
        },
        "mark": {
            "type": "arc",
            "tooltip": True,
        },
        "encoding": {
            "theta": {
                "field": "doc_count",
                "type": "quantitative",
            },
            "color": {
                "field": "key",
                "type": "nominal",
                "title": "Status",
            },
            "tooltip": [
                {
                    "field": "key",
                    "type": "nominal",
                    "title": "Status",
                },
                {
                    "field": "doc_count",
                    "type": "quantitative",
                    "title": "Windows",
                },
            ],
        },
    }


def build_visualizations() -> list[tuple[str, str, dict, str]]:
    """Return all SHIELD dashboard visualizations."""

    return [
        (
            "shield-traffic-packets",
            "SHIELD — Network packets",
            traffic_packets_spec(),
            "Number of captured packets in each 10-second period.",
        ),
        (
            "shield-traffic-bytes",
            "SHIELD — Traffic volume",
            traffic_bytes_spec(),
            "Total packet bytes captured over time.",
        ),
        (
            "shield-protocol-breakdown",
            "SHIELD — Protocol breakdown",
            protocol_spec(),
            "Distribution of observed network protocols.",
        ),
        (
            "shield-destination-ports",
            "SHIELD — Top destination ports",
            destination_ports_spec(),
            "Most frequently observed destination ports.",
        ),
        (
            "shield-destination-ips",
            "SHIELD — Top destination IPs",
            destination_ips_spec(),
            "Most frequently observed destination IP addresses.",
        ),
        (
            "shield-detector-traffic",
            "SHIELD — Detection activity",
            detector_traffic_spec(),
            "Shows normal and anomalous traffic windows with detailed hover information.",
        ),
        (
            "shield-anomaly-reasons",
            "SHIELD — Anomaly reasons",
            anomaly_reasons_spec(),
            "Breakdown of why the detector marked traffic as anomalous.",
        ),
        (
            "shield-normal-vs-anomaly",
            "SHIELD — Detection results",
            normal_vs_anomaly_spec(),
            "Normal versus anomalous detection windows.",
        ),
    ]


def build_dashboard_panels() -> list[dict]:
    """Create the dashboard grid layout."""

    # layouts = [
    #     (0, 0, 24, 8),
    #     (0, 8, 24, 8),
    #     (0, 16, 12, 8),
    #     (12, 16, 12, 8),
    #     (0, 24, 12, 9),
    #     (12, 24, 12, 9),
    #     (0, 33, 12, 8),
    #     (12, 33, 12, 8),
    # ]
    
    layouts = [
        (0, 0, 48, 8),
        (0, 8, 48, 8),
        (0, 16, 24, 8),
        (24, 16, 24, 8),
        (0, 24, 24, 9),
        (24, 24, 24, 9),
        (0, 33, 24, 8),
        (24, 33, 24, 8),
    ]

    panels = []

    for index, (x, y, width, height) in enumerate(layouts):
        panel_id = str(index + 1)

        panels.append(
            {
                "version": "8.12.0",
                "type": "visualization",
                "gridData": {
                    "x": x,
                    "y": y,
                    "w": width,
                    "h": height,
                    "i": panel_id,
                },
                "panelIndex": panel_id,
                "embeddableConfig": {},
                "panelRefName": f"panel_{index}",
            }
        )

    return panels


def create_dashboard() -> None:
    """Create or replace the SHIELD dashboard."""

    visualizations = build_visualizations()

    for visualization_id, title, spec, description in visualizations:
        print(f"Creating visualization: {title}")
        _save_visualization(
            visualization_id,
            title,
            spec,
            description,
        )

    references = [
        {
            "id": visualization_id,
            "name": f"panel_{index}",
            "type": "visualization",
        }
        for index, (
            visualization_id,
            _title,
            _spec,
            _description,
        ) in enumerate(visualizations)
    ]

    dashboard_attributes = {
        "title": DASHBOARD_TITLE,
        "description": (
            "SHIELD live network telemetry, anomaly detection, "
            "and security analysis dashboard."
        ),
        "hits": 0,
        "version": 1,
        "timeRestore": True,
        "timeFrom": "now-1h",
        "timeTo": "now",
        "refreshInterval": {
            "pause": False,
            "value": 10000,
        },
        "optionsJSON": json.dumps(
            {
                "darkTheme": False,
                "hidePanelTitles": False,
                "useMargins": True,
            }
        ),
        "panelsJSON": json.dumps(
            build_dashboard_panels(),
            separators=(",", ":"),
        ),
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps(
                {
                    "query": {
                        "query": "",
                        "language": "kuery",
                    },
                    "filter": [],
                }
            )
        },
    }

    payload = {
        "attributes": dashboard_attributes,
        "references": references,
    }

    response = requests.post(
        f"{KIBANA}/api/saved_objects/dashboard/"
        f"{DASHBOARD_ID}?overwrite=true",
        headers=HEADERS,
        json=payload,
        timeout=30,
    )

    response.raise_for_status()

    print()
    print("SHIELD dashboard created successfully.")
    print(
        "Open:"
        f" {KIBANA}/app/dashboards#/view/{DASHBOARD_ID}"
    )


def main() -> None:
    """Create the SHIELD Kibana dashboard."""

    try:
        requests.get(
            f"{KIBANA}/api/status",
            timeout=8,
        ).raise_for_status()

    except requests.RequestException as exc:
        print(f"Kibana is not reachable at {KIBANA}: {exc}")
        print("Start it with: docker compose up -d")
        sys.exit(1)

    ensure_data_views()
    create_dashboard()


if __name__ == "__main__":
    main()
