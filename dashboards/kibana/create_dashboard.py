# File: dashboards/kibana/create_dashboard.py
# Purpose: Creates and updates SHIELD Kibana dashboards and visualizations.

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
DASHBOARD_TITLE = "SHIELD live traffic"

VIZ_DASHBOARD_ID = "shield-data-visualizer"
VIZ_DASHBOARD_TITLE = "SHIELD data visualizer"


def _upsert_data_view(view_id, title, name):
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


def ensure_data_views():
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


def main():
    try:
        requests.get(
            f"{KIBANA}/api/status",
            timeout=8,
        ).raise_for_status()

    except requests.RequestException as exc:
        print(f"Kibana is not reachable at {KIBANA}: {exc}")
        print("Start it with: docker compose up -d")
        sys.exit(1)

    logs_id, ml_id = ensure_data_views()

    print("Kibana is reachable.")
    print(f"Live packets data view: {logs_id}")
    print(f"Anomaly results data view: {ml_id}")


if __name__ == "__main__":
    main()