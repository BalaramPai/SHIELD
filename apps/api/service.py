# File: apps/api/service.py
# Purpose: Provides Elasticsearch-backed operations for the SHIELD API.

from elasticsearch import Elasticsearch

from apps.api.config import ELASTICSEARCH_URL
from packages.schemas.network import LOGS_INDEX, RESULTS_INDEX


class ShieldAPIService:
    def __init__(self):
        self.es = Elasticsearch(ELASTICSEARCH_URL)
        self.logs_index = LOGS_INDEX
        self.results_index = RESULTS_INDEX

    def get_current_status(self) -> dict | None:
        """Return the latest detector status."""
        try:
            response = self.es.get(
                index=self.results_index,
                id="current-status",
                ignore=[404],
            )
        except Exception:
            return None

        if not response.get("found"):
            return None

        return response["_source"]

    def get_recent_incidents(self, limit: int = 20) -> list[dict]:
        """Return the most recent anomalous detection results."""
        try:
            response = self.es.search(
                index=self.results_index,
                query={
                    "term": {
                        "anomaly": -1,
                    }
                },
                size=limit,
                sort=[
                    {
                        "@timestamp": {
                            "order": "desc",
                        }
                    }
                ],
            )
        except Exception:
            return []

        return [
            {
                "event_id": hit["_source"].get("event_id"),
                "timestamp": hit["_source"].get("@timestamp"),
                "status": hit["_source"].get("status"),
                "detector": hit["_source"].get("detector"),
                "anomaly_score": hit["_source"].get("anomaly_score"),
                "threshold": hit["_source"].get("threshold"),
                "reason": hit["_source"].get("reason"),
                "packets": hit["_source"].get("packets"),
                "unique_dst_ports": hit["_source"].get("unique_dst_ports"),
                "unique_dst_ips": hit["_source"].get("unique_dst_ips"),
            }
            for hit in response["hits"]["hits"]
        ]

    def get_incident(self, event_id: str) -> dict | None:
        """Return the complete detection result for one event."""
        try:
            response = self.es.get(
                index=self.results_index,
                id=event_id,
                ignore=[404],
            )
        except Exception:
            return None

        if not response.get("found"):
            return None

        return response["_source"]

    def search_events(
        self,
        limit: int = 50,
        src_ip: str | None = None,
        dst_ip: str | None = None,
        protocol: str | None = None,
        dst_port: int | None = None,
    ) -> list[dict]:
        """Search recent network telemetry using optional filters."""
        filters = []

        if src_ip:
            filters.append({"term": {"src_ip": src_ip}})

        if dst_ip:
            filters.append({"term": {"dst_ip": dst_ip}})

        if protocol:
            filters.append(
                {
                    "term": {
                        "protocol.keyword": protocol.upper(),
                    }
                }
            )

        if dst_port is not None:
            filters.append({"term": {"dst_port": dst_port}})

        query = {
            "bool": {
                "filter": filters,
            }
        }

        try:
            response = self.es.search(
                index=self.logs_index,
                query=query,
                size=limit,
                sort=[
                    {
                        "@timestamp": {
                            "order": "desc",
                        }
                    }
                ],
            )
        except Exception:
            return []

        return [hit["_source"] for hit in response["hits"]["hits"]]

    def get_devices(self, limit: int = 50) -> list[dict]:
        """Return recently observed source devices."""
        try:
            response = self.es.search(
                index=self.logs_index,
                size=0,
                aggs={
                    "devices": {
                        "terms": {
                            "field": "src_ip.keyword",
                            "size": limit,
                        }
                    }
                },
            )
        except Exception:
            return []

        buckets = response.get("aggregations", {}).get(
            "devices",
            {},
        ).get("buckets", [])

        return [
            {
                "ip_address": bucket["key"],
                "event_count": bucket["doc_count"],
            }
            for bucket in buckets
        ]

    def get_device_activity(
        self,
        ip_address: str,
        limit: int = 50,
    ) -> list[dict]:
        """Return recent network activity for a specific source IP."""
        try:
            response = self.es.search(
                index=self.logs_index,
                query={
                    "term": {
                        "src_ip": ip_address,
                    }
                },
                size=limit,
                sort=[
                    {
                        "@timestamp": {
                            "order": "desc",
                        }
                    }
                ],
            )
        except Exception:
            return []

        return [hit["_source"] for hit in response["hits"]["hits"]]

    def get_detector_status(self) -> dict:
        """Return basic information about the detection engine."""
        status = self.get_current_status()

        if status is None:
            return {
                "status": "not_ready",
                "message": "The detector has not produced a result yet.",
            }

        return {
            "status": "running",
            "latest_result": status,
        }