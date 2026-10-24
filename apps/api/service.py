
from datetime import datetime, timezone
from ipaddress import ip_address

from elasticsearch import Elasticsearch

from apps.api.config import ELASTICSEARCH_URL
from packages.schemas.network import LOGS_INDEX, RESULTS_INDEX


class ShieldAPIService:
    SENSOR_STALE_SECONDS = 120
    DETECTOR_STALE_SECONDS = 300

    def __init__(self):
        self.es = Elasticsearch(ELASTICSEARCH_URL)
        self.logs_index = LOGS_INDEX
        self.results_index = RESULTS_INDEX

    def _search(self, index, query, size=50, sort=None, aggs=None):
        try:
            kwargs = {
                "index": index,
                "query": query,
                "size": size,
                "track_total_hits": True,
            }
            if sort:
                kwargs["sort"] = sort
            if aggs:
                kwargs["aggs"] = aggs
            return self.es.search(**kwargs)
        except Exception:
            return None

    @staticmethod
    def _hits(response):
        if not response:
            return []
        return [hit["_source"] for hit in response.get("hits", {}).get("hits", [])]

    @staticmethod
    def _is_private_ip(value):
        try:
            return ip_address(str(value)).is_private
        except ValueError:
            return False

    @staticmethod
    def _parse_timestamp(value):
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except (TypeError, ValueError):
            return None

    @classmethod
    def _freshness(cls, timestamp, stale_after_seconds):
        parsed = cls._parse_timestamp(timestamp)
        if parsed is None:
            return {
                "status": "unknown",
                "last_seen": timestamp,
                "age_seconds": None,
                "stale_after_seconds": stale_after_seconds,
                "message": "No valid activity timestamp is available.",
            }

        age = max(0, int((datetime.now(timezone.utc) - parsed).total_seconds()))
        is_fresh = age <= stale_after_seconds
        return {
            "status": "active" if is_fresh else "stale",
            "last_seen": parsed.isoformat(),
            "age_seconds": age,
            "stale_after_seconds": stale_after_seconds,
            "message": (
                "Recent activity observed."
                if is_fresh
                else "No recent activity observed within the freshness threshold."
            ),
        }

    def get_system_health(self):
        """Report storage connectivity and timestamp-based activity freshness."""
        checked_at = datetime.now(timezone.utc).isoformat()

        try:
            elasticsearch_available = bool(self.es.ping())
        except Exception:
            elasticsearch_available = False

        if not elasticsearch_available:
            return {
                "available": False,
                "checked_at": checked_at,
                "elasticsearch": {"status": "unavailable"},
                "sensor": {
                    "status": "unknown",
                    "message": "Activity cannot be checked while Elasticsearch is unavailable.",
                },
                "detector": {
                    "status": "unknown",
                    "message": "Activity cannot be checked while Elasticsearch is unavailable.",
                },
                "notes": [
                    "Sensor and detector process liveness is not directly monitored by this endpoint."
                ],
            }

        logs_response = self._search(
            self.logs_index,
            {"match_all": {}},
            size=0,
            aggs={"last_event": {"max": {"field": "@timestamp"}}},
        )

        results_response = self._search(
            self.results_index,
            {"match_all": {}},
            size=0,
            aggs={"last_result": {"max": {"field": "@timestamp"}}},
        )

        if logs_response is None or results_response is None:
            return {
                "available": False,
                "checked_at": checked_at,
                "elasticsearch": {"status": "connected"},
                "sensor": {"status": "unknown"},
                "detector": {"status": "unknown"},
                "message": "Elasticsearch is reachable, but one or more activity queries failed.",
            }

        logs_aggs = logs_response.get("aggregations", {})
        results_aggs = results_response.get("aggregations", {})

        last_event = (
            logs_aggs.get("last_event", {}).get("value_as_string")
        )
        last_result = (
            results_aggs.get("last_result", {}).get("value_as_string")
        )

        sensor = self._freshness(last_event, self.SENSOR_STALE_SECONDS)
        detector = self._freshness(last_result, self.DETECTOR_STALE_SECONDS)

        return {
            "available": True,
            "checked_at": checked_at,
            "elasticsearch": {"status": "connected"},
            "sensor": sensor,
            "detector": detector,
            "thresholds": {
                "sensor_stale_after_seconds": self.SENSOR_STALE_SECONDS,
                "detector_stale_after_seconds": self.DETECTOR_STALE_SECONDS,
            },
            "notes": [
                "Activity status is inferred from the newest indexed timestamp.",
                "A fresh timestamp does not prove the corresponding process is still running.",
                "A stale timestamp may mean inactivity, a stopped process, or an ingestion problem.",
            ],
        }

    def get_current_status(self):
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

    def get_recent_incidents(self, limit=20):
        response = self._search(
            self.results_index,
            {"term": {"anomaly": -1}},
            size=limit,
            sort=[{"@timestamp": {"order": "desc"}}],
        )

        return [
            {
                "event_id": row.get("event_id"),
                "timestamp": row.get("@timestamp"),
                "status": row.get("status"),
                "detector": row.get("detector"),
                "anomaly_score": row.get("anomaly_score"),
                "threshold": row.get("threshold"),
                "reason": row.get("reason"),
                "packets": row.get("packets"),
                "unique_dst_ports": row.get("unique_dst_ports"),
                "unique_dst_ips": row.get("unique_dst_ips"),
                "syn_count": row.get("syn_count"),
                "src_ip": row.get("src_ip"),
                "dst_ip": row.get("dst_ip"),
                "protocol": row.get("protocol"),
                "dst_port": row.get("dst_port"),
            }
            for row in self._hits(response)
        ]

    def get_incident(self, event_id):
        try:
            response = self.es.get(
                index=self.results_index,
                id=event_id,
                ignore=[404],
            )
        except Exception:
            return None

        return response["_source"] if response.get("found") else None

    def search_events(
        self,
        limit=50,
        src_ip=None,
        dst_ip=None,
        protocol=None,
        dst_port=None,
    ):
        filters = []

        if src_ip:
            filters.append({"term": {"src_ip": src_ip}})
        if dst_ip:
            filters.append({"term": {"dst_ip": dst_ip}})
        if protocol:
            filters.append({"term": {"protocol.keyword": protocol.upper()}})
        if dst_port is not None:
            filters.append({"term": {"dst_port": dst_port}})

        response = self._search(
            self.logs_index,
            {"bool": {"filter": filters}},
            size=limit,
            sort=[{"@timestamp": {"order": "desc"}}],
        )
        return self._hits(response)

    def get_devices(self, limit=50):
        response = self._search(
            self.logs_index,
            {"match_all": {}},
            size=0,
            aggs={
                "observed_ips": {
                    "terms": {
                        "field": "src_ip.keyword",
                        "size": limit,
                    },
                    "aggs": {
                        "last_seen": {"max": {"field": "@timestamp"}}
                    },
                }
            },
        )

        buckets = (
            response.get("aggregations", {}).get("observed_ips", {}).get("buckets", [])
            if response else []
        )

        return [
            {
                "ip_address": bucket["key"],
                "event_count": bucket["doc_count"],
                "last_seen": bucket.get("last_seen", {}).get("value_as_string"),
                "address_scope": (
                    "private"
                    if self._is_private_ip(bucket["key"])
                    else "public_or_other"
                ),
            }
            for bucket in buckets
        ]

    def get_device_activity(self, ip_address, limit=50):
        response = self._search(
            self.logs_index,
            {"term": {"src_ip": ip_address}},
            size=limit,
            sort=[{"@timestamp": {"order": "desc"}}],
        )
        return self._hits(response)

    def get_detector_status(self):
        status = self.get_current_status()
        if status is None:
            return {
                "status": "not_ready",
                "message": "No detector status record is available.",
            }

        return {
            "status": "status_record_available",
            "latest_result": status,
        }

    def get_overview(self, minutes=60):
        time_filter = {
            "range": {
                "@timestamp": {
                    "gte": f"now-{minutes}m",
                    "lte": "now",
                }
            }
        }

        traffic_response = self._search(
            self.logs_index,
            time_filter,
            size=0,
            aggs={
                "packets_over_time": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "5m",
                        "min_doc_count": 0,
                    }
                },
                "protocols": {
                    "terms": {"field": "protocol.keyword", "size": 10}
                },
                "last_packet": {"max": {"field": "@timestamp"}},
            },
        )

        result_response = self._search(
            self.results_index,
            time_filter,
            size=0,
            aggs={
                "anomalies": {"filter": {"term": {"anomaly": -1}}},
                "normal": {"filter": {"term": {"anomaly": 1}}},
                "last_detection": {"max": {"field": "@timestamp"}},
            },
        )

        if traffic_response is None or result_response is None:
            return {
                "window_minutes": minutes,
                "available": False,
                "message": "Could not query one or more Elasticsearch indices.",
            }

        traffic_aggs = traffic_response.get("aggregations", {})
        result_aggs = result_response.get("aggregations", {})
        latest_alerts = self.get_recent_incidents(limit=1)

        buckets = traffic_aggs.get("packets_over_time", {}).get("buckets", [])
        protocols = traffic_aggs.get("protocols", {}).get("buckets", [])

        return {
            "available": True,
            "window_minutes": minutes,
            "traffic": {
                "event_count": traffic_response.get("hits", {}).get("total", {}).get("value", 0),
                "events_over_time": [
                    {
                        "time": bucket.get("key_as_string"),
                        "events": bucket.get("doc_count", 0),
                    }
                    for bucket in buckets
                ],
                "protocols": [
                    {"protocol": bucket["key"], "events": bucket["doc_count"]}
                    for bucket in protocols
                ],
                "last_packet_timestamp": traffic_aggs.get("last_packet", {}).get("value_as_string"),
            },
            "detections": {
                "anomalous_windows": result_aggs.get("anomalies", {}).get("doc_count", 0),
                "normal_windows": result_aggs.get("normal", {}).get("doc_count", 0),
                "last_detection_timestamp": result_aggs.get("last_detection", {}).get("value_as_string"),
                "latest_alert": latest_alerts[0] if latest_alerts else None,
            },
        }
