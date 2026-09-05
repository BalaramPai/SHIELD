# File: apps/detector/storage.py
# Purpose: Persists detection results and the latest SHIELD status in Elasticsearch.

from elasticsearch import Elasticsearch

from apps.detector.config import ELASTICSEARCH_URL, OUTPUT_INDEX


class DetectionStorage:
    def __init__(self) -> None:
        self.es = Elasticsearch(ELASTICSEARCH_URL)

    def store_result(self, result: dict) -> None:
        event_id = result["event_id"]

        self.es.index(
            index=OUTPUT_INDEX,
            id=event_id,
            document=result,
        )

        self.es.index(
            index=OUTPUT_INDEX,
            id="current-status",
            document={
                "event_id": "current-status",
                "status": result["status"],
                "anomaly": result["anomaly"],
                "anomaly_score": result["anomaly_score"],
                "threshold": result["threshold"],
                "packets": result["packets"],
                "unique_dst_ports": result["unique_dst_ports"],
                "unique_dst_ips": result["unique_dst_ips"],
                "syn_count": result["syn_count"],
                "@timestamp": result["@timestamp"],
            },
        )