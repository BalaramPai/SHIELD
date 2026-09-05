# File: apps/detector/engine.py
# Purpose: Runs the SHIELD detection pipeline using Isolation Forest and flood-pattern analysis.

import time
from datetime import datetime, timezone

import pandas as pd
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import NotFoundError

from apps.detector.config import (
    BASELINE_WINDOWS,
    ELASTICSEARCH_URL,
    INPUT_INDEX,
)
from apps.detector.flood import FloodDetector
from apps.detector.isolation_forest import IsolationForestDetector
from apps.detector.storage import DetectionStorage
from apps.detector.windowing import build_windows, parse_timestamp


BATCH_SLEEP_SECONDS = 10
FETCH_SIZE = 5000
LIVE_LOOKBACK = "now-30s"


class DetectionEngine:
    """Coordinates SHIELD traffic windowing and detection."""

    def __init__(self):
        self.es = Elasticsearch(ELASTICSEARCH_URL)

        self.detector = IsolationForestDetector()
        self.flood_detector = FloodDetector()

        self.storage = DetectionStorage()

        self.baseline_windows = []
        self.scored_ids = set()
        self.fetch_gte = None

    def fetch_events(self):
        """Fetch recent network events from Elasticsearch."""

        query = {
            "range": {
                "@timestamp": {
                    "gte": self.fetch_gte or LIVE_LOOKBACK,
                }
            }
        }

        response = self.es.search(
            index=INPUT_INDEX,
            query=query,
            size=FETCH_SIZE,
            sort=[
                {
                    "@timestamp": {
                        "order": "asc",
                    }
                },
                {
                    "event_id.keyword": {
                        "order": "asc",
                    }
                },
            ],
        )

        rows = []

        for hit in response["hits"]["hits"]:
            source = hit["_source"]

            timestamp = parse_timestamp(
                source.get("@timestamp") or source.get("timestamp")
            )

            if timestamp is None:
                continue

            rows.append(
                {
                    "bytes": float(
                        source.get("bytes")
                        or source.get("packet_size")
                        or 0
                    ),
                    "src_port": int(source.get("src_port") or 0),
                    "dst_port": int(source.get("dst_port") or 0),
                    "src_ip": source.get("src_ip", ""),
                    "dst_ip": source.get("dst_ip", ""),
                    "protocol": source.get("protocol", "OTHER"),
                    "flags": str(source.get("flags") or ""),
                    "timestamp": timestamp,
                }
            )

        return pd.DataFrame(rows)

    def mark_live_cursor(self):
        """Move the Elasticsearch fetch cursor to the current window."""

        now = datetime.now(timezone.utc)

        epoch = int(now.timestamp())
        window_start = epoch - (epoch % 10)

        self.fetch_gte = datetime.fromtimestamp(
            window_start,
            tz=timezone.utc,
        ).strftime("%Y-%m-%dT%H:%M:%S.000000Z")

    def _combine_detection_results(self, window, ml_result):
        """Combine Isolation Forest and flood analysis into one SHIELD result."""

        flood_result = self.flood_detector.score(window)

        is_ml_anomaly = ml_result["anomaly"] == -1

        is_anomaly = (
            is_ml_anomaly
            or flood_result.is_flood
        )

        if flood_result.is_flood:
            reason = flood_result.reason
        elif is_ml_anomaly:
            reason = ml_result["reason"]
        else:
            reason = "normal"

        result = dict(ml_result)

        result["anomaly"] = -1 if is_anomaly else 1
        result["status"] = "ANOMALY" if is_anomaly else "NORMAL"
        result["reason"] = reason

        result["flood_detected"] = flood_result.is_flood
        result["flood_reason"] = flood_result.reason
        result["packet_rate"] = flood_result.packet_rate
        result["syn_ratio"] = flood_result.syn_ratio
        result["destination_concentration"] = (
            flood_result.destination_concentration
        )

        result["ml_anomaly"] = is_ml_anomaly

        return result

    def process(self):
        """Process newly completed traffic windows."""

        dataframe = self.fetch_events()

        windows = build_windows(dataframe)

        windows = [
            window
            for window in windows
            if window["event_id"] not in self.scored_ids
        ]

        if not windows:
            self.mark_live_cursor()
            return

        # ---------------------------------------------------------
        # Learn the initial normal baseline.
        # ---------------------------------------------------------

        if not self.detector.ready:
            self.baseline_windows.extend(windows)

            for window in windows:
                self.scored_ids.add(window["event_id"])

            print(
                f"Learning baseline: "
                f"{len(self.baseline_windows)}/{BASELINE_WINDOWS} windows."
            )

            if len(self.baseline_windows) >= BASELINE_WINDOWS:
                self.detector.fit(self.baseline_windows)

                self.flood_detector.fit(
                    self.baseline_windows
                )

                for window in self.baseline_windows:
                    ml_result = self.detector.score(window)

                    result = self._combine_detection_results(
                        window,
                        ml_result,
                    )

                    self.storage.store_result(result)

                print("Baseline ready.")

            self.mark_live_cursor()
            return

        # ---------------------------------------------------------
        # Score live traffic.
        # ---------------------------------------------------------

        anomalies = 0
        flood_events = 0

        for window in windows:
            ml_result = self.detector.score(window)

            result = self._combine_detection_results(
                window,
                ml_result,
            )

            self.storage.store_result(result)

            self.scored_ids.add(window["event_id"])

            if result["anomaly"] == -1:
                anomalies += 1

            if result["flood_detected"]:
                flood_events += 1

            print(
                f"{result['status']:8} "
                f"ports={result['unique_dst_ports']:<4} "
                f"pkts={result['packets']:<5} "
                f"syn={result['syn_ratio']:.2f} "
                f"score={result['anomaly_score']:.4f} "
                f"reason={result['reason']} "
                f"id={result['event_id']}"
            )

        print(
            f"Scored {len(windows)} windows; "
            f"{anomalies} anomalous; "
            f"{flood_events} flood-like."
        )

        self.mark_live_cursor()


def main():
    """Start the SHIELD detection engine."""

    print("SHIELD detection engine started.")

    engine = DetectionEngine()

    while True:
        try:
            engine.process()

        except NotFoundError:
            print(
                f"Index `{INPUT_INDEX}` does not exist yet. "
                "Start the sensor first."
            )

        except Exception as exc:
            print(f"Detection error: {exc}")

        time.sleep(BATCH_SLEEP_SECONDS)


if __name__ == "__main__":
    main()