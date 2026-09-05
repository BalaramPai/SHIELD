# File: apps/detector/isolation_forest.py
# Purpose: Trains and applies the Isolation Forest anomaly detector to traffic windows.

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from apps.detector.config import (
    ANOMALY_THRESHOLD_SIGMA,
    BASELINE_WINDOWS,
    PORT_SCAN_MULTIPLIER,
)
from apps.detector.features import build_feature_vector


class IsolationForestDetector:
    def __init__(self) -> None:
        self.scaler = StandardScaler()
        self.model: IsolationForest | None = None
        self.threshold: float | None = None
        self.port_scan_cutoff: float | None = None

    @property
    def ready(self) -> bool:
        return (
            self.model is not None
            and self.threshold is not None
            and self.port_scan_cutoff is not None
        )

    def fit(self, windows: list[dict]) -> None:
        if len(windows) < BASELINE_WINDOWS:
            raise ValueError(
                f"Need at least {BASELINE_WINDOWS} baseline windows."
            )

        features = np.array(
            [
                [float(window[column]) for column in (
                    "packets",
                    "bytes",
                    "unique_dst_ips",
                    "unique_dst_ports",
                    "tcp_count",
                    "udp_count",
                    "syn_count",
                )]
                for window in windows
            ],
            dtype=float,
        )

        scaled = self.scaler.fit_transform(features)

        self.model = IsolationForest(
            contamination="auto",
            random_state=42,
            n_estimators=200,
        )

        self.model.fit(scaled)

        scores = self.model.decision_function(scaled)

        spread = float(max(np.std(scores), 1e-6))

        self.threshold = float(
            np.mean(scores) - ANOMALY_THRESHOLD_SIGMA * spread
        )

        max_ports = float(
            max(window["unique_dst_ports"] for window in windows)
        )

        self.port_scan_cutoff = max(
            max_ports * PORT_SCAN_MULTIPLIER,
            max_ports + 40,
        )

    def score(self, window: dict) -> dict:
        if not self.ready:
            raise RuntimeError("Detector has not been trained yet.")

        vector = build_feature_vector(window)
        scaled = self.scaler.transform(vector)

        score = float(
            self.model.decision_function(scaled)[0]
        )

        scan_hit = (
            window["unique_dst_ports"]
            >= self.port_scan_cutoff
        )

        is_anomaly = (
            score < self.threshold
            or scan_hit
        )

        result = dict(window)

        result["detector"] = "isolation_forest"
        result["anomaly_score"] = score
        result["threshold"] = self.threshold
        result["anomaly"] = -1 if is_anomaly else 1
        result["status"] = (
            "ANOMALY"
            if is_anomaly
            else "NORMAL"
        )

        if scan_hit:
            result["reason"] = "destination_port_scan"
        elif score < self.threshold:
            result["reason"] = "isolation_forest"
        else:
            result["reason"] = "normal"

        return result