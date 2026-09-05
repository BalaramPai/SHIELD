# File: tests/unit/test_isolation_forest.py
# Purpose: Tests baseline training and anomaly scoring of the SHIELD detector.

from apps.detector.isolation_forest import IsolationForestDetector


def make_window(index: int) -> dict:
    return {
        "event_id": f"window-{index}",
        "packets": 20 + index,
        "bytes": 2000 + (index * 100),
        "unique_dst_ips": 2,
        "unique_dst_ports": 3,
        "tcp_count": 15,
        "udp_count": 5,
        "syn_count": 5,
    }


def test_detector_trains_and_scores():
    windows = [make_window(i) for i in range(10)]

    detector = IsolationForestDetector()

    detector.fit(windows)

    assert detector.ready is True
    assert detector.threshold is not None
    assert detector.port_scan_cutoff is not None

    result = detector.score(make_window(10))

    assert result["detector"] == "isolation_forest"
    assert "anomaly_score" in result
    assert "threshold" in result
    assert result["anomaly"] in (-1, 1)
    assert result["status"] in ("NORMAL", "ANOMALY")
    assert "reason" in result