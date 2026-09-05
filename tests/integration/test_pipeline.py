# File: tests/integration/test_pipeline.py
# Purpose: Tests the main SHIELD processing flow across sensor and detector components.

from datetime import datetime, timezone

import pandas as pd
from scapy.layers.inet import IP, TCP

from apps.detector.isolation_forest import IsolationForestDetector
from apps.detector.windowing import build_windows
from apps.sensor.parser import parse_packet


def test_sensor_to_detector_flow():
    packet = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=12345, dport=443, flags="S")
    )

    event = parse_packet(packet)

    assert event is not None

    dataframe = pd.DataFrame(
        [
            {
                "timestamp": datetime.fromtimestamp(
                    1000,
                    tz=timezone.utc,
                ),
                "bytes": event.packet_size,
                "src_port": event.src_port,
                "dst_port": event.dst_port,
                "src_ip": event.src_ip,
                "dst_ip": event.dst_ip,
                "protocol": event.protocol,
                "flags": event.flags,
            }
        ]
    )

    windows = build_windows(dataframe)

    assert len(windows) == 1

    baseline = []

    for index in range(10):
        window = dict(windows[0])
        window["event_id"] = f"window-{index}"
        window["packets"] = 20 + index
        window["bytes"] = 2000 + index * 100
        baseline.append(window)

    detector = IsolationForestDetector()
    detector.fit(baseline)

    result = detector.score(windows[0])

    assert result["status"] in ("NORMAL", "ANOMALY")
    assert "anomaly_score" in result