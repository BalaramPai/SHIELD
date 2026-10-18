# File: tests/unit/test_windowing.py
# Purpose: Tests 10-second traffic window creation for the SHIELD detector.

from datetime import datetime, timezone

import pandas as pd

from apps.detector.windowing import build_windows


def test_build_completed_window():
    df = pd.DataFrame(
        [
            {
                "timestamp": datetime.fromtimestamp(
                    1000,
                    tz=timezone.utc,
                ),
                "bytes": 100,
                "src_port": 1234,
                "dst_port": 80,
                "src_ip": "192.168.1.10",
                "dst_ip": "192.168.1.20",
                "protocol": "TCP",
                "flags": "S",
            },
            {
                "timestamp": datetime.fromtimestamp(
                    1005,
                    tz=timezone.utc,
                ),
                "bytes": 200,
                "src_port": 1235,
                "dst_port": 443,
                "src_ip": "192.168.1.10",
                "dst_ip": "192.168.1.30",
                "protocol": "TCP",
                "flags": "S",
            },
        ]
    )

    windows = build_windows(df)

    # The test timestamps are historical, so the 10-second window is completed.
    assert len(windows) == 1

    window = windows[0]

    assert window["event_id"] == "window-1000"
    assert window["packets"] == 2
    assert window["bytes"] == 300
    assert window["unique_dst_ips"] == 2
    assert window["unique_dst_ports"] == 2
    assert window["tcp_count"] == 2
    assert window["udp_count"] == 0
    assert window["syn_count"] == 2