# File: tests/unit/test_network_schema.py
# Purpose: Tests the shared network constants and ML feature definitions.

from packages.schemas.network import (
    LOGS_INDEX,
    ML_FEATURE_COLUMNS,
    PROTOCOL_TO_NUM,
    RESULTS_INDEX,
    WINDOW_SECONDS,
)


def test_protocol_mapping():
    assert PROTOCOL_TO_NUM["TCP"] == 6
    assert PROTOCOL_TO_NUM["UDP"] == 17
    assert PROTOCOL_TO_NUM["ICMP"] == 1
    assert PROTOCOL_TO_NUM["OTHER"] == 0


def test_indexes():
    assert LOGS_INDEX == "logs"
    assert RESULTS_INDEX == "ml-results"


def test_window_configuration():
    assert WINDOW_SECONDS == 10


def test_ml_features():
    assert ML_FEATURE_COLUMNS == [
        "packets",
        "bytes",
        "unique_dst_ips",
        "unique_dst_ports",
        "tcp_count",
        "udp_count",
        "syn_count",
    ]