# File: packages/schemas/network.py
# Purpose: Shared network constants and ML feature definitions used by the sensor and detector.

PROTOCOL_TO_NUM = {
    "TCP": 6,
    "UDP": 17,
    "ICMP": 1,
    "OTHER": 0,
}

WINDOW_SECONDS = 10
MIN_BASELINE_WINDOWS = 6
THRESHOLD_SIGMA = 2.0
PORT_SCAN_MULT = 2.0

ML_FEATURE_COLUMNS = [
    "packets",
    "bytes",
    "unique_dst_ips",
    "unique_dst_ports",
    "tcp_count",
    "udp_count",
    "syn_count",
]

LOGS_INDEX = "logs"
RESULTS_INDEX = "ml-results"