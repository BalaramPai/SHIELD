# File: apps/detector/windowing.py
# Purpose: Groups network events into completed 10-second traffic windows and calculates traffic concentration.

from datetime import datetime, timezone

import pandas as pd

from apps.detector.config import WINDOW_SIZE


def parse_timestamp(value):
    """Convert an Elasticsearch timestamp into a timezone-aware datetime."""

    if not value:
        return None

    text = str(value).replace("Z", "+00:00")

    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def window_start_epoch(timestamp):
    """Return the beginning of the 10-second window containing a timestamp."""

    epoch = int(timestamp.timestamp())

    return epoch - (epoch % WINDOW_SIZE)


def iso_from_epoch(epoch):
    """Convert an epoch timestamp to SHIELD's UTC timestamp format."""

    return datetime.fromtimestamp(
        epoch,
        tz=timezone.utc,
    ).strftime("%Y-%m-%dT%H:%M:%S.000000Z")


def build_windows(df):
    """Build completed traffic windows from network events."""

    if df.empty:
        return []

    now = datetime.now(timezone.utc)

    current_window = window_start_epoch(now)

    grouped = {}

    for start, group in df.groupby(
        df["timestamp"].map(window_start_epoch)
    ):
        grouped[int(start)] = group

    windows = []

    for start, group in sorted(grouped.items()):

        # Never score the currently active window.
        if start >= current_window:
            continue

        tcp = group[group["protocol"] == "TCP"]
        udp = group[group["protocol"] == "UDP"]

        syn_count = 0

        if "flags" in group:
            syn_count = int(
                group["flags"]
                .fillna("")
                .astype(str)
                .str.upper()
                .str.contains("S")
                .sum()
            )

        top_ports = (
            group["dst_port"]
            .dropna()
            .value_counts()
            .head(8)
            .index
            .astype(int)
            .tolist()
        )

        # Find the most common destination IP + port combination.
        destination_pairs = (
            group.groupby(["dst_ip", "dst_port"])
            .size()
            .sort_values(ascending=False)
        )

        if destination_pairs.empty:
            top_destination_ip = ""
            top_destination_port = 0
            top_destination_packets = 0
        else:
            (
                top_destination_ip,
                top_destination_port,
            ) = destination_pairs.index[0]

            top_destination_packets = int(
                destination_pairs.iloc[0]
            )

        destination_concentration = (
            top_destination_packets / len(group)
            if len(group) > 0
            else 0.0
        )

        windows.append(
            {
                "event_id": f"window-{start}",
                "window_start": iso_from_epoch(start),
                "window_end": iso_from_epoch(
                    start + WINDOW_SIZE
                ),
                "@timestamp": iso_from_epoch(
                    start + WINDOW_SIZE
                ),

                "packets": int(len(group)),
                "bytes": float(group["bytes"].sum()),

                "unique_dst_ips": int(
                    group["dst_ip"].nunique()
                ),
                "unique_dst_ports": int(
                    group["dst_port"].nunique()
                ),

                "tcp_count": int(len(tcp)),
                "udp_count": int(len(udp)),
                "syn_count": syn_count,

                "sample_src_ip": (
                    str(group["src_ip"].mode().iloc[0])
                    if not group["src_ip"].mode().empty
                    else ""
                ),

                "sample_dst_ip": (
                    str(group["dst_ip"].mode().iloc[0])
                    if not group["dst_ip"].mode().empty
                    else ""
                ),

                "top_dst_ports": ",".join(
                    str(port)
                    for port in top_ports
                ),

                "top_destination_ip": str(
                    top_destination_ip
                ),

                "top_destination_port": int(
                    top_destination_port or 0
                ),

                "top_destination_packets": (
                    top_destination_packets
                ),

                "destination_concentration": (
                    destination_concentration
                ),
            }
        )

    return windows