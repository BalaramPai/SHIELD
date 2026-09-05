# File: apps/detector/windowing.py
# Purpose: Groups network events into completed 10-second traffic windows.

from datetime import datetime, timezone

import pandas as pd

from apps.detector.config import WINDOW_SIZE


def parse_timestamp(value) -> datetime | None:
    if not value:
        return None

    text = str(value).replace("Z", "+00:00")

    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def window_start_epoch(timestamp: datetime) -> int:
    epoch = int(timestamp.timestamp())
    return epoch - (epoch % WINDOW_SIZE)


def iso_from_epoch(epoch: int) -> str:
    return datetime.fromtimestamp(
        epoch,
        tz=timezone.utc,
    ).strftime("%Y-%m-%dT%H:%M:%S.000000Z")


def build_windows(df: pd.DataFrame) -> list[dict]:
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
        # Do not process the currently open window.
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

        windows.append(
            {
                "event_id": f"window-{start}",
                "window_start": iso_from_epoch(start),
                "window_end": iso_from_epoch(start + WINDOW_SIZE),
                "@timestamp": iso_from_epoch(start + WINDOW_SIZE),
                "packets": int(len(group)),
                "bytes": float(group["bytes"].sum()),
                "unique_dst_ips": int(group["dst_ip"].nunique()),
                "unique_dst_ports": int(group["dst_port"].nunique()),
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
                    str(port) for port in top_ports
                ),
            }
        )

    return windows