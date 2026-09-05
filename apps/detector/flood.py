# File: apps/detector/flood.py
# Purpose: Detects flood-like network traffic patterns using learned baseline thresholds.

from dataclasses import dataclass


@dataclass(frozen=True)
class FloodDetection:
    """Describes the result of the flood detector."""

    is_flood: bool
    reason: str
    packet_rate: float
    syn_ratio: float
    destination_concentration: float


class FloodDetector:
    """Detects traffic patterns that resemble a concentrated network flood."""

    def __init__(
        self,
        packet_multiplier: float = 3.0,
        syn_ratio_threshold: float = 0.70,
        concentration_threshold: float = 0.80,
    ):
        self.packet_multiplier = packet_multiplier
        self.syn_ratio_threshold = syn_ratio_threshold
        self.concentration_threshold = concentration_threshold

        self.packet_baseline = None
        self.ready = False

    def fit(self, baseline_windows: list[dict]) -> None:
        """Learn the normal packet-rate baseline."""

        if not baseline_windows:
            raise ValueError("At least one baseline window is required.")

        packet_counts = [
            float(window.get("packets", 0))
            for window in baseline_windows
        ]

        self.packet_baseline = max(
            sum(packet_counts) / len(packet_counts),
            1.0,
        )

        self.ready = True

    def score(self, window: dict) -> FloodDetection:
        """Evaluate one completed traffic window."""

        if not self.ready:
            raise RuntimeError(
                "Flood detector is not ready. Fit a baseline first."
            )

        packets = float(window.get("packets", 0))
        syn_count = float(window.get("syn_count", 0))
        unique_dst_ips = int(window.get("unique_dst_ips", 0))
        unique_dst_ports = int(window.get("unique_dst_ports", 0))

        packet_rate = packets / 10.0

        syn_ratio = (
            syn_count / packets
            if packets > 0
            else 0.0
        )

        destination_total = unique_dst_ips + unique_dst_ports

        if destination_total == 0:
            destination_concentration = 1.0
        else:
            destination_concentration = (
                1.0 / destination_total
            )

        high_packet_rate = (
            packets >= self.packet_baseline * self.packet_multiplier
        )

        concentrated_target = (
            unique_dst_ips <= 2
            and unique_dst_ports <= 2
        )

        syn_flood_pattern = (
            syn_ratio >= self.syn_ratio_threshold
            and packets >= self.packet_baseline
        )

        flood_detected = (
            high_packet_rate
            and concentrated_target
        ) or syn_flood_pattern

        if syn_flood_pattern:
            reason = "syn_flood_pattern"
        elif high_packet_rate and concentrated_target:
            reason = "concentrated_traffic_flood"
        else:
            reason = "normal"

        return FloodDetection(
            is_flood=flood_detected,
            reason=reason,
            packet_rate=packet_rate,
            syn_ratio=syn_ratio,
            destination_concentration=destination_concentration,
        )