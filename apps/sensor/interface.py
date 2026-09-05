# File: apps/sensor/interface.py
# Purpose: Detects the active network interface used by the SHIELD sensor.

from scapy.all import conf


def detect_interfaces() -> list[str]:
    """Return the network interface selected by Scapy."""
    interface = str(conf.iface) if conf.iface else None

    if not interface:
        raise RuntimeError(
            "Could not determine the active network interface."
        )

    return [interface]