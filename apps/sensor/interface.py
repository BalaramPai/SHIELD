# File: apps/sensor/interface.py
# Purpose: Detects the active network interface(s) used by the SHIELD sensor.

import subprocess

from scapy.all import conf


def detect_interfaces() -> list[str]:
    interfaces = []

    try:
        output = subprocess.check_output(
            ["route", "-n", "get", "default"],
            text=True,
            stderr=subprocess.DEVNULL,
        )

        for line in output.splitlines():
            if "interface:" in line:
                interface = line.split(":", 1)[1].strip()

                if interface:
                    interfaces.append(interface)

                break

    except (OSError, subprocess.CalledProcessError):
        fallback = str(conf.iface) if conf.iface else None

        if fallback:
            interfaces.append(fallback)

    if "lo0" not in interfaces:
        interfaces.append("lo0")

    return interfaces