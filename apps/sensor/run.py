# File: apps/sensor/run.py
# Purpose: Runs the complete SHIELD sensor capture, parsing, and ingestion flow.

import os
import sys

from scapy.all import sniff

from apps.sensor.ingest import send_event
from apps.sensor.interface import detect_interfaces
from apps.sensor.parser import parse_packet


def main() -> None:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("Packet capture needs raw socket permissions.")
        print("Run with administrator/root privileges.")
        sys.exit(1)

    interfaces = detect_interfaces()

    print(f"Listening on: {', '.join(interfaces)}")
    print("Capturing header metadata only. Press Ctrl+C to stop.")

    def handle_packet(packet) -> None:
        event = parse_packet(packet)

        if event is None:
            return

        print(
            f"{event.protocol:5} "
            f"{event.src_ip}:{event.src_port} -> "
            f"{event.dst_ip}:{event.dst_port} "
            f"{event.packet_size}B "
            f"{event.flags}"
        )

        try:
            send_event(event)
        except OSError as exc:
            print(f"Could not send event to Logstash: {exc}")

    try:
        sniff(
            iface=interfaces,
            prn=handle_packet,
            store=False,
        )
    except KeyboardInterrupt:
        print("\nSensor stopped.")


if __name__ == "__main__":
    main()