# File: apps/sensor/capture.py
# Purpose: Captures live network packets using Scapy and passes them for parsing.

from scapy.all import sniff

from apps.sensor.parser import parse_packet


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


def capture_packets(interface: str | None = None) -> None:
    sniff(
        iface=interface,
        prn=handle_packet,
        store=False,
    )


if __name__ == "__main__":
    capture_packets()