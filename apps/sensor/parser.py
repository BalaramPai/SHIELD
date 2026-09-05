# File: apps/sensor/parser.py
# Purpose: Converts raw Scapy packets into structured SHIELD network events.

import hashlib
import time
from datetime import datetime, timezone

from scapy.layers.inet import ICMP, IP, TCP, UDP

from apps.sensor.config import SENSOR_ID
from packages.schemas.events import NetworkEvent
from packages.schemas.network import PROTOCOL_TO_NUM


_packet_sequence = 0


def parse_packet(packet) -> NetworkEvent | None:
    if IP not in packet:
        return None

    ip = packet[IP]

    src_port = None
    dst_port = None
    flags = ""
    protocol = "OTHER"

    if TCP in packet:
        protocol = "TCP"
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)
        flags = str(packet[TCP].flags)

    elif UDP in packet:
        protocol = "UDP"
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)

    elif ICMP in packet:
        protocol = "ICMP"

    global _packet_sequence
    _packet_sequence += 1

    event_id = hashlib.sha1(
        (
            f"{time.time_ns()}|{_packet_sequence}|"
            f"{ip.src}|{ip.dst}|{src_port}|{dst_port}|{protocol}"
        ).encode()
    ).hexdigest()[:16]

    return NetworkEvent(
        event_id=event_id,
        timestamp=datetime.now(timezone.utc),
        sensor_id=SENSOR_ID,
        src_ip=ip.src,
        dst_ip=ip.dst,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        protocol_num=PROTOCOL_TO_NUM[protocol],
        packet_size=len(packet),
        flags=flags,
    )