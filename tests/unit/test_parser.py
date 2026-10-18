# File: tests/unit/test_parser.py
# Purpose: Tests conversion of Scapy packets into SHIELD network events.

from scapy.layers.inet import IP, TCP

from apps.sensor.parser import parse_packet


def test_parse_tcp_packet():
    packet = IP(
        src="192.168.1.10",
        dst="192.168.1.20",
    ) / TCP(
        sport=12345,
        dport=443,
        flags="S",
    )

    event = parse_packet(packet)

    assert event is not None
    assert event.src_ip == "192.168.1.10"
    assert event.dst_ip == "192.168.1.20"
    assert event.src_port == 12345
    assert event.dst_port == 443
    assert event.protocol == "TCP"
    assert event.protocol_num == 6
    assert event.flags == "S"
    assert event.packet_size == len(packet)