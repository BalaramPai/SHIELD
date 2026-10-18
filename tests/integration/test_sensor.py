# File: tests/integration/test_sensor.py
# Purpose: Tests that the SHIELD sensor correctly parses different network protocols.

from scapy.layers.inet import ICMP, IP, TCP, UDP

from apps.sensor.parser import parse_packet


def test_parse_tcp_packet():
    packet = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
        sport=1234,
        dport=443,
        flags="S",
    )

    event = parse_packet(packet)

    assert event is not None
    assert event.protocol == "TCP"
    assert event.protocol_num == 6
    assert event.src_port == 1234
    assert event.dst_port == 443
    assert event.flags == "S"


def test_parse_udp_packet():
    packet = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(
        sport=1234,
        dport=53,
    )

    event = parse_packet(packet)

    assert event is not None
    assert event.protocol == "UDP"
    assert event.protocol_num == 17
    assert event.src_port == 1234
    assert event.dst_port == 53


def test_parse_icmp_packet():
    packet = IP(
        src="10.0.0.1",
        dst="10.0.0.2",
    ) / ICMP()

    event = parse_packet(packet)

    assert event is not None
    assert event.protocol == "ICMP"
    assert event.protocol_num == 1
    assert event.src_port is None
    assert event.dst_port is None