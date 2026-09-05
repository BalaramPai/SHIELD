from scapy.all import sniff


def capture_packets(interface: str | None = None) -> None:
    sniff(
        iface=interface,
        prn=lambda packet: print(packet.summary()),
        store=False,
    )


if __name__ == "__main__":
    capture_packets()