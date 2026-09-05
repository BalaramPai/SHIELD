# File: scripts/development/demo_burst.py
# Purpose: Generates safe localhost-only traffic for testing SHIELD anomaly detection.

import argparse
import socket
import sys
from concurrent.futures import ThreadPoolExecutor


LOCALHOST = "127.0.0.1"


def scan_local_ports(start: int, end: int) -> None:
    print(
        f"TCP connection burst to {LOCALHOST} ports {start}-{end}"
    )

    def hit(port: int) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.05)

        try:
            sock.connect((LOCALHOST, port))
        except OSError:
            pass
        finally:
            sock.close()

    with ThreadPoolExecutor(max_workers=64) as pool:
        list(pool.map(hit, range(start, end + 1)))


def udp_scan_local(count: int, base_port: int) -> None:
    print(
        f"UDP burst: {count} packets to "
        f"{LOCALHOST}:{base_port}-{base_port + count - 1}"
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"x" * 16

    try:
        for i in range(count):
            sock.sendto(
                payload,
                (LOCALHOST, base_port + i),
            )
    finally:
        sock.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate localhost-only SHIELD demo traffic."
    )

    parser.add_argument(
        "--mode",
        choices=("scan", "flood", "both"),
        default="both",
    )

    parser.add_argument("--start-port", type=int, default=1)
    parser.add_argument("--end-port", type=int, default=400)
    parser.add_argument("--flood-count", type=int, default=400)
    parser.add_argument("--flood-port", type=int, default=20000)

    args = parser.parse_args()

    if (
        args.start_port < 1
        or args.end_port > 65535
        or args.start_port > args.end_port
    ):
        print("Port range must be 1-65535 and start <= end.")
        sys.exit(1)

    print(
        f"Target is always {LOCALHOST}. "
        "Nothing is sent to the Wi-Fi LAN."
    )

    if args.mode in ("scan", "both"):
        scan_local_ports(
            args.start_port,
            args.end_port,
        )

    if args.mode in ("flood", "both"):
        udp_scan_local(
            args.flood_count,
            args.flood_port,
        )

    print("Demo traffic generation complete.")


if __name__ == "__main__":
    main()