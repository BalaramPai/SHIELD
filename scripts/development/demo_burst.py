# File: scripts/development/demo_burst.py
# Purpose: Generates three isolated synthetic traffic phases for a safe SHIELD flood-detection demonstration.

import sys
import time
import uuid
from datetime import datetime, timedelta, timezone

from elasticsearch import Elasticsearch


ELASTICSEARCH_URL = "http://localhost:9200"
LOGS_INDEX = "logs"

LOCAL_SOURCE_IP = "192.168.0.135"

NORMAL_EVENTS = 30
SPIKE_EVENTS = 300
FLOOD_EVENTS = 3000

NORMAL_DESTINATIONS = [
    ("8.8.8.8", 443),
    ("1.1.1.1", 443),
    ("142.250.72.14", 443),
    ("151.101.1.69", 443),
]

SPIKE_DESTINATIONS = [
    ("8.8.8.8", 443),
    ("1.1.1.1", 443),
    ("142.250.72.14", 443),
    ("151.101.1.69", 443),
    ("20.42.73.24", 443),
    ("52.84.150.10", 443),
    ("104.16.132.229", 443),
    ("172.217.160.78", 443),
]

FLOOD_DESTINATION = ("192.168.0.1", 80)


def create_event(
    timestamp: datetime,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    protocol: str = "TCP",
    flags: str = "",
    packet_size: int = 100,
) -> dict:
    """Create one synthetic SHIELD network event."""

    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": timestamp.isoformat(),
        "@timestamp": timestamp.isoformat(),
        "sensor_id": "demo-sensor",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": 50000,
        "dst_port": dst_port,
        "protocol": protocol,
        "protocol_num": 6 if protocol == "TCP" else 17,
        "packet_size": packet_size,
        "bytes": packet_size,
        "flags": flags,
    }


def send_events(es: Elasticsearch, events: list[dict]) -> None:
    """Insert synthetic events into Elasticsearch."""

    for event in events:
        es.index(
            index=LOGS_INDEX,
            id=event["event_id"],
            document=event,
        )


def normal_traffic(es: Elasticsearch, start: datetime) -> None:
    """Generate distributed ordinary traffic."""

    events = []

    for index in range(NORMAL_EVENTS):
        dst_ip, dst_port = NORMAL_DESTINATIONS[
            index % len(NORMAL_DESTINATIONS)
        ]

        timestamp = start + timedelta(milliseconds=index * 200)

        events.append(
            create_event(
                timestamp=timestamp,
                src_ip=LOCAL_SOURCE_IP,
                dst_ip=dst_ip,
                dst_port=dst_port,
                flags="PA",
                packet_size=120,
            )
        )

    send_events(es, events)

    print(f"Normal traffic: {len(events)} events sent.")


def traffic_spike(es: Elasticsearch, start: datetime) -> None:
    """Generate a high-volume but distributed traffic spike."""

    events = []

    for index in range(SPIKE_EVENTS):
        dst_ip, dst_port = SPIKE_DESTINATIONS[
            index % len(SPIKE_DESTINATIONS)
        ]

        timestamp = start + timedelta(
            milliseconds=index * 30
        )

        events.append(
            create_event(
                timestamp=timestamp,
                src_ip=LOCAL_SOURCE_IP,
                dst_ip=dst_ip,
                dst_port=dst_port,
                flags="PA",
                packet_size=120,
            )
        )

    send_events(es, events)

    print(f"Traffic spike: {len(events)} events sent.")


def flood_like_traffic(es: Elasticsearch, start: datetime) -> None:
    """Generate concentrated SYN-heavy flood-like traffic."""

    dst_ip, dst_port = FLOOD_DESTINATION
    events = []

    for index in range(FLOOD_EVENTS):
        source_ip = (
            f"10.99.{index // 250}.{(index % 250) + 1}"
        )

        timestamp = start + timedelta(
            milliseconds=index * 3
        )

        events.append(
            create_event(
                timestamp=timestamp,
                src_ip=source_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                flags="S",
                packet_size=60,
            )
        )

    send_events(es, events)

    print(
        f"Flood-like traffic: {len(events)} SYN events sent "
        f"toward {dst_ip}:{dst_port}."
    )


def wait_for_window() -> datetime:
    """Wait until the next clean 10-second window begins."""

    now = datetime.now(timezone.utc)

    next_epoch = (
        int(now.timestamp() / 10) + 1
    ) * 10

    start = datetime.fromtimestamp(
        next_epoch,
        tz=timezone.utc,
    )

    wait_seconds = (
        start - now
    ).total_seconds()

    if wait_seconds > 0:
        time.sleep(wait_seconds)

    return start


def main() -> None:
    """Run the complete isolated SHIELD traffic demonstration."""

    es = Elasticsearch(ELASTICSEARCH_URL)

    if not es.ping():
        print("Elasticsearch is not reachable.")
        sys.exit(1)

    print("SHIELD safe traffic demonstration")
    print("----------------------------------")
    print("Synthetic Elasticsearch telemetry only.")
    print()

    # Phase 1: normal traffic.
    start = wait_for_window()
    normal_traffic(es, start)

    print("Waiting for normal window to complete...")
    time.sleep(12)

    # Phase 2: legitimate traffic spike.
    start = wait_for_window()
    traffic_spike(es, start)

    print("Waiting for spike window to complete...")
    time.sleep(12)

    # Phase 3: flood-like traffic.
    start = wait_for_window()
    flood_like_traffic(es, start)

    print("Waiting for flood window to complete...")
    time.sleep(12)

    print()
    print("Demo traffic generation complete.")


if __name__ == "__main__":
    main()