# File: scripts/development/demo_burst.py
# Purpose: Generates isolated synthetic normal, spike, and flood-like traffic phases for SHIELD testing.

import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from elasticsearch.helpers import bulk

from elasticsearch import Elasticsearch


ELASTICSEARCH_URL = "http://localhost:9200"
LOGS_INDEX = "logs"

LOCAL_SOURCE_IP = "192.168.0.135"

NORMAL_EVENTS = 30
SPIKE_EVENTS = 500
FLOOD_EVENTS = 4000

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

FLOOD_DESTINATION = (
    "192.168.0.1",
    80,
)


def create_event(
    timestamp: datetime,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    flags: str,
    packet_size: int,
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
        "protocol": "TCP",
        "protocol_num": 6,
        "packet_size": packet_size,
        "bytes": packet_size,
        "flags": flags,
    }


def send_events(
    es: Elasticsearch,
    events: list[dict],
) -> None:
    """Bulk-insert synthetic events into Elasticsearch."""

    actions = [
        {
            "_index": LOGS_INDEX,
            "_id": event["event_id"],
            "_source": event,
        }
        for event in events
    ]

    success, failed = bulk(
        es,
        actions,
        chunk_size=1000,
        request_timeout=60,
    )

    print(
        f"Inserted {success} synthetic events."
    )

    if failed:
        print(
            f"Failed to insert {len(failed)} events."
        )


def normal_traffic(
    es: Elasticsearch,
    start: datetime,
) -> None:
    """Generate low-volume distributed traffic."""

    events = []

    for index in range(NORMAL_EVENTS):
        dst_ip, dst_port = NORMAL_DESTINATIONS[
            index % len(NORMAL_DESTINATIONS)
        ]

        timestamp = start + timedelta(
            milliseconds=index * 200
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

    print(
        f"Normal traffic: {len(events)} events sent."
    )


def traffic_spike(
    es: Elasticsearch,
    start: datetime,
) -> None:
    """Generate high-volume distributed traffic."""

    events = []

    for index in range(SPIKE_EVENTS):
        dst_ip, dst_port = SPIKE_DESTINATIONS[
            index % len(SPIKE_DESTINATIONS)
        ]

        timestamp = start + timedelta(
            milliseconds=index * 15
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

    print(
        f"Traffic spike: {len(events)} events sent."
    )


def flood_like_traffic(
    es: Elasticsearch,
    start: datetime,
) -> None:
    """Generate concentrated SYN-heavy synthetic flood telemetry."""

    dst_ip, dst_port = FLOOD_DESTINATION

    events = []

    for index in range(FLOOD_EVENTS):
        source_ip = (
            f"10.99."
            f"{index // 250}."
            f"{(index % 250) + 1}"
        )

        timestamp = start + timedelta(
            milliseconds=index * 2
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
        f"Flood-like traffic: {len(events)} SYN events "
        f"sent toward {dst_ip}:{dst_port}."
    )


def wait_for_next_window() -> datetime:
    """Wait until the beginning of the next 10-second window."""

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
    """Run the complete controlled SHIELD demonstration."""

    es = Elasticsearch(
        ELASTICSEARCH_URL
    )

    if not es.ping():
        print(
            "Elasticsearch is not reachable."
        )
        sys.exit(1)

    print(
        "SHIELD controlled traffic demonstration"
    )
    print(
        "-----------------------------------------"
    )
    print(
        "Synthetic Elasticsearch telemetry only."
    )
    print()

    # Phase 1.
    start = wait_for_next_window()

    normal_traffic(
        es,
        start,
    )

    print(
        "Waiting for normal window..."
    )

    time.sleep(12)

    # Phase 2.
    start = wait_for_next_window()

    traffic_spike(
        es,
        start,
    )

    print(
        "Waiting for spike window..."
    )

    time.sleep(12)

    # Phase 3.
    start = wait_for_next_window()

    flood_like_traffic(
        es,
        start,
    )

    print(
        "Waiting for flood window..."
    )

    time.sleep(12)

    print()
    print(
        "Controlled demonstration complete."
    )


if __name__ == "__main__":
    main()