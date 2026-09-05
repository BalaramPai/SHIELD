from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class NetworkEvent:
    event_id: str
    timestamp: datetime
    sensor_id: str
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: int
    packet_size: int