# File: packages/schemas/detections.py
# Purpose: Defines the shared structure for detection results produced by SHIELD detectors.

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class DetectionResult:
    event_id: str
    timestamp: datetime
    detector: str
    score: float
    threshold: float
    is_anomaly: bool
    reason: str