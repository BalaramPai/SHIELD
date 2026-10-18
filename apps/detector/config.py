# File: apps/detector/config.py
# Purpose: Provides configuration values used by the SHIELD detection engine.

from packages.config.settings import settings
from packages.schemas.network import (
    LOGS_INDEX,
    MIN_BASELINE_WINDOWS,
    ML_FEATURE_COLUMNS,
    PORT_SCAN_MULT,
    RESULTS_INDEX,
    THRESHOLD_SIGMA,
    WINDOW_SECONDS,
)


ELASTICSEARCH_URL = settings.elasticsearch_url

WINDOW_SIZE = WINDOW_SECONDS
BASELINE_WINDOWS = MIN_BASELINE_WINDOWS
ANOMALY_THRESHOLD_SIGMA = THRESHOLD_SIGMA
PORT_SCAN_MULTIPLIER = PORT_SCAN_MULT

FEATURE_COLUMNS = ML_FEATURE_COLUMNS

INPUT_INDEX = LOGS_INDEX
OUTPUT_INDEX = RESULTS_INDEX