# File: apps/detector/features.py
# Purpose: Extracts the ML feature vector from aggregated network traffic windows.

import numpy as np

from apps.detector.config import FEATURE_COLUMNS


def build_feature_vector(window: dict) -> np.ndarray:
    return np.array(
        [[float(window[column]) for column in FEATURE_COLUMNS]],
        dtype=float,
    )