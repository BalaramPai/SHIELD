# File: apps/detector/service.py
# Purpose: Provides the SHIELD detector as a reusable service entry point.

from apps.detector.engine import DetectionEngine


def run() -> None:
    engine = DetectionEngine()

    print("SHIELD detector service started.")

    while True:
        engine.process()


if __name__ == "__main__":
    run()