# SHIELD

### Smart Home Intrusion and Event Logging & Detection

SHIELD is a privacy-preserving network intrusion detection and security analysis platform designed for home and small-network environments.

The system observes network traffic metadata, analyzes network behavior, detects suspicious activity, correlates security events into incidents, and provides human-readable explanations through an AI-assisted security agent.

SHIELD is designed to evolve from a local development environment into a deployable Raspberry Pi-based network security system.

---

## Project Status

🚧 **Active Development — Pre-Release**

The current repository is the production-oriented redevelopment of the original SHIELD prototype.

The initial prototype demonstrated:

- Real-time packet metadata capture
- Elasticsearch-based event storage
- 10-second traffic-window aggregation
- Isolation Forest anomaly detection
- Kibana visualization
- Local traffic anomaly demonstrations

The current project is restructuring these components into a modular, testable, and deployable architecture.

---

## Vision

SHIELD aims to provide a lightweight network security system that can:

1. Observe network traffic without storing packet payloads.
2. Learn normal network behavior.
3. Detect anomalous and suspicious activity.
4. Correlate individual detections into meaningful security incidents.
5. Identify affected devices and network behavior.
6. Explain what happened, when it happened, and why it was considered suspicious.
7. Allow users to investigate their network through an AI-assisted security agent.
8. Run from a Raspberry Pi as a dedicated network sensor.

---

## High-Level Architecture

```text
                         HOME NETWORK
                              │
              ┌───────────────┴───────────────┐
              │                               │
           Devices                          Router
              │                               │
              └───────────────┬───────────────┘
                              │
                       SHIELD SENSOR
                       Raspberry Pi
                              │
                              ▼
                       Event Ingestion
                              │
                              ▼
                        Elasticsearch
                              │
                 ┌────────────┴────────────┐
                 │                         │
                 ▼                         ▼
          Traffic Windows            Raw Events
                 │
                 ▼
          Feature Extraction
                 │
                 ▼
         Detection Engine
                 │
          ┌──────┴──────┐
          │             │
          ▼             ▼
     ML Detection   Rule Detection
          │             │
          └──────┬──────┘
                 ▼
          Security Events
                 │
                 ▼
        Incident Correlation
                 │
                 ▼
            Risk Analysis
                 │
          ┌──────┴──────┐
          │             │
          ▼             ▼
      SHIELD UI      RAG / AI Agent