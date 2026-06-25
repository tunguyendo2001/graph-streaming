# Streaming Graph Analytics for CERT r4.2

This project is a resource-bounded Python + Memgraph pipeline that replays real CERT r4.2 events and performs incremental temporal-motif detection.

## Features
- Only uses real data (no synthetic generation).
- Uses all 70 incidents and matched controls.
- Incremental detection logic during event replay.
- Graph detection evaluated alongside flat baseline rules.

## Requirements
- Python 3.11+
- Memgraph Platform (Docker)
- 8GB RAM

## Run the Demo
1. Run `docker-compose up -d` to start Memgraph.
2. Prepare the data: `python 1_prepare_cert_data.py --input-dir data/cert-r4.2/r4.2 --answers-dir data/cert-r4.2/answers --output artifacts/evaluation_stream.jsonl --manifest artifacts/cohort.json`
3. Stream the data: `python 2_stream_cert.py --stream artifacts/evaluation_stream.jsonl --reset`
4. Evaluate: `python evaluation.py`

## Detection Rules
- **UC1**: S1 = 0.20A + 0.25U + 0.25F + 0.15D + 0.15C1
- **UC2**: S2 = 0.25M + 0.25K + 0.20E + 0.15R + 0.15C2

## Limitations
- CERT has no removable-device ID.
- Source files are replayed rather than received from Kafka.
