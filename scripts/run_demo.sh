#!/bin/bash
set -e

docker compose up -d
python3 1_prepare_cert_data.py --input-dir data/cert-r4.2/r4.2 --answers-dir data/cert-r4.2/answers --output artifacts/evaluation_stream.jsonl --manifest artifacts/cohort.json
python3 2_stream_cert.py --stream artifacts/evaluation_stream.jsonl --reset
python3 evaluation.py
