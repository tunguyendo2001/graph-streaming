#!/usr/bin/env bash
set -euo pipefail

controls_per_insider=1
run_size=10000
limit=5000
calibration_days=0
python_bin="${PYTHON:-python}"
memgraph_uri="bolt://localhost:7687"
cert_root=""

usage() {
  cat <<'USAGE'
Usage: scripts/run_demo.sh [options]

Options:
  --controls-per-insider N   Number of matched controls per insider (default: 1)
  --run-size N               External-sort run size for stream extraction (default: 10000)
  --limit N                  Number of replayed events for quick demo (default: 5000)
  --calibration-days N       Calibration window before alerts fire (default: 0 = fallback threshold immediately; the CERT stream's --limit-bounded window is only a few days, so the usual 30-day calibration default would keep every event in calibration and no alert would ever fire)
  --python PATH              Python executable (default: $PYTHON or python)
  --memgraph-uri URI         Memgraph Bolt URI (default: bolt://localhost:7687)
  --cert-root PATH           CERT r4.2 root containing r4.2/ and answers/
  -h, --help                 Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --controls-per-insider)
      controls_per_insider="$2"
      shift 2
      ;;
    --run-size)
      run_size="$2"
      shift 2
      ;;
    --limit)
      limit="$2"
      shift 2
      ;;
    --calibration-days)
      calibration_days="$2"
      shift 2
      ;;
    --python)
      python_bin="$2"
      shift 2
      ;;
    --memgraph-uri)
      memgraph_uri="$2"
      shift 2
      ;;
    --cert-root)
      cert_root="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
cd "$repo_root"

if [[ -z "$cert_root" ]]; then
  for candidate in "$repo_root/data/cert-r4.2" "$repo_root/../../data/cert-r4.2"; do
    if [[ -f "$candidate/answers/insiders.csv" ]]; then
      cert_root="$(cd "$candidate" && pwd)"
      break
    fi
  done
fi

if [[ -z "$cert_root" ]]; then
  echo "Cannot find data/cert-r4.2. Pass --cert-root explicitly." >&2
  exit 1
fi

input_dir="$cert_root/r4.2"
answers_dir="$cert_root/answers"

mkdir -p artifacts

echo "[DEMO] Starting Memgraph Platform..."
docker compose up -d

echo "[DEMO] Preparing bounded CERT r4.2 stream..."
"$python_bin" 1_prepare_cert_data.py \
  --input-dir "$input_dir" \
  --answers-dir "$answers_dir" \
  --output artifacts/evaluation_stream.jsonl \
  --manifest artifacts/cohort.json \
  --controls-per-insider "$controls_per_insider" \
  --run-size "$run_size"

echo "[DEMO] Replaying first $limit events into Memgraph..."
"$python_bin" 2_stream_cert.py \
  --stream artifacts/evaluation_stream.jsonl \
  --uri "$memgraph_uri" \
  --reset \
  --delay 0 \
  --limit "$limit" \
  --calibration-days "$calibration_days" \
  --summary artifacts/replay_summary.json

echo "[DEMO] Evaluating graph alerts vs flat rule baseline..."
"$python_bin" evaluation.py \
  --answers-dir "$answers_dir" \
  --stream artifacts/evaluation_stream.jsonl \
  --uri "$memgraph_uri" \
  --graph-output artifacts/graph_metrics.json \
  --rule-output artifacts/rule_metrics.json \
  --comparison-output artifacts/comparison.json

echo "[DEMO] Memgraph Lab: http://localhost:3000"
echo "[DEMO] Outputs: artifacts/replay_summary.json, artifacts/graph_metrics.json, artifacts/rule_metrics.json, artifacts/comparison.json"
