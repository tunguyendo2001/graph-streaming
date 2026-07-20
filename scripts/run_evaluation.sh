#!/usr/bin/env bash
set -euo pipefail

controls_per_insider=2
run_size=50000
python_bin="${PYTHON:-python}"
memgraph_uri="bolt://localhost:7687"
cert_root=""
skip_prepare=0
skip_replay=0
no_docker=0

usage() {
  cat <<'USAGE'
Usage: scripts/run_evaluation.sh [options]

Options:
  --controls-per-insider N   Number of matched controls per insider (default: 2)
  --run-size N               External-sort run size for stream extraction (default: 50000)
  --python PATH              Python executable (default: $PYTHON or python)
  --memgraph-uri URI         Memgraph Bolt URI (default: bolt://localhost:7687)
  --cert-root PATH           CERT r4.2 root containing r4.2/ and answers/
  --skip-prepare             Reuse artifacts/evaluation_stream.jsonl and artifacts/cohort.json
  --skip-replay              Reuse existing graph alerts in Memgraph
  --no-docker                Do not run docker compose up -d
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
    --skip-prepare)
      skip_prepare=1
      shift
      ;;
    --skip-replay)
      skip_replay=1
      shift
      ;;
    --no-docker)
      no_docker=1
      shift
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
start_epoch="$(date +%s)"

mkdir -p artifacts

if [[ "$no_docker" -eq 0 ]]; then
  echo "[EVAL] Starting Memgraph Platform..."
  docker compose up -d
fi

if [[ "$skip_prepare" -eq 0 ]]; then
  echo "[EVAL] Preparing CERT r4.2 cohort stream..."
  "$python_bin" 1_prepare_cert_data.py \
    --input-dir "$input_dir" \
    --answers-dir "$answers_dir" \
    --output artifacts/evaluation_stream.jsonl \
    --manifest artifacts/cohort.json \
    --controls-per-insider "$controls_per_insider" \
    --run-size "$run_size"
fi

if [[ "$skip_replay" -eq 0 ]]; then
  echo "[EVAL] Replaying full stream into Memgraph..."
  "$python_bin" 2_stream_cert.py \
    --stream artifacts/evaluation_stream.jsonl \
    --uri "$memgraph_uri" \
    --reset \
    --delay 0 \
    --summary artifacts/replay_summary.json
fi

echo "[EVAL] Comparing graph motifs with flat rule baseline..."
"$python_bin" evaluation.py \
  --answers-dir "$answers_dir" \
  --stream artifacts/evaluation_stream.jsonl \
  --uri "$memgraph_uri" \
  --graph-output artifacts/graph_metrics.json \
  --rule-output artifacts/rule_metrics.json \
  --comparison-output artifacts/comparison.json

end_epoch="$(date +%s)"
elapsed_seconds="$((end_epoch - start_epoch))"
memgraph_stats=""
if command -v docker >/dev/null 2>&1; then
  memgraph_stats="$(docker stats memgraph-platform --no-stream --format '{{json .}}' 2>/dev/null || true)"
fi

RUN_PROFILE_ELAPSED="$elapsed_seconds" \
RUN_PROFILE_CONTROLS="$controls_per_insider" \
RUN_PROFILE_RUN_SIZE="$run_size" \
RUN_PROFILE_MEMGRAPH_STATS="$memgraph_stats" \
"$python_bin" - <<'PY'
import json
import os
from pathlib import Path

stats_raw = os.environ.get("RUN_PROFILE_MEMGRAPH_STATS") or ""
try:
    memgraph_stats = json.loads(stats_raw) if stats_raw else None
except json.JSONDecodeError:
    memgraph_stats = {"raw": stats_raw}

payload = {
    "elapsed_seconds": float(os.environ["RUN_PROFILE_ELAPSED"]),
    "controls_per_insider": int(os.environ["RUN_PROFILE_CONTROLS"]),
    "run_size": int(os.environ["RUN_PROFILE_RUN_SIZE"]),
    "stream": "artifacts/evaluation_stream.jsonl",
    "replay_summary": "artifacts/replay_summary.json",
    "graph_metrics": "artifacts/graph_metrics.json",
    "rule_metrics": "artifacts/rule_metrics.json",
    "comparison": "artifacts/comparison.json",
    "memgraph_stats": memgraph_stats,
}
Path("artifacts/run_profile.json").write_text(
    json.dumps(payload, indent=2, sort_keys=True),
    encoding="utf-8",
)
PY

echo "[EVAL] Outputs: artifacts/graph_metrics.json, artifacts/rule_metrics.json, artifacts/comparison.json"
echo "[EVAL] Run profile: artifacts/run_profile.json"
