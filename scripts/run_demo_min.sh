#!/usr/bin/env bash
# Demo tối giản: 1 insider scenario-1 (UC1 exfil) + 1 insider scenario-3 (UC2 credential pivot),
# không control, chỉ lấy vài tuần lịch sử quanh incident. Mục tiêu: lên alert cho cả 2 use case
# trong ~20 phút thay vì replay toàn bộ cohort 70 insider.
set -euo pipefail

uc1_insider="AAM0658"   # scenario 1, incident 2010-10-23..10-29
uc2_insider="BBS0039"   # scenario 3, incident 2010-08-12..08-13
calibration_days=14     # stream chỉ trải ~3 tuần trước incident sớm nhất -> 30 ngày sẽ nuốt hết stream
python_bin="${PYTHON:-python}"
memgraph_uri="${MEMGRAPH_URI:-bolt://localhost:7687}"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
cd "$repo_root"

cert_root=""
for candidate in "$repo_root/data/cert-r4.2" "$repo_root/../../data/cert-r4.2"; do
  if [[ -f "$candidate/answers/insiders.csv" ]]; then
    cert_root="$(cd "$candidate" && pwd)"
    break
  fi
done
[[ -n "$cert_root" ]] || { echo "Cannot find data/cert-r4.2" >&2; exit 1; }

mkdir -p artifacts
docker compose up -d

# Trích 2 stream nhỏ (bỏ qua nếu artifact đã có: quét http.csv 13GB rất tốn thời gian).
prepare() {
  local insider="$1" out="$2" manifest="$3" history_days="$4"
  if [[ -s "$out" ]]; then
    echo "[DEMO] reuse $out"
    return
  fi
  "$python_bin" 1_prepare_cert_data.py \
    --input-dir "$cert_root/r4.2" \
    --answers-dir "$cert_root/answers" \
    --output "$out" \
    --manifest "$manifest" \
    --insider-ids "$insider" \
    --controls-per-insider 0 \
    --history-days-before "$history_days" \
    --days-after-incident 2 \
    --run-size 10000
}

prepare "$uc1_insider" artifacts/demo_min_uc1.jsonl artifacts/demo_min_uc1_cohort.json 40
prepare "$uc2_insider" artifacts/demo_min_uc2.jsonl artifacts/demo_min_uc2_cohort.json 22

# Một graph, một lần replay: ReplayEngine tự external-sort nên chỉ cần nối 2 file.
cat artifacts/demo_min_uc1.jsonl artifacts/demo_min_uc2.jsonl > artifacts/demo_min_stream.jsonl
wc -l < artifacts/demo_min_stream.jsonl | xargs echo "[DEMO] events:"

"$python_bin" 2_stream_cert.py \
  --stream artifacts/demo_min_stream.jsonl \
  --uri "$memgraph_uri" \
  --reset \
  --delay 0 \
  --calibration-days "$calibration_days" \
  --summary artifacts/demo_min_summary.json

"$python_bin" - "$memgraph_uri" <<'PY'
import sys
from neo4j import GraphDatabase

with GraphDatabase.driver(sys.argv[1]) as driver, driver.session() as session:
    rows = session.run(
        "MATCH (a:Alert) RETURN a.detector AS detector, a.score AS score, a.threshold AS threshold, "
        "a.event_time AS event_time, a.user_ids AS users, a.machine_ids AS machines, "
        "size(a.evidence_event_ids) AS evidence ORDER BY a.detector, a.event_time"
    ).data()
print(f"[DEMO] alerts={len(rows)}")
for row in rows:
    print(
        f"  {row['detector']} score={row['score']:.3f} (>{row['threshold']:.3f}) "
        f"{row['event_time']} users={row['users']} machines={row['machines']} evidence={row['evidence']}"
    )
PY

echo "[DEMO] Memgraph Lab: http://localhost:3000"
