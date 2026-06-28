# CERT r4.2 Streaming Graph Analytics

Demo xử lý đồ thị theo luồng với Python + Memgraph, chỉ dùng dữ liệu thật CERT r4.2 và ground truth trong `data/cert-r4.2/answers/`.

Không còn nhánh dữ liệu synthetic/fake. Pipeline hiện tại:

1. `1_prepare_cert_data.py` chọn cohort đánh giá nhẹ tài nguyên: toàn bộ insider thật trong answers + nhóm control thật được match từ lịch sử trước incident.
2. `cert_extractor.py` trích các event thật `logon/device/file/http/email` thành JSONL đã sort theo `event_ts,event_id`.
3. `2_stream_cert.py` replay JSONL vào Memgraph, cập nhật temporal graph, chạy UC1/UC2 detectors, lưu alert và summary.

## Cài đặt

```bash
pip install -r requirements.txt
```

Chạy Memgraph:

```bash
docker compose up -d
```

Khởi tạo schema trong Memgraph Lab bằng `init_schema.cypher`.

## Bước 1: tạo evaluation stream từ CERT thật

```bash
python 1_prepare_cert_data.py \
  --input-dir data/cert-r4.2/r4.2 \
  --answers-dir data/cert-r4.2/answers \
  --output artifacts/evaluation_stream.jsonl \
  --manifest artifacts/cohort.json \
  --controls-per-insider 2 \
  --run-size 50000
```

## Bước 2: replay stream vào Memgraph

```bash
python 2_stream_cert.py \
  --stream artifacts/evaluation_stream.jsonl \
  --uri bolt://localhost:7687 \
  --reset \
  --delay 0 \
  --summary artifacts/replay_summary.json
```

Demo nhanh:

```bash
python 2_stream_cert.py --stream artifacts/evaluation_stream.jsonl --reset --limit 5000
```

## Use cases graph streaming

UC1: anomalous exfiltration motif

```text
LOGON lệch baseline cá nhân -> USB -> FILE_COPY burst -> domain leak/cloud mới

S1 = 0.20A + 0.25U + 0.25F + 0.15D + 0.15C1
Gate: U > 0, C1 >= 0.60, S1 >= threshold
```

Trong đó:

- `A`: độ bất thường giờ đăng nhập theo histogram giờ của chính user.
- `U`: USB mới hoặc USB daily count tăng mạnh so với lịch sử.
- `F`: số file copy vượt robust baseline.
- `D`: độ mới của domain đối với user.
- `C1`: continuity của temporal evidence path, có stage coverage, thứ tự thời gian, cùng machine và decay 8h/30 ngày.

UC2: credential pivot motif

```text
attacker keylogger/download + USB/filecopy -> login target machine -> victim email fan-out

S2 = 0.25M + 0.25K + 0.20E + 0.15R + 0.15C2
Gate: M >= 0.60, K >= 0.40, C2 >= 0.50, S2 >= threshold
```

Trong đó:

- `M = (1 - p(user,machine)) * owner_confidence(machine)`.
- `K`: coverage + order + 48h decay của keylogger/source USB/source file/pivot/target USB.
- `E`: max(per-email fan-out deviation, 10-minute fan-out deviation).
- `R`: phần recipient nằm ngoài 90-day social neighborhood.
- `C2`: hop coverage + temporal order + identity bridge + 48h decay.

## Test

```bash
python -m unittest discover -s tests
```
