# CERT r4.2 Streaming Graph Analytics

Project này demo xử lý đồ thị theo luồng với Python + Memgraph, chỉ dùng dữ liệu thật CERT r4.2 và ground truth trong `data/cert-r4.2/answers/`.

Không còn dữ liệu fake/synthetic để “ép” demo. Tập đánh giá được dựng từ:

- 70 insider thật của CERT r4.2 trong `answers/insiders.csv`: scenario 1 có 30, scenario 2 có 30, scenario 3 có 10.
- Nhóm control thật được match từ lịch sử trước incident, mặc định 2 control / insider.
- Event thật từ `logon.csv`, `device.csv`, `file.csv`, `http.csv`, `email.csv`.

## Vì sao dùng graph streaming thay rule-based phẳng?

Rule-based truyền thống chỉ nhìn điều kiện cục bộ như “sau giờ làm + có USB + copy nhiều file” hoặc “email nhiều recipient”. Cách đó dễ miss khi hành vi được chia nhỏ theo thời gian, đổi máy, hoặc cần nối nhiều identity.

Graph streaming trong project này làm tốt hơn ở 3 điểm:

1. Mỗi event mới được ghi vào temporal graph ngay khi replay.
2. Detector chỉ chấm lại neighborhood liên quan đến event mới, không scan toàn bộ CSV.
3. Alert dựa trên evidence path có thứ tự thời gian, quan hệ user-machine-domain-email, độ mới của cạnh, baseline cá nhân và motif nhiều hop.

Nói ngắn gọn: rule hỏi “event này có vượt ngưỡng không?”, graph hỏi “event này có hoàn tất một chuỗi quan hệ đáng ngờ không?”.

## Kiến trúc pipeline

```text
CERT r4.2 CSV + answers/
        |
        v
1_prepare_cert_data.py
  - load 70 insider thật
  - match control thật
  - external sort JSONL theo event_ts,event_id
        |
        v
artifacts/evaluation_stream.jsonl
        |
        v
2_stream_cert.py
  - replay event-time stream
  - upsert event vào Memgraph
  - cập nhật baseline / temporal sessions
  - chạy UC1 + UC2 incremental detectors
        |
        v
Memgraph Alert nodes + artifacts/replay_summary.json
        |
        v
evaluation.py
  - đọc graph alerts
  - chạy flat rule baseline trên cùng stream
  - so sánh với answers/ ground truth
```

## Cài đặt

```powershell
python -m pip install -r requirements.txt
docker compose up -d
```

Memgraph Lab chạy ở `http://localhost:3000`, Bolt URI mặc định là `bolt://localhost:7687`.

Khởi tạo schema bằng cách chạy nội dung `init_schema.cypher` trong Memgraph Lab.

## Chạy nhanh demo

```powershell
.\scripts\run_demo.ps1
```

Linux/macOS:

```bash
chmod +x scripts/run_demo.sh
./scripts/run_demo.sh
```

Script này dùng 1 control / insider, trích stream nhỏ hơn, replay 5.000 event đầu và ghi:

- `artifacts/evaluation_stream.jsonl`
- `artifacts/cohort.json`
- `artifacts/replay_summary.json`
- `artifacts/graph_metrics.json`
- `artifacts/rule_metrics.json`
- `artifacts/comparison.json`

Nếu dữ liệu CERT nằm ngoài repo hiện tại, truyền rõ:

```powershell
.\scripts\run_demo.ps1 -CertRoot "D:\path\to\data\cert-r4.2"
```

Linux/macOS:

```bash
./scripts/run_demo.sh --cert-root /path/to/data/cert-r4.2
```

## Chạy full evaluation cohort

```powershell
.\scripts\run_evaluation.ps1
```

Linux/macOS:

```bash
chmod +x scripts/run_evaluation.sh
./scripts/run_evaluation.sh
```

Mặc định script dùng 2 control / insider và không giới hạn replay. Kết quả chính:

- `artifacts/graph_metrics.json`: precision, recall, F1, false positive rate, MTTD của graph motifs.
- `artifacts/rule_metrics.json`: cùng metric cho flat rules.
- `artifacts/comparison.json`: delta giữa graph và rule.
- `artifacts/run_profile.json`: elapsed time, config cohort, đường dẫn artifact, Docker memory snapshot.

Có thể bỏ qua bước đã chạy trước:

```powershell
.\scripts\run_evaluation.ps1 -SkipPrepare -SkipReplay
```

Linux/macOS:

```bash
./scripts/run_evaluation.sh --skip-prepare --skip-replay
```

## Chạy từng bước thủ công

### 1. Chuẩn bị stream từ CERT thật

```powershell
python 1_prepare_cert_data.py `
  --input-dir data/cert-r4.2/r4.2 `
  --answers-dir data/cert-r4.2/answers `
  --output artifacts/evaluation_stream.jsonl `
  --manifest artifacts/cohort.json `
  --controls-per-insider 2 `
  --run-size 50000
```

### 2. Replay stream vào Memgraph

```powershell
python 2_stream_cert.py `
  --stream artifacts/evaluation_stream.jsonl `
  --uri bolt://localhost:7687 `
  --reset `
  --delay 0 `
  --summary artifacts/replay_summary.json
```

Demo bounded:

```powershell
python 2_stream_cert.py --stream artifacts/evaluation_stream.jsonl --reset --limit 5000 --delay 0
```

### 3. So sánh graph detector với rule baseline

```powershell
python evaluation.py `
  --answers-dir data/cert-r4.2/answers `
  --stream artifacts/evaluation_stream.jsonl `
  --uri bolt://localhost:7687 `
  --graph-output artifacts/graph_metrics.json `
  --rule-output artifacts/rule_metrics.json `
  --comparison-output artifacts/comparison.json
```

### Cohort tối thiểu chỉ đủ demo UC1 + UC2 (máy yếu / 8GB RAM)

Cohort mặc định (70 insider thật + control) tạo ra một graph quá lớn cho Memgraph chạy trên
máy 8GB, dù bước Python đọc stream đã bounded memory. Nếu chỉ cần demo đúng 2 motif, dùng
`--insider-ids` để giới hạn `1_prepare_cert_data.py` xuống 1 insider đại diện cho mỗi use case
thay vì toàn bộ 70 insider:

```bash
python 1_prepare_cert_data.py \
  --insider-ids AAM0658,BBS0039 \
  --controls-per-insider 1 \
  --output artifacts/demo_stream.jsonl \
  --manifest artifacts/demo_cohort.json

python 2_stream_cert.py --stream artifacts/demo_stream.jsonl --reset --replay-run-size 5000
```

- `AAM0658` (scenario 1): chắc chắn bắn alert UC1 exfiltration motif (leak domain sau USB burst).
- `BBS0039` (scenario 3): chắc chắn bắn alert UC2 credential pivot motif. Vì UC2 cần cả danh
  tính "nạn nhân" bị pivot tới, `1_prepare_cert_data.py` tự động đọc file ground-truth chi tiết
  của incident (`answers/r4.2-<scenario>/<details_file>`) và thêm mọi user_id xuất hiện trong đó
  vào cohort (ví dụ `FAW0032` cho BBS0039) — không cần khai báo tay.
- Cohort này chỉ còn ~5 user thay vì 210, nên tổng số node/cạnh trong Memgraph nhỏ hơn hàng
  chục lần so với cohort đầy đủ.
- Muốn thêm ví dụ UC1 khác (intent + USB spike thay vì leak domain), dùng `VSS0154` (scenario 2)
  thay cho/thêm vào `AAM0658`.

## Temporal graph schema

Node chính:

- `User(id)`
- `Machine(id)`
- `Event(id, kind, event_ts, user_id, machine_id, ...)`
- `Domain(name)`
- `EmailAddress(address)`
- `ActivityWindow(id)`
- `UsbSession(id)`
- `Alert(id, detector, score, threshold, components, evidence_event_ids, ...)`

Quan hệ chính:

- `(User)-[:ACTED]->(Event)`
- `(Event)-[:ON_MACHINE]->(Machine)`
- `(User)-[:USED_MACHINE]->(Machine)`
- `(Event)-[:VISITED_DOMAIN]->(Domain)`
- `(Event)-[:SENT_TO]->(EmailAddress)`
- `(User)-[:EMAILED]->(EmailAddress)`
- `(Event)-[:IN_WINDOW]->(ActivityWindow)`
- `(Event)-[:IN_USB_SESSION]->(UsbSession)`
- `(Alert)-[:EVIDENCE]->(Event)`
- `(Alert)-[:ABOUT]->(User)`
- `(Alert)-[:INVOLVES]->(Machine)`

## Use case 1: anomalous exfiltration motif

Motif:

```text
LOGON lệch baseline cá nhân
  -> USB connect
  -> FILE_COPY burst hoặc domain leak/job/cloud mới
  -> cùng user/machine trong temporal evidence path
```

Score:

```text
S1 = 0.20A + 0.25U + 0.25F + 0.15D + 0.15C1
Gate: U > 0, C1 >= 0.60, S1 >= threshold
```

Thành phần:

- `A`: bất thường giờ đăng nhập theo histogram giờ của chính user.
- `U`: USB mới hoặc số lần USB trong ngày tăng mạnh so với lịch sử.
- `F`: số file copy vượt robust baseline cá nhân.
- `D`: domain mới đối với user, ưu tiên leak/cloud/job signal.
- `C1`: continuity của path, gồm stage coverage, đúng thứ tự thời gian, cùng machine và decay theo khoảng cách thời gian.

Điểm khác rule-based: UC1 không chỉ bắt “copy nhiều file”; nó bắt motif có ngữ cảnh trước/sau, ví dụ scenario 2 có USB spike + job-domain intent dù không có một burst file-copy đơn giản.

## Use case 2: credential pivot motif

Motif:

```text
attacker keylogger/download + USB/filecopy
  -> credential pivot sang machine của victim
  -> victim email fan-out / recipient ngoài social neighborhood
```

Score:

```text
S2 = 0.25M + 0.25K + 0.20E + 0.15R + 0.15C2
Gate: M >= 0.60, K >= 0.40, C2 >= 0.50, S2 >= threshold
```

Thành phần:

- `M = (1 - p(user,machine)) * owner_confidence(machine)`: identity-machine edge mới/hiếm, có xét machine thường thuộc về ai.
- `K`: coverage + order + 48h decay của keylogger/source USB/source file/pivot/target USB.
- `E`: độ lệch email fan-out của victim theo per-email và cửa sổ 10 phút.
- `R`: tỷ lệ recipient mới nằm ngoài 90-day social neighborhood.
- `C2`: continuity của multi-hop path, gồm hop coverage, temporal order, identity bridge và 48h decay.

Điểm khác rule-based: rule có thể flag “unseen machine” hoặc “email nhiều người”, nhưng UC2 nối được attacker -> machine pivot -> victim email burst trong cùng evidence path.

## Threshold calibration

`2_stream_cert.py` dùng các ngày đầu stream làm calibration window, mặc định 30 ngày:

```text
threshold_uc1 = percentile_99.5(score_uc1 trong calibration window)
threshold_uc2 = percentile_99.5(score_uc2 trong calibration window)
```

Nếu calibration window chưa đủ candidate, fallback threshold mặc định là `0.75`. Có thể chỉnh:

```powershell
python 2_stream_cert.py --calibration-days 30
$env:UC1_FALLBACK_THRESHOLD="0.75"
$env:UC2_FALLBACK_THRESHOLD="0.75"
```

Replay summary ghi `thresholds`, `processed_events`, `alerts_persisted`, `throughput_events_per_second`, `peak_python_rss_mb`, `late_events`, `recomputed_neighborhoods`.

## Flat rule baseline

`rule_detectors.py` là baseline không dùng graph:

- Rule UC1: after-hours logon + USB cùng ngày + file-count threshold hoặc external signal.
- Rule UC2: keylogger gần USB, hoặc email recipient threshold, hoặc unseen machine.

`evaluation.py` chạy rule baseline trên cùng `artifacts/evaluation_stream.jsonl`, rồi so với graph alerts theo cùng ground truth `answers/insiders.csv`.

## Memgraph Lab visualization

Chạy các query trong thư mục `queries/`:

- `queries/alerts.cypher`: xem alert mới nhất, trigger event và event evidence.
- `queries/uc1_evidence.cypher`: inspect evidence path UC1 quanh user/time.
- `queries/uc2_evidence.cypher`: inspect multi-identity evidence path UC2 quanh victim/machine/time.

Ví dụ xem alert evidence tổng quát:

```cypher
MATCH (alert:Alert)-[:EVIDENCE]->(event:Event)
OPTIONAL MATCH (alert)-[:ABOUT]->(user:User)
OPTIONAL MATCH (alert)-[:INVOLVES]->(machine:Machine)
RETURN alert, event, user, machine
ORDER BY alert.event_time DESC
LIMIT 100;
```

## Yêu cầu tài nguyên

Thiết kế hiện tại dành cho máy 8GB RAM / 8 vCPU:

- Không load toàn bộ CERT vào memory; extraction (bước 1) dùng external sorted runs.
- Replay (bước 2, `2_stream_cert.py`/`event_replay.py`) cũng dùng external merge sort để đọc
  `evaluation_stream.jsonl` theo lô `--replay-run-size` (mặc định 20.000 event/lô) thay vì nạp
  toàn bộ stream vào RAM cùng lúc, nên RAM đỉnh của tiến trình Python gần như không phụ thuộc
  vào tổng số event trong cohort. `evaluation.py` (bước 3, rule baseline) dùng chung cơ chế này.
- Chỉ dựng evaluation cohort gồm 70 insider thật + control thật được match.
- Docker Compose cap Memgraph container ở 6GB để chừa RAM cho Python và OS.
- Replay có pruning mặc định 90 ngày cho event cũ.

### Bắt buộc: `vm.max_map_count` trên host Linux

Memgraph log cảnh báo này mỗi lần khởi động nhưng rất dễ bị bỏ qua:

```text
Max virtual memory areas vm.max_map_count 65530 is too low, increase to at least 262144
```

`vm.max_map_count` mặc định trên Ubuntu (65530) quá thấp cho allocator dựa trên mmap của
Memgraph. Khi bị chặn ở mức này, container có thể báo "Memory limit exceeded" / bị OOM-killed
**gần như ngay khi khởi động, kể cả khi graph gần như rỗng** — dễ nhầm là do dữ liệu/query quá
nặng trong khi nguyên nhân thật là setting hệ điều hành. Sửa một lần trên host (cần `sudo`):

```bash
# Áp dụng ngay (mất khi reboot)
sudo sysctl -w vm.max_map_count=262144

# Áp dụng vĩnh viễn
echo "vm.max_map_count=262144" | sudo tee /etc/sysctl.d/99-memgraph.conf
sudo sysctl --system

# Restart lại container để nhận setting mới
docker compose restart memgraph-platform
```

Nếu vẫn OOM ở bước replay trên máy yếu, giảm dần theo thứ tự sau:

```bash
# 1. Giảm số event mỗi lô sort ngoài bộ nhớ (RAM đỉnh của Python ~ tỉ lệ thuận với số này)
python 2_stream_cert.py --stream artifacts/evaluation_stream.jsonl --reset --replay-run-size 5000

# 2. Giảm cohort (ít control hơn mỗi insider => stream nhỏ hơn, ít node/cạnh hơn trong Memgraph)
./scripts/run_evaluation.sh --controls-per-insider 1
```

```powershell
.\scripts\run_evaluation.ps1 -ControlsPerInsider 1
```

## Giới hạn đã biết

- CERT r4.2 không có removable-device ID thật, nên `UsbSession` được suy luận theo user-machine-connect window.
- Source file là CSV được replay theo event-time, chưa nhận event từ Kafka/socket thật. Đây vẫn là streaming graph analytics ở tầng xử lý: mỗi event được ingest tuần tự, cập nhật graph và detector incremental.
- Ground truth chỉ có insider interval ở `answers/`; không có nhãn từng event, nên evaluation match alert theo user + scenario + time window.

## Test

```powershell
python -m compileall .
python -m unittest discover -s tests -v
docker compose config
```

Integration Memgraph live:

```powershell
docker compose up -d
$env:MEMGRAPH_URI="bolt://localhost:7687"
python -m unittest tests.test_graph_repository_integration -v
```
