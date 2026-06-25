# Thiết kế Streaming Graph Analytics cho CERT r4.2

## 1. Mục tiêu

Chuyển project từ mô hình “đọc CSV tuần tự rồi chạy query báo cáo” thành hệ thống
phát hiện bất thường trên đồ thị theo luồng:

1. Chỉ sử dụng dữ liệu thật từ CERT r4.2.
2. Dùng toàn bộ 70 incident thật thuộc ba scenario r4.2 và một nhóm control thật.
3. Replay event theo `event_time`.
4. Cập nhật temporal graph trong Memgraph khi từng event đến.
5. Chỉ truy vấn neighborhood bị event mới tác động.
6. Tính score tăng dần và phát sinh `Alert` ngay khi motif hoàn thành.
7. Chỉ dùng `answers/` sau detection để đánh giá precision, recall, F1 và latency.
8. Chạy được trên máy 8 GB RAM, 8 vCPU.

Project giữ stack Python + Memgraph. Không bổ sung Kafka/Redpanda để phần demo tập
trung vào graph analytics và incremental detection thay vì hạ tầng message broker.

## 2. Những điều không làm

- Không tạo user, event, file, USB hoặc máy synthetic.
- Không dùng identity hoặc khoảng thời gian trong `answers/` làm feature.
- Không dùng ground truth để chọn weight hoặc threshold.
- Không nạp toàn bộ `http.csv` hoặc `email.csv` vào RAM.
- Không lưu trường `content` lớn vào graph.
- Không coi việc ghi từng dòng CSV kèm `sleep()` là đủ để gọi là streaming analytics.
- Không tuyên bố graph làm được điều rule engine không thể làm. So sánh tập trung vào
  khả năng biểu diễn context nhiều-hop, cập nhật cục bộ, evidence path và chất lượng
  detection.

## 3. Dữ liệu và tập evaluation

### 3.1 Nguồn dữ liệu

Các nguồn thật được dùng:

| File | Ý nghĩa |
|---|---|
| `logon.csv` | Logon/Logoff của user trên PC |
| `device.csv` | Connect/Disconnect removable media; CERT không cung cấp device ID |
| `file.csv` | Mỗi dòng là một file được copy sang removable media |
| `http.csv` | URL/domain được truy cập |
| `email.csv` | Sender, recipients, size, attachment count |
| `answers/insiders.csv` | Master ground truth, chỉ dùng trong bước evaluation |
| `answers/r4.2-*/*.csv` | Observable thật của từng incident, chỉ dùng để đánh giá |

Ba scenario r4.2 có:

- Scenario 1: 30 incident.
- Scenario 2: 30 incident.
- Scenario 3: 10 incident.
- Tổng cộng: 70 incident thật.

### 3.2 Chọn controls

Mặc định chọn hai control cho mỗi insider, không lặp lại control nếu còn đủ ứng viên.
Control phải không xuất hiện trong bất kỳ ground-truth incident nào.

Việc matching dùng vector hoạt động được tính streaming từ dữ liệu thật:

```text
active_days
logon_count
after_hours_logon_ratio
device_connect_count
file_copy_count
email_count
distinct_machine_count
```

Mỗi feature được robust-standardize bằng median/MAD trên toàn cohort. Khoảng cách
matching là Euclidean distance trên vector đã chuẩn hóa. Ưu tiên ứng viên có khoảng
thời gian hoạt động giao với incident tương ứng. Tie-break theo user ID để kết quả
tái lập được.

Không cần quét `http.csv` 14.5 GB để chọn control. Sau khi đã có danh sách insider
và control, extractor mới quét từng nguồn một lần để giữ event của cohort.

### 3.3 Trích xuất tiết kiệm tài nguyên

- Đọc CSV bằng chunk/streaming iterator.
- Chỉ giữ các user thuộc evaluation cohort.
- Không đọc hoặc không ghi trường `content` vào output.
- HTTP chỉ giữ URL, domain và các lexical flags cần thiết.
- Email chỉ giữ sender, danh sách recipient, size và attachment count.
- File chỉ giữ filename và extension.
- Mỗi nguồn tạo một stream con đã có thứ tự.
- Dùng k-way merge theo `event_time` để tạo stream chung, không sort toàn bộ trong RAM.

## 4. Kiến trúc

```text
CERT r4.2 CSV thật
        |
        v
cert_extractor.py
  - chọn insider + matched controls
  - đọc theo chunk
  - bỏ content lớn
        |
        v
event_replay.py
  - k-way merge event-time
  - replay từng event hoặc micro-batch cấu hình được
        |
        v
graph_repository.py --------> Memgraph temporal graph
        |                         |
        |                         v
        +-----------------> graph_detectors.py
                              - candidate query cục bộ
                              - temporal motif traversal
                              - graph-derived features
                              - incremental score
                                      |
                                      v
                                    Alert
                                      |
                                      v
evaluation.py <--------------- answers/ chỉ ở bước này
```

### 4.1 Phân chia trách nhiệm

| Module | Trách nhiệm |
|---|---|
| `cert_extractor.py` | Tạo cohort và event stream thật |
| `event_model.py` | Kiểu dữ liệu và parser cho các event |
| `event_replay.py` | Replay theo event-time, watermark và retry |
| `graph_repository.py` | Idempotent upsert, sessionization, aggregate state |
| `baselines.py` | Median/MAD, novelty, decay và pure scoring functions |
| `graph_detectors.py` | Chạy Cypher cục bộ, dựng motif, tạo/deduplicate alert |
| `rule_detectors.py` | Rule baseline để đối chứng |
| `evaluation.py` | Ground-truth matching và metrics |
| `queries/*.cypher` | Candidate, evidence, visualization và evaluation query |

Candidate generation, identity bridge, neighborhood và evidence path bắt buộc được
truy vấn từ Memgraph. Các phép toán số học nhỏ như median/MAD có thể thực hiện bằng
pure Python trên danh sách aggregate được trả về từ neighborhood query. Score và
mọi component phải được ghi lại vào `Alert` trong graph.

## 5. Temporal graph schema

### 5.1 Node

```text
(:User {id})
(:Machine {id})
(:Event {id, kind, event_time, ingest_time, source})
(:LogonEvent:Event {activity})
(:DeviceEvent:Event {activity})
(:FileCopyEvent:Event {filename, extension})
(:HttpEvent:Event {url, keylogger_signal, job_signal, leak_signal, cloud_signal})
(:EmailEvent:Event {sender, recipient_count, size, attachments})
(:Domain {name})
(:EmailAddress {address, internal})
(:ActivityWindow {id, opened_at, closed_at, inferred})
(:UsbSession {id, opened_at, closed_at, inferred})
(:Alert {
  id, detector, score, threshold,
  event_time, detected_at, processing_latency_ms,
  evidence_start, evidence_end
})
```

`Event.id` là ID toàn cục dạng `<source>:<original-id>` vì CERT chỉ đảm bảo ID duy
nhất bên trong từng file.

### 5.2 Relationship

```text
(User)-[:ACTED]->(Event)
(Event)-[:ON_MACHINE]->(Machine)
(Event)-[:IN_ACTIVITY_WINDOW]->(ActivityWindow)
(DeviceEvent)-[:BOUNDARY_OF]->(UsbSession)
(FileCopyEvent)-[:IN_USB_SESSION]->(UsbSession)
(HttpEvent)-[:VISITED]->(Domain)
(EmailEvent)-[:SENT_TO]->(EmailAddress)
(User)-[:EMAILED {count, first_seen, last_seen}]->(EmailAddress)
(User)-[:USED_MACHINE {count, first_seen, last_seen}]->(Machine)
(Machine)-[:DOMINANT_USER {ratio, count}]->(User)
(Alert)-[:ABOUT]->(User)
(Alert)-[:EVIDENCE]->(Event)
(Alert)-[:INVOLVES]->(Machine|Domain|EmailAddress|UsbSession)
```

### 5.3 Sessionization

#### Activity window

- Mở bằng `Logon(user, pc)`.
- Đóng bằng `Logoff(user, pc)`.
- Nếu có Logon mới trước Logoff, đóng window cũ tại event mới.
- Nếu thiếu Logoff, đóng sau timeout cấu hình, mặc định 12 giờ.
- Event PC activity không có window phù hợp được gắn vào inferred window.

#### USB session

- Mở bằng `Connect(user, pc)`.
- Đóng bằng `Disconnect(user, pc)`.
- `FileCopy` được gắn vào open session gần nhất cùng user và PC.
- Nếu không có Connect vì dữ liệu bẩn, tạo inferred session quanh FileCopy.
- Nếu thiếu Disconnect, đóng sau 8 giờ.
- CERT không có device ID nên không được suy diễn rằng hai session là cùng một USB
  vật lý.

## 6. Luồng xử lý từng event

```text
1. Parse và validate event.
2. Ghi Event idempotently vào Memgraph.
3. Cập nhật ActivityWindow/UsbSession liên quan.
4. Cập nhật aggregate edge và rolling state.
5. Chạy candidate query chỉ trên user/machine/window bị thay đổi.
6. Dựng temporal motif và lấy graph-derived features.
7. Tính component score và detector score.
8. Upsert Alert nếu vượt threshold và điều kiện motif.
9. Ghi evidence path.
10. Sau cùng mới cập nhật baseline bằng event hiện tại.
```

Thứ tự 5–10 ngăn event hiện tại rò vào baseline dùng để chấm chính nó.

## 7. Chuẩn hóa score dùng chung

Mọi component nằm trong `[0,1]`.

Với đại lượng chỉ bất thường khi tăng cao:

```text
median(X) = trung vị lịch sử
MAD(X)    = median(|x - median(X)|)

z_plus(x, X) =
  max(0, (x - median(X)) / max(1, 1.4826 * MAD(X)))

deviation(x, X) = min(1, z_plus(x, X) / 4)
```

`deviation = 1` tương ứng mức lệch xấp xỉ ít nhất bốn robust standard deviations.

Baseline cá nhân dùng 30 ngày trước event. Social neighborhood dùng 90 ngày. Khi
user chưa có ít nhất 14 active days hoặc 20 event phù hợp, detector dùng baseline
toàn cohort tại cùng giai đoạn, không dùng danh sách control/insider từ answers.

Time decay:

```text
decay(duration, T) = exp(-duration / T)
```

## 8. Use case 1: Multi-stage data exfiltration

### 8.1 Ý nghĩa graph

Detector không cảnh báo chỉ vì một event ngoài giờ hoặc một lần dùng USB. Nó yêu cầu
các event tạo được evidence path có cùng identity, machine, session và thứ tự:

```text
User
 -> ActivityWindow/Logon
 -> Machine
 -> UsbSession
 -> FileCopy
 -> HttpEvent
 -> Domain
```

Hai motif được hỗ trợ:

1. Execution/leak motif: after-hours logon, USB, optional FileCopy, truy cập leak
   hoặc cloud domain trong cửa sổ ngắn.
2. Intent-to-theft motif: job/competitor activity, sau đó USB usage spike và
   optional FileCopy burst trong cửa sổ dài.

### 8.2 Công thức tổng

```text
S1 = 0.20A + 0.25U + 0.25F + 0.15D + 0.15C1
```

Trong đó:

| Thành phần | Ý nghĩa |
|---|---|
| `A` | Giờ logon lệch baseline cá nhân |
| `U` | USB mới hoặc tăng mạnh |
| `F` | Số file copy trong USB session lệch baseline |
| `D` | Domain novelty |
| `C1` | Độ hoàn chỉnh, liên tục và đúng thứ tự của motif |

### 8.3 Giờ logon bất thường `A`

Chia ngày thành 24 bucket. Dùng Laplace smoothing:

```text
p_u(h) = (logon_count_u_in_hour_h + 1)
         / (total_logon_u + 24)

A = clip(1 - p_u(h_current) / max_h(p_u(h)), 0, 1)
```

User vốn thường làm đêm sẽ không bị phạt chỉ vì giờ hiện tại nằm ngoài giờ hành
chính.

### 8.4 USB novelty/deviation `U`

```text
x_usb = số Connect trong 24 giờ hiện tại
B_usb = phân phối số Connect/ngày trong 30 ngày trước

new_usb = 1 nếu user chưa từng Connect trước event hiện tại, ngược lại 0

U = max(new_usb, deviation(x_usb, B_usb))
```

### 8.5 File copy deviation `F`

Theo semantics chính thức của CERT, mỗi dòng `file.csv` là một file copy sang
removable media:

```text
x_file = số FileCopy trong UsbSession hiện tại
B_file = phân phối FileCopy/UsbSession trước đây của user

F = deviation(x_file, B_file)
```

Nếu event hiện tại chưa thuộc USB session hợp lệ, `F = 0` và motif continuity giảm.

### 8.6 Domain novelty `D`

Gọi `c(u,d)` là số lần user đã truy cập domain trước event:

```text
D = 1 / sqrt(1 + c(u,d))
```

Ví dụ:

| Số lần trước | `D` |
|---:|---:|
| 0 | 1.00 |
| 1 | 0.71 |
| 3 | 0.50 |
| 8 | 0.33 |
| 24 | 0.20 |

Các lexical flag `job`, `leak`, `cloud` hỗ trợ xác định stage semantic nhưng không
thay thế novelty và graph continuity.

### 8.7 Motif completeness `C1`

Mỗi motif có weighted stage coverage:

```text
execution_coverage =
  0.20 * after_hours_logon_present
+ 0.25 * usb_present
+ 0.25 * file_copy_present
+ 0.30 * leak_or_cloud_domain_present

intent_coverage =
  0.25 * job_or_competitor_signal_present
+ 0.30 * usb_spike_present
+ 0.25 * file_copy_burst_present
+ 0.20 * external_contact_or_domain_present
```

```text
order =
  số cặp stage bắt buộc đúng thứ tự
  / tổng số cặp stage bắt buộc đã có đủ hai đầu

continuity =
  1 nếu stage nối được qua cùng user và machine/session
  0 nếu không tạo được evidence path

execution_motif =
  execution_coverage
  * order
  * continuity
  * decay(duration, 8 giờ)

intent_motif =
  intent_coverage
  * order
  * continuity
  * decay(duration, 30 ngày)

C1 = max(execution_motif, intent_motif)
```

FileCopy là stage tăng bằng chứng nhưng không bắt buộc tuyệt đối vì ground truth
scenario 1 chủ yếu chứa logon, device và HTTP observable.

### 8.8 Điều kiện alert UC1

```text
C1 >= 0.60
AND U > 0
AND S1 >= threshold_UC1
```

Alert được deduplicate theo `(detector, user, motif_window)` và được cập nhật nếu
evidence path mới làm score cao hơn.

## 9. Use case 2: Credential pivot và social blast radius

### 9.1 Ý nghĩa graph

Detector nối hai identity khác nhau qua cùng target machine và theo dõi hậu quả trên
email neighborhood:

```text
Attacker
 -> KeyloggerDomain
 -> SourceMachine
 -> UsbSession/FileCopy
 -> TargetMachine
 <- Victim identity
 -> MassEmail
 -> RecipientNeighborhood
```

Đây là motif nổi bật của scenario 3: attacker nghiên cứu keylogger, copy executable,
truy cập máy của victim, sau đó identity victim gửi email fan-out bất thường.

### 9.2 Công thức tổng

```text
S2 = 0.25M + 0.25K + 0.20E + 0.15R + 0.15C2
```

| Thành phần | Ý nghĩa |
|---|---|
| `M` | Identity–machine edge mới/hiếm có xét độ chắc chắn chủ máy |
| `K` | Chuỗi keylogger–USB–credential pivot |
| `E` | Email fan-out lệch baseline |
| `R` | Recipient nằm ngoài social neighborhood |
| `C2` | Multi-identity path coverage và temporal order |

### 9.3 Identity–machine novelty `M`

Memgraph duy trì:

```text
p(u,m) = logon_count(u,m) / total_logon_count(u)

owner(m) = user có logon_count(u,m) lớn nhất

owner_confidence(m) =
  logon_count(owner(m),m)
  / total_logon_count(all users,m)
```

Với identity đang truy cập máy:

```text
M = (1 - p(current_user,m)) * owner_confidence(m)
```

Máy lab/shared có `owner_confidence` thấp nên giảm false positive.

### 9.4 Keylogger–USB–pivot `K`

Stage:

```text
q = HTTP có keylogger/monitoring signal
s = USB session trên source machine
f = copy executable hoặc file đáng chú ý
p = attacker logon target machine mới/hiếm
t = USB session trên target machine
```

Lexical signal được suy ra từ URL/domain và filename, ví dụ `keylogger`,
`spectorsoft`, `monitoring` và extension thực thi. Đây là semantic feature; graph
chịu trách nhiệm chứng minh các stage thuộc cùng đường tấn công.

```text
coverage_K =
  0.25q + 0.15s + 0.20f + 0.25p + 0.15t

order_K =
  số cặp stage đúng thứ tự
  / số cặp stage bắt buộc đã có đủ hai đầu

K = coverage_K * order_K * decay(duration, 48 giờ)
```

Các cặp thứ tự chính:

```text
q < s
s <= f
f < p
p <= t
```

### 9.5 Email fan-out deviation `E`

```text
x_recipient =
  số recipient duy nhất trong email hiện tại
  hoặc trong cửa sổ 10 phút

B_recipient =
  phân phối recipient/email và recipient/10-phút
  của identity trong 30 ngày trước

E = max(
  deviation(current_email_recipient_count, per_email_baseline),
  deviation(current_10m_unique_recipient_count, window_baseline)
)
```

### 9.6 Social neighborhood novelty `R`

`N_u` là tập recipient mà identity đã gửi email trong 90 ngày trước:

```text
current = tập recipient của email/window hiện tại

R = 1 - |current intersect N_u| / max(1, |current|)
```

Mười recipient đều mới cho `R = 1`; hai recipient mới trong mười cho `R = 0.2`.

### 9.7 Evidence path completeness `C2`

```text
hop_coverage =
  số loại cạnh evidence đã xuất hiện
  / 7

temporal_order =
  số quan hệ đúng thứ tự
  / số quan hệ thứ tự được yêu cầu

identity_bridge =
  1 nếu attacker != victim
    và cả hai nối qua cùng target machine
  0 nếu không

C2 =
  hop_coverage
  * temporal_order
  * identity_bridge
  * decay(duration, 48 giờ)
```

Các quan hệ thứ tự:

```text
keylogger HTTP < source USB/FileCopy
source FileCopy < attacker target-machine logon
attacker target-machine activity < victim target-machine logon
victim logon < mass email
mass email -> recipient expansion
```

### 9.8 Điều kiện alert UC2

```text
M >= 0.60
AND K >= 0.40
AND C2 >= 0.50
AND S2 >= threshold_UC2
```

Alert UC2 được tạo khi event cuối làm hoàn thành motif, thường là victim logon hoặc
mass-email event.

## 10. Threshold và calibration

Không dùng ground truth để đặt threshold.

Calibration mặc định:

1. Replay 30 ngày đầu của cohort.
2. Tính candidate score nhưng không phát alert.
3. Xác nhận bằng evaluator rằng calibration interval không giao incident interval.
4. Đặt và đóng băng:

```text
threshold_UC1 = percentile_99.5(S1_calibration_candidates)
threshold_UC2 = percentile_99.5(S2_calibration_candidates)
```

Nếu không đủ candidate, dùng threshold bảo thủ cấu hình sẵn và đánh dấu
`threshold_source=fallback`; không dùng labels để hạ threshold.

## 11. Streaming state và retention

| State | Cửa sổ |
|---|---:|
| USB session | Tối đa 8 giờ |
| Activity window | Tối đa 12 giờ |
| UC1 execution motif | 8 giờ |
| UC1 intent motif | 30 ngày |
| UC2 pivot motif | 48 giờ |
| Email fan-out | 10 phút |
| Personal count baseline | 30 ngày |
| Social neighborhood | 90 ngày |

Raw Event cũ hơn 90 ngày có thể được prune sau khi:

- aggregate baseline đã được cập nhật;
- Alert liên quan đã lưu evidence summary;
- evaluator không còn cần raw event đó.

Long-term state như machine ownership và lifetime domain counts được giữ dưới dạng
aggregate edge/property, không cần giữ toàn bộ event.

## 12. Event đến muộn, lỗi và idempotency

- Event duplicate: `MERGE` theo global event ID.
- Event đến muộn: ghi event rồi recompute neighborhood của user/machine trong cửa
  sổ detector tối đa 48 giờ; Alert được upsert.
- CSV malformed: ghi dead-letter CSV gồm source, line number và error.
- Memgraph lỗi tạm thời: retry exponential backoff có giới hạn.
- Không cập nhật baseline nếu transaction ghi graph thất bại.
- Không bỏ qua event chỉ vì thiếu Logon/Connect; tạo inferred window/session và giảm
  continuity trong motif.

## 13. Rule-based baseline để đối chứng

Rule baseline dùng cùng raw event stream nhưng không traverse graph.

### Rule UC1

```text
alert nếu cùng user trong cùng ngày:
  logon ngoài 08:00-18:00
  AND có Device Connect
  AND (
    truy cập domain keyword leak/cloud/job
    OR file_copy_count >= fixed_limit
  )
```

### Rule UC2

```text
alert nếu:
  keylogger keyword AND USB trong 48 giờ trên cùng user
  OR email có recipient_count >= fixed_limit
  OR user logon máy chưa thấy trong 30 ngày
```

Rule baseline cố ý là một baseline phẳng, thực tế và giải thích được; nó không có
multi-identity machine bridge, social-neighborhood traversal hoặc evidence path.

## 14. Evaluation

### 14.1 Ground-truth matching

Chỉ `evaluation.py` đọc `answers/`.

- UC1 được đánh giá trên scenario 1 và 2.
- UC2 được đánh giá trên scenario 3.
- Một alert là true positive nếu:
  - detector đúng nhóm scenario;
  - user/identity liên quan khớp incident;
  - ít nhất một evidence event nằm trong incident interval;
  - evidence path kết thúc không muộn hơn incident end + detector window.
- Alert không khớp incident nào là false positive.
- Recall tính theo incident, không theo số alert.

### 14.2 Metrics

```text
precision
recall
F1
false positives / user-day
incident time-to-detect
processing latency
throughput events/second
peak process RSS
Memgraph memory usage
evidence-path completeness
```

Hai latency khác nhau:

```text
incident_time_to_detect =
  alert.evidence_end - incident.start

processing_latency =
  alert.detected_at - trigger_event.ingest_time
```

Kết quả graph detector và rule baseline được báo cáo cạnh nhau trên cùng cohort và
cùng event ordering.

## 15. Alert explainability

Mỗi Alert lưu:

```text
detector
score
threshold
threshold_source
A, U, F, D, C1
hoặc M, K, E, R, C2
user/attacker/victim
machines
domains
recipient_count
evidence event IDs
evidence_start/evidence_end
event_time
detected_at
processing_latency_ms
```

Memgraph Lab query phải trả về Alert cùng evidence path để người xem thấy vì sao
score tăng, stage nào thiếu và event nào kích hoạt cảnh báo.

## 16. Kiểm thử

### 16.1 Unit tests

- Parser của năm event type.
- Robust median/MAD và `deviation`.
- `A`, `U`, `F`, `D`, `C1`.
- `M`, `K`, `E`, `R`, `C2`.
- Time decay và temporal ordering.
- Event hiện tại không lọt vào baseline.
- Connect/FileCopy/Disconnect sessionization.
- Missing Disconnect/Logoff.
- Duplicate event idempotency.

### 16.2 Integration tests với Memgraph

- Upsert event và aggregate relationship.
- Candidate query chỉ trả affected neighborhood.
- UC1 alert được tạo đúng event kích hoạt.
- UC2 nối được hai identity qua target machine.
- Alert deduplication và score update.
- Late event recompute.
- Evidence visualization query trả path.

### 16.3 Replay tests

- Replay ít nhất một incident thật của mỗi scenario.
- Negative test bằng matched control có event đơn lẻ tương tự nhưng không đủ motif.
- So sánh graph detector với rule baseline.
- Kiểm tra peak RSS và Memgraph memory trên evaluation cohort mặc định.

## 17. Tiêu chí hoàn thành

Project chỉ được xem là đáp ứng “Xử lý đồ thị theo luồng” khi:

1. Không còn synthetic event trong preparation pipeline.
2. Event được replay theo event-time.
3. Detection chạy incremental sau từng event/micro-batch.
4. Candidate và evidence path được lấy từ temporal graph.
5. Alert xuất hiện trước khi replay kết thúc.
6. Hai detector lưu đầy đủ component score và evidence.
7. Evaluation dùng 70 incident thật và matched controls thật.
8. Có báo cáo graph-vs-rule về precision, recall, F1 và latency.
9. Demo chạy được trong giới hạn mục tiêu 8 GB RAM, 8 vCPU.
10. README giải thích rõ công thức, cách chạy và giới hạn của dataset.
