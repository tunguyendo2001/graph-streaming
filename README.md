# CERT Insider Threat Streaming Graph Demo

Dự án demo "Xử lý đồ thị theo luồng thời gian thực" với Memgraph và Python.

Nguồn dữ liệu chính là CMU CERT Insider Threat r4.2 đã giải nén tại:

```text
data/cert-r4.2
```

Pipeline hiện tại gồm 2 bước:

1. `1_prepare_cert_data.py`: lọc CERT dataset theo 7 target users, bơm synthetic insider events, xuất `clean_cert_stream.csv`.
2. `2_stream_cert.py`: đọc `clean_cert_stream.csv` và stream từng event vào Memgraph qua Bolt.

## Cài dependencies

```bash
pip install -r requirements.txt
```

## Chạy Memgraph Platform

Dùng Docker Compose:

```bash
docker compose up -d
```

Hoặc dùng script:

```powershell
.\scripts\run_memgraph.ps1
```

Memgraph Lab:

```text
http://localhost:3000
```

Bolt URI:

```text
bolt://localhost:7687
```

## Khởi tạo index

Mở Memgraph Lab và chạy:

```cypher
CREATE INDEX ON :User(id);
CREATE INDEX ON :Machine(id);
CREATE INDEX ON :File(id);
CREATE INDEX ON :Device(id);
```

Hoặc copy nội dung từ `init_schema.cypher`.

## Bước 1: Chuẩn bị dữ liệu CERT

Script đọc CSV theo chunk và chỉ đọc các cột cần thiết để bảo vệ RAM máy 8GB.

```bash
python 1_prepare_cert_data.py --input-dir data/cert-r4.2 --output clean_cert_stream.csv --max-rows 5000
```

Kết quả là file:

```text
clean_cert_stream.csv
```

## Bước 2: Stream vào Memgraph

```bash
python 2_stream_cert.py --csv clean_cert_stream.csv --reset
```

Demo nhanh vài dòng:

```bash
python 2_stream_cert.py --csv clean_cert_stream.csv --reset --limit 50
```

## Query báo cáo

Mở `cert_queries.cypher` trong Memgraph Lab để chạy:

1. Bắt user đăng nhập đêm, cắm USB, copy file mật.
2. Bắt user đăng nhập vào nhiều máy Finance.

## Test

```bash
python -m unittest discover -s tests
```
