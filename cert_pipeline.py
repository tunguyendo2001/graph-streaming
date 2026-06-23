from __future__ import annotations

import math
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable

import pandas as pd


TARGET_USERS = [
    "JDE0001",
    "ACA0002",
    "BDP0003",
    "CFC0004",
    "EHB0005",
    "THIEF_U101",
    "SNOOP_U102",
]

EVENT_COLUMNS = [
    "timestamp",
    "event_type",
    "user_id",
    "machine_id",
    "machine_dept",
    "device_id",
    "file_id",
    "file_action",
    "is_secret",
    "source",
]

DATE_FORMAT = "%m/%d/%Y %H:%M:%S"
OUTPUT_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"


def _as_dataframe(rows: pd.DataFrame | Iterable[dict]) -> pd.DataFrame:
    if isinstance(rows, pd.DataFrame):
        return rows.copy()
    return pd.DataFrame(list(rows))


def _empty_events() -> pd.DataFrame:
    return pd.DataFrame(columns=EVENT_COLUMNS)


def _format_timestamps(values: pd.Series) -> pd.Series:
    timestamps = pd.to_datetime(values, format=DATE_FORMAT, errors="coerce")
    return timestamps.dt.strftime(OUTPUT_TIMESTAMP_FORMAT)


def _clean_event_id(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and math.isnan(value):
        return ""
    return str(value).strip().strip("{}")


def _machine_dept(machine_id: object) -> str:
    machine = "" if machine_id is None else str(machine_id)
    if machine.startswith("PC-FIN-"):
        return "Finance"
    if machine.startswith("PC-MKT-"):
        return "Marketing"
    return "Unknown"


def _finalize_events(events: pd.DataFrame) -> pd.DataFrame:
    for column in EVENT_COLUMNS:
        if column not in events.columns:
            events[column] = ""

    events = events[EVENT_COLUMNS].copy()
    events["is_secret"] = events["is_secret"].fillna(False).astype(bool)
    return events


def normalize_logon_events(rows: pd.DataFrame | Iterable[dict]) -> pd.DataFrame:
    """
    Chuyển logon.csv thành event LOGON chuẩn cho graph.

    Chỉ giữ activity=Logon vì schema demo chỉ cần cạnh LOGON từ User sang Machine.
    """
    df = _as_dataframe(rows)
    if df.empty:
        return _empty_events()

    if "activity" in df.columns:
        df = df[df["activity"].astype(str).str.lower() == "logon"].copy()
    if df.empty:
        return _empty_events()

    events = pd.DataFrame(
        {
            "timestamp": _format_timestamps(df["date"]),
            "event_type": "LOGON",
            "user_id": df["user"].astype(str),
            "machine_id": df["pc"].astype(str),
            "machine_dept": df["pc"].map(_machine_dept),
            "source": "cert-logon",
        }
    )
    return _finalize_events(events.dropna(subset=["timestamp"]))


def normalize_device_events(rows: pd.DataFrame | Iterable[dict]) -> pd.DataFrame:
    """
    Chuyển device.csv thành event CONNECT chuẩn.

    CERT r4.2 không có cột device id riêng, nên dùng id của event làm định danh device
    ổn định cho demo. Synthetic event vẫn dùng USB-DEV-01 để dễ nhìn trong Lab.
    """
    df = _as_dataframe(rows)
    if df.empty:
        return _empty_events()

    if "activity" in df.columns:
        df = df[df["activity"].astype(str).str.lower() == "connect"].copy()
    if df.empty:
        return _empty_events()

    events = pd.DataFrame(
        {
            "timestamp": _format_timestamps(df["date"]),
            "event_type": "CONNECT",
            "user_id": df["user"].astype(str),
            "machine_id": df["pc"].astype(str),
            "machine_dept": df["pc"].map(_machine_dept),
            "device_id": df["id"].map(lambda value: f"DEVICE-{_clean_event_id(value)}"),
            "source": "cert-device",
        }
    )
    return _finalize_events(events.dropna(subset=["timestamp"]))


def normalize_file_events(rows: pd.DataFrame | Iterable[dict]) -> pd.DataFrame:
    """
    Chuyển file.csv thành event FILE chuẩn.

    Để bảo vệ RAM, script tiền xử lý chỉ đọc filename và bỏ qua cột content rất lớn.
    Raw CERT file event không có action, nên mặc định là Open; kịch bản trộm file sẽ
    bơm action Copy riêng.
    """
    df = _as_dataframe(rows)
    if df.empty:
        return _empty_events()

    events = pd.DataFrame(
        {
            "timestamp": _format_timestamps(df["date"]),
            "event_type": "FILE",
            "user_id": df["user"].astype(str),
            "machine_id": df["pc"].astype(str),
            "machine_dept": df["pc"].map(_machine_dept),
            "file_id": df["filename"].astype(str),
            "file_action": "Open",
            "is_secret": False,
            "source": "cert-file",
        }
    )
    return _finalize_events(events.dropna(subset=["timestamp"]))


def create_synthetic_events(base_date: str | datetime = "2010-01-15") -> pd.DataFrame:
    """
    Bơm hai kịch bản demo có chủ đích:
    - THIEF_U101: đăng nhập lúc 02:00, cắm USB, copy 30 file mật.
    - SNOOP_U102: đăng nhập ngầm vào 6 máy Finance trong giờ hành chính.
    """
    if isinstance(base_date, str):
        base_day = pd.to_datetime(base_date).to_pydatetime().replace(hour=0, minute=0, second=0, microsecond=0)
    else:
        base_day = base_date.replace(hour=0, minute=0, second=0, microsecond=0)

    rows: list[dict] = []

    theft_start = base_day.replace(hour=2)
    rows.append(
        {
            "timestamp": theft_start.strftime(OUTPUT_TIMESTAMP_FORMAT),
            "event_type": "LOGON",
            "user_id": "THIEF_U101",
            "machine_id": "PC-9999",
            "machine_dept": "Unknown",
            "source": "synthetic-theft",
        }
    )
    rows.append(
        {
            "timestamp": (theft_start + timedelta(seconds=5)).strftime(OUTPUT_TIMESTAMP_FORMAT),
            "event_type": "CONNECT",
            "user_id": "THIEF_U101",
            "machine_id": "PC-9999",
            "machine_dept": "Unknown",
            "device_id": "USB-DEV-01",
            "source": "synthetic-theft",
        }
    )

    for index in range(1, 31):
        rows.append(
            {
                "timestamp": (theft_start + timedelta(seconds=10 + index)).strftime(OUTPUT_TIMESTAMP_FORMAT),
                "event_type": "FILE",
                "user_id": "THIEF_U101",
                "machine_id": "PC-9999",
                "machine_dept": "Unknown",
                "file_id": f"Secret_Doc_{index}.pdf",
                "file_action": "Copy",
                "is_secret": True,
                "source": "synthetic-theft",
            }
        )

    snoop_start = base_day.replace(hour=10)
    for index in range(1, 7):
        rows.append(
            {
                "timestamp": (snoop_start + timedelta(minutes=index - 1)).strftime(OUTPUT_TIMESTAMP_FORMAT),
                "event_type": "LOGON",
                "user_id": "SNOOP_U102",
                "machine_id": f"PC-FIN-{index:02d}",
                "machine_dept": "Finance",
                "source": "synthetic-snoop",
            }
        )

    return _finalize_events(pd.DataFrame(rows))


def find_cert_csvs(input_dir: Path) -> dict[str, Path]:
    """
    Tìm bộ logon/device/file trong folder CERT.

    Một số bản giải nén có dạng data/cert-r4.2/r4.2/*.csv, nên không giả định
    các file nằm ngay ở input_dir.
    """
    input_dir = Path(input_dir)
    required = {"logon.csv", "device.csv", "file.csv"}
    found: dict[str, Path] = {}

    for csv_path in input_dir.rglob("*.csv"):
        if csv_path.name in required and csv_path.name not in found:
            found[csv_path.name] = csv_path

    missing = sorted(required.difference(found))
    if missing:
        raise FileNotFoundError(f"Không tìm thấy file CERT bắt buộc: {missing} trong {input_dir}")

    return found


def _read_filtered_chunks(
    csv_path: Path,
    usecols: list[str],
    normalizer,
    chunksize: int,
    target_users: list[str],
) -> list[pd.DataFrame]:
    frames: list[pd.DataFrame] = []

    for chunk in pd.read_csv(csv_path, usecols=usecols, dtype=str, chunksize=chunksize):
        filtered = chunk[chunk["user"].isin(target_users)].copy()
        if filtered.empty:
            continue
        normalized = normalizer(filtered)
        if not normalized.empty:
            frames.append(normalized)

    retained = sum(len(frame) for frame in frames)
    print(f"[PREP] {csv_path.name}: giữ {retained} event sau khi lọc target users.")
    return frames


def prepare_cert_stream(
    input_dir: Path,
    output_csv: Path,
    max_rows: int = 5000,
    chunksize: int = 100_000,
    target_users: list[str] | None = None,
    synthetic_base_date: str = "2010-01-15",
) -> pd.DataFrame:
    """
    Tạo clean_cert_stream.csv nhỏ để stream vào Memgraph.

    Chiến lược bảo vệ máy 8GB RAM:
    - Không đọc cột content của file.csv.
    - Đọc từng chunk bằng Pandas chunksize.
    - Lọc target user ngay trong chunk.
    - Chỉ concat phần đã lọc và synthetic event nhỏ.
    """
    users = target_users or TARGET_USERS
    csvs = find_cert_csvs(input_dir)

    frames: list[pd.DataFrame] = []
    frames.extend(
        _read_filtered_chunks(
            csv_path=csvs["logon.csv"],
            usecols=["id", "date", "user", "pc", "activity"],
            normalizer=normalize_logon_events,
            chunksize=chunksize,
            target_users=users,
        )
    )
    frames.extend(
        _read_filtered_chunks(
            csv_path=csvs["device.csv"],
            usecols=["id", "date", "user", "pc", "activity"],
            normalizer=normalize_device_events,
            chunksize=chunksize,
            target_users=users,
        )
    )
    frames.extend(
        _read_filtered_chunks(
            csv_path=csvs["file.csv"],
            usecols=["id", "date", "user", "pc", "filename"],
            normalizer=normalize_file_events,
            chunksize=chunksize,
            target_users=users,
        )
    )

    frames.append(create_synthetic_events(synthetic_base_date))

    stream = pd.concat(frames, ignore_index=True) if frames else _empty_events()
    stream["_sort_ts"] = pd.to_datetime(stream["timestamp"], errors="coerce")
    stream = stream.dropna(subset=["_sort_ts"]).sort_values(["_sort_ts", "event_type", "user_id"]).head(max_rows)
    stream = stream[EVENT_COLUMNS].copy()

    output_csv = Path(output_csv)
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    stream.to_csv(output_csv, index=False, encoding="utf-8")

    print(f"[PREP] Xuất {len(stream)} event ra {output_csv.resolve()}")
    return stream


def _value(row: dict | pd.Series, key: str, default: str = ""):
    value = row.get(key, default)
    if value is None:
        return default
    if isinstance(value, float) and math.isnan(value):
        return default
    return value


def build_cypher_payload(row: dict | pd.Series) -> tuple[str, dict]:
    """
    Sinh Cypher và params tương ứng với từng event trong clean_cert_stream.csv.
    """
    event_type = str(_value(row, "event_type")).upper()
    common = {
        "timestamp": str(_value(row, "timestamp")),
        "user_id": str(_value(row, "user_id")),
    }

    if event_type == "LOGON":
        query = """
MERGE (u:User {id: $user_id})
MERGE (m:Machine {id: $machine_id})
SET m.dept = $machine_dept
CREATE (u)-[:LOGON {timestamp: $timestamp}]->(m)
"""
        params = {
            **common,
            "machine_id": str(_value(row, "machine_id")),
            "machine_dept": str(_value(row, "machine_dept", "Unknown") or "Unknown"),
        }
        return query, params

    if event_type == "CONNECT":
        query = """
MERGE (u:User {id: $user_id})
MERGE (d:Device {id: $device_id})
CREATE (u)-[:CONNECT {timestamp: $timestamp}]->(d)
"""
        params = {
            **common,
            "device_id": str(_value(row, "device_id")),
        }
        return query, params

    if event_type == "FILE":
        query = """
MERGE (u:User {id: $user_id})
MERGE (f:File {id: $file_id})
SET f.is_secret = $is_secret
CREATE (u)-[:FILE_ACTION {action: $file_action, timestamp: $timestamp}]->(f)
"""
        params = {
            **common,
            "file_id": str(_value(row, "file_id")),
            "file_action": str(_value(row, "file_action", "Open") or "Open"),
            "is_secret": str(_value(row, "is_secret", "False")).lower() in {"true", "1", "yes"},
        }
        return query, params

    raise ValueError(f"Unsupported event_type: {event_type}")


def format_stream_log(row: dict | pd.Series) -> str:
    event_type = str(_value(row, "event_type")).upper()
    timestamp = str(_value(row, "timestamp"))
    user_id = str(_value(row, "user_id"))

    if event_type == "LOGON":
        action = "đăng nhập vào máy"
        target = str(_value(row, "machine_id"))
    elif event_type == "CONNECT":
        action = "cắm thiết bị"
        target = str(_value(row, "device_id"))
    elif event_type == "FILE":
        action = f"{_value(row, 'file_action', 'Open')} file"
        target = str(_value(row, "file_id"))
    else:
        action = f"thực hiện {event_type}"
        target = ""

    return f"[STREAMING] {timestamp} | User {user_id} vừa {action} {target}"
