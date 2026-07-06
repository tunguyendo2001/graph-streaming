from __future__ import annotations

import heapq
import json
import shutil
import tempfile
from contextlib import ExitStack
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlparse

CERT_TIME_FORMAT = "%m/%d/%Y %H:%M:%S"

KEYLOGGER_TERMS = ("keylogger", "spectorsoft", "keystroke", "monitoring")
JOB_TERMS = ("monster.com", "careerbuilder", "job", "resume", "linkedin")
LEAK_TERMS = ("wikileaks", "pastebin")
CLOUD_TERMS = ("dropbox", "drive.google", "box.com", "onedrive")

_FLAT_RECORD_ENVELOPE_KEYS = frozenset(
    {"event_id", "source", "kind", "event_time", "event_ts", "user_id", "machine_id", "action", "pc", "properties"}
)


class FrozenList(list):
    def _blocked(self, *_args: Any, **_kwargs: Any) -> None:
        raise TypeError("FrozenList does not support mutation")

    append = extend = insert = remove = pop = clear = sort = reverse = _blocked
    __setitem__ = __delitem__ = __iadd__ = __imul__ = _blocked


class FrozenDict(dict):
    def _blocked(self, *_args: Any, **_kwargs: Any) -> None:
        raise TypeError("FrozenDict does not support mutation")

    __setitem__ = __delitem__ = clear = pop = popitem = setdefault = update = __ior__ = _blocked


def _freeze(value: Any) -> Any:
    if isinstance(value, (FrozenDict, FrozenList)):
        return value
    if isinstance(value, dict):
        return FrozenDict({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return FrozenList(_freeze(item) for item in value)
    if isinstance(value, tuple):
        return tuple(_freeze(item) for item in value)
    return value


def _clone(value: Any) -> Any:
    if isinstance(value, (FrozenDict, dict)):
        return {key: _clone(item) for key, item in value.items()}
    if isinstance(value, (FrozenList, list)):
        return [_clone(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_clone(item) for item in value)
    return value


def _parse_record_event_time(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(value)


@dataclass(frozen=True)
class Event:
    event_id: str
    source: str
    kind: str
    event_time: datetime
    user_id: str
    machine_id: str
    properties: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "properties", _freeze(_clone(self.properties)))

    @property
    def event_ts(self) -> int:
        if self.event_time.tzinfo is None:
            event_time = self.event_time.replace(tzinfo=timezone.utc)
        else:
            event_time = self.event_time.astimezone(timezone.utc)
        return int(event_time.timestamp())

    def to_record(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "source": self.source,
            "kind": self.kind,
            "event_time": self.event_time.isoformat(sep=" "),
            "event_ts": self.event_ts,
            "user_id": self.user_id,
            "machine_id": self.machine_id,
            "properties": _clone(self.properties),
        }

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> "Event":
        event_time = _parse_record_event_time(record["event_time"])
        properties = record.get("properties")
        if properties is None:
            # cert_extractor.extract_evaluation_stream writes a flattened JSONL
            # (no nested "properties" key) so the file stays human-readable;
            # anything outside the core envelope fields is a property.
            properties = {key: value for key, value in record.items() if key not in _FLAT_RECORD_ENVELOPE_KEYS}
        return cls(
            event_id=record["event_id"],
            source=record["source"],
            kind=record["kind"],
            event_time=event_time,
            user_id=record["user_id"],
            machine_id=record["machine_id"],
            properties=_freeze(_clone(properties)),
        )


def _split_addresses(*values: str) -> list[str]:
    addresses = {
        address.strip().lower()
        for value in values
        for address in (value or "").split(";")
        if address.strip()
    }
    return sorted(addresses)


def _domain(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


def _contains(value: str, terms: tuple[str, ...]) -> bool:
    lowered = value.lower()
    return any(term in lowered for term in terms)


def parse_cert_row(source: str, row: dict[str, str]) -> Event:
    source = source.lower()
    event_time = datetime.strptime(row["date"], CERT_TIME_FORMAT)
    common = dict(
        event_id=f"{source}:{row['id']}",
        source=source,
        event_time=event_time,
        user_id=row["user"],
        machine_id=row["pc"],
    )

    if source == "logon":
        activity = row["activity"].strip().upper()
        if activity not in {"LOGON", "LOGOFF"}:
            raise ValueError(f"Unsupported logon activity: {row['activity']}")
        return Event(kind=activity, properties={"activity": activity}, **common)

    if source == "device":
        activity = row["activity"].strip().lower()
        if activity == "connect":
            kind = "DEVICE_CONNECT"
            normalized = "CONNECT"
        elif activity == "disconnect":
            kind = "DEVICE_DISCONNECT"
            normalized = "DISCONNECT"
        else:
            raise ValueError(f"Unsupported device activity: {row['activity']}")
        return Event(kind=kind, properties={"activity": normalized}, **common)

    if source == "file":
        filename = row["filename"]
        return Event(
            kind="FILE_COPY",
            properties={"filename": filename, "extension": Path(filename).suffix.lower()},
            **common,
        )

    if source == "http":
        url = row["url"]
        domain = _domain(url)
        searchable = f"{domain} {url}"
        return Event(
            kind="HTTP",
            properties={
                "url": url,
                "domain": domain,
                "keylogger_signal": _contains(searchable, KEYLOGGER_TERMS),
                "job_signal": _contains(searchable, JOB_TERMS),
                "leak_signal": _contains(searchable, LEAK_TERMS),
                "cloud_signal": _contains(searchable, CLOUD_TERMS),
            },
            **common,
        )

    if source == "email":
        recipients = _split_addresses(row.get("to", ""), row.get("cc", ""), row.get("bcc", ""))
        return Event(
            kind="EMAIL",
            properties={
                "sender": row.get("from", "").strip().lower(),
                "recipients": recipients,
                "recipient_count": len(recipients),
                "size": int(row.get("size") or 0),
                "attachments": int(row.get("attachments") or 0),
            },
            **common,
        )

    raise ValueError(f"Unsupported CERT source: {source}")


DEFAULT_SORT_RUN_SIZE = 20000


def load_sorted_stream(stream_path: Path | str, run_size: int = DEFAULT_SORT_RUN_SIZE) -> tuple[Iterator[Event], int, int]:
    """
    Đọc JSONL event stream theo thứ tự (event_ts, event_id) mà không cần load toàn bộ
    file vào RAM cùng lúc: dùng external merge sort (giống cert_extractor.py) để giới
    hạn bộ nhớ đỉnh còn khoảng run_size record, bất kể file gốc lớn cỡ nào.

    Trả về (event_iterator, late_events, recomputed_neighborhoods), trong đó hai số đếm
    cuối phản ánh thứ tự thật trên đĩa (trước khi sắp xếp lại).
    """
    if run_size <= 0:
        raise ValueError("run_size must be greater than 0")

    stream_path = Path(stream_path)
    if not stream_path.exists():
        raise FileNotFoundError(f"stream file not found: {stream_path}")

    temp_parent = stream_path.parent if str(stream_path.parent) else None
    temp_dir = tempfile.mkdtemp(dir=temp_parent, prefix=f".{stream_path.stem}-sort-")
    try:
        run_paths, late_events, recomputes = _write_sorted_event_runs(stream_path, Path(temp_dir), run_size)
    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise

    return _merge_sorted_event_runs(run_paths, temp_dir), late_events, recomputes


def _write_sorted_event_runs(stream_path: Path, temp_dir: Path, run_size: int) -> tuple[list[Path], int, int]:
    run_paths: list[Path] = []
    batch: list[dict[str, Any]] = []
    late_events = 0
    recomputes = 0
    max_seen_ts: int | None = None

    def flush() -> None:
        if not batch:
            return
        batch.sort(key=lambda record: (record["event_ts"], record["event_id"]))
        run_path = temp_dir / f"run-{len(run_paths):06d}.jsonl"
        with run_path.open("w", encoding="utf-8") as handle:
            for record in batch:
                handle.write(json.dumps(record, separators=(",", ":")))
                handle.write("\n")
        run_paths.append(run_path)
        batch.clear()

    with stream_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                record = json.loads(stripped)
            except Exception as exc:  # pragma: no cover - message matters more than branch shape
                raise ValueError(f"invalid JSONL event at {stream_path}:{line_number}: {exc}") from exc
            event_ts = record["event_ts"]
            if max_seen_ts is not None and event_ts < max_seen_ts:
                late_events += 1
                if max_seen_ts - event_ts <= 48 * 60 * 60:
                    recomputes += 1
            max_seen_ts = max(max_seen_ts or event_ts, event_ts)
            batch.append(record)
            if len(batch) >= run_size:
                flush()
        flush()

    return run_paths, late_events, recomputes


def _merge_sorted_event_runs(run_paths: list[Path], temp_dir: str) -> Iterator[Event]:
    try:
        with ExitStack() as stack:
            iterators = [
                _jsonl_record_iterator(stack.enter_context(run_path.open("r", encoding="utf-8")))
                for run_path in run_paths
            ]
            for record in heapq.merge(*iterators, key=lambda record: (record["event_ts"], record["event_id"])):
                yield Event.from_record(record)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def _jsonl_record_iterator(handle):
    for line in handle:
        stripped = line.strip()
        if stripped:
            yield json.loads(stripped)
