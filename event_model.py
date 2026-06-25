from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

CERT_TIME_FORMAT = "%m/%d/%Y %H:%M:%S"

KEYLOGGER_TERMS = ("keylogger", "spectorsoft", "keystroke", "monitoring")
JOB_TERMS = ("monster.com", "careerbuilder", "job", "resume", "linkedin")
LEAK_TERMS = ("wikileaks", "pastebin")
CLOUD_TERMS = ("dropbox", "drive.google", "box.com", "onedrive")


@dataclass(frozen=True)
class Event:
    event_id: str
    source: str
    kind: str
    event_time: datetime
    user_id: str
    machine_id: str
    properties: dict[str, Any] = field(default_factory=dict)

    @property
    def event_ts(self) -> int:
        return int(self.event_time.replace(tzinfo=timezone.utc).timestamp())

    def to_record(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "source": self.source,
            "kind": self.kind,
            "event_time": self.event_time.isoformat(sep=" "),
            "event_ts": self.event_ts,
            "user_id": self.user_id,
            "machine_id": self.machine_id,
            "properties": self.properties,
        }

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> "Event":
        return cls(
            event_id=record["event_id"],
            source=record["source"],
            kind=record["kind"],
            event_time=datetime.fromisoformat(record["event_time"]),
            user_id=record["user_id"],
            machine_id=record["machine_id"],
            properties=dict(record.get("properties", {})),
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
    event_time = datetime.strptime(row["date"], CERT_TIME_FORMAT)
    common = dict(
        event_id=f"{source}:{row['id']}",
        source=source,
        event_time=event_time,
        user_id=row["user"],
        machine_id=row["pc"],
    )

    if source == "logon":
        activity = row["activity"].upper()
        return Event(kind=activity, properties={"activity": activity}, **common)

    if source == "device":
        activity = row["activity"].upper()
        kind = "DEVICE_CONNECT" if activity == "CONNECT" else "DEVICE_DISCONNECT"
        return Event(kind=kind, properties={"activity": activity}, **common)

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
