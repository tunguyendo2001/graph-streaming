from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone

from event_model import Event


SECONDS_PER_DAY = 24 * 60 * 60


@dataclass(frozen=True)
class RuleAlert:
    alert_id: str
    detector: str
    event_id: str
    event_time: datetime
    user_id: str
    machine_id: str
    reason: str
    score: float = 1.0


class RuleUC1Detector:
    def __init__(self, *, file_threshold: int = 20, business_start_hour: int = 8, business_end_hour: int = 18):
        self.file_threshold = file_threshold
        self.business_start_hour = business_start_hour
        self.business_end_hour = business_end_hour
        self._after_hours_days: set[tuple[str, int]] = set()
        self._usb_days: set[tuple[str, int]] = set()
        self._file_counts: dict[tuple[str, int], int] = defaultdict(int)

    def observe(self, event: Event) -> RuleAlert | None:
        key = (event.user_id, _day(event.event_ts))
        if event.kind == "LOGON" and self._is_after_hours(event):
            self._after_hours_days.add(key)
            return None
        if event.kind == "DEVICE_CONNECT":
            self._usb_days.add(key)
            return None
        if event.kind == "FILE_COPY":
            self._file_counts[key] += 1
            if self._ready(key) and self._file_counts[key] >= self.file_threshold:
                return self._alert(event, "after_hours_usb_file_threshold")
            return None
        if event.kind == "HTTP" and self._ready(key) and _has_external_signal(event):
            return self._alert(event, "after_hours_usb_external_signal")
        return None

    def _ready(self, key: tuple[str, int]) -> bool:
        return key in self._after_hours_days and key in self._usb_days

    def _is_after_hours(self, event: Event) -> bool:
        hour = event.event_time.astimezone(timezone.utc).hour
        return hour < self.business_start_hour or hour >= self.business_end_hour

    def _alert(self, event: Event, reason: str) -> RuleAlert:
        return RuleAlert(
            alert_id=f"rule_uc1|{event.event_id}",
            detector="rule_uc1",
            event_id=event.event_id,
            event_time=event.event_time,
            user_id=event.user_id,
            machine_id=event.machine_id,
            reason=reason,
        )


class RuleUC2Detector:
    def __init__(
        self,
        *,
        recipient_threshold: int = 10,
        keylogger_usb_lookback_seconds: int = 48 * 60 * 60,
        new_machine_lookback_seconds: int = 30 * SECONDS_PER_DAY,
    ):
        self.recipient_threshold = recipient_threshold
        self.keylogger_usb_lookback_seconds = keylogger_usb_lookback_seconds
        self.new_machine_lookback_seconds = new_machine_lookback_seconds
        self._keylogger_times: dict[str, deque[int]] = defaultdict(deque)
        self._usb_times: dict[str, deque[int]] = defaultdict(deque)
        self._machine_times: dict[str, dict[str, int]] = defaultdict(dict)

    def observe(self, event: Event) -> RuleAlert | None:
        if event.kind == "HTTP" and _has_keylogger_signal(event):
            self._remember(self._keylogger_times[event.user_id], event.event_ts, self.keylogger_usb_lookback_seconds)
            if self._has_recent(self._usb_times[event.user_id], event.event_ts, self.keylogger_usb_lookback_seconds):
                return self._alert(event, "keylogger_usb")
            return None

        if event.kind == "DEVICE_CONNECT":
            self._remember(self._usb_times[event.user_id], event.event_ts, self.keylogger_usb_lookback_seconds)
            if self._has_recent(self._keylogger_times[event.user_id], event.event_ts, self.keylogger_usb_lookback_seconds):
                return self._alert(event, "keylogger_usb")
            return None

        if event.kind == "EMAIL" and _recipient_count(event) >= self.recipient_threshold:
            return self._alert(event, "recipient_threshold")

        if event.kind == "LOGON":
            machine_history = self._machine_times[event.user_id]
            previous = machine_history.get(event.machine_id)
            machine_history[event.machine_id] = event.event_ts
            if previous is None or event.event_ts - previous > self.new_machine_lookback_seconds:
                return self._alert(event, "unseen_machine")
        return None

    @staticmethod
    def _remember(values: deque[int], event_ts: int, horizon_seconds: int) -> None:
        values.append(event_ts)
        while values and event_ts - values[0] > horizon_seconds:
            values.popleft()

    @staticmethod
    def _has_recent(values: deque[int], event_ts: int, horizon_seconds: int) -> bool:
        return any(0 <= event_ts - value <= horizon_seconds for value in values)

    def _alert(self, event: Event, reason: str) -> RuleAlert:
        return RuleAlert(
            alert_id=f"rule_uc2|{event.event_id}",
            detector="rule_uc2",
            event_id=event.event_id,
            event_time=event.event_time,
            user_id=event.user_id,
            machine_id=event.machine_id,
            reason=reason,
        )


def _day(event_ts: int) -> int:
    return event_ts // SECONDS_PER_DAY


def _has_external_signal(event: Event) -> bool:
    return bool(
        event.properties.get("leak_signal")
        or event.properties.get("cloud_signal")
        or event.properties.get("job_signal")
        or _contains(event.properties.get("domain"), ("leak", "cloud", "job", "dropbox", "drive"))
        or _contains(event.properties.get("url"), ("leak", "cloud", "job", "dropbox", "drive"))
    )


def _has_keylogger_signal(event: Event) -> bool:
    return bool(
        event.properties.get("keylogger_signal")
        or _contains(event.properties.get("domain"), ("keylog", "keylogger"))
        or _contains(event.properties.get("url"), ("keylog", "keylogger"))
    )


def _recipient_count(event: Event) -> int:
    if "recipient_count" in event.properties:
        return int(event.properties["recipient_count"])
    return len(event.properties.get("recipients", ()))


def _contains(value, needles: tuple[str, ...]) -> bool:
    text = str(value or "").lower()
    return any(needle in text for needle in needles)
