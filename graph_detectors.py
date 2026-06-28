from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence

from baselines import (
    domain_novelty,
    logon_hour_anomaly,
    robust_deviation,
    score_uc1,
    temporal_order,
    time_decay,
    usb_deviation,
    weighted_coverage,
)
from event_model import Event
from graph_repository import AlertRecord


UC1_DETECTOR = "uc1_exfiltration_motif"
UC1_MIN_CONTINUITY = 0.60
SECONDS_PER_DAY = 24 * 60 * 60


@dataclass(frozen=True)
class DetectionScore:
    score: float
    components: dict[str, float]
    evidence_event_ids: tuple[str, ...]
    machine_ids: tuple[str, ...]
    evidence_start_ts: int
    evidence_end_ts: int
    baseline_sizes: dict[str, int]


class UC1Detector:
    """Incremental graph score for LOGON -> USB -> FILE_COPY -> external domain motifs."""

    def score(self, trigger: Event, context: Mapping[str, Any]) -> DetectionScore:
        trigger_record = _trigger_record(trigger)
        trigger_ts = int(context.get("trigger_ts") or trigger.event_ts)

        history_events = [
            event
            for event in _normalise_events(context.get("history_events", ()))
            if event["event_ts"] < trigger_ts
        ]
        candidate_events = [
            event
            for event in _normalise_events(context.get("candidate_events", ()))
            if event["event_ts"] <= trigger_ts
        ]
        if trigger_record["event_id"] not in {event["event_id"] for event in candidate_events}:
            candidate_events.append(trigger_record)
        candidate_events.sort(key=lambda event: (event["event_ts"], event["event_id"]))

        logon_event = _latest_event(candidate_events, {"LOGON"}, trigger_ts)
        usb_event = _latest_event(candidate_events, {"DEVICE_CONNECT"}, trigger_ts)
        file_events = _events_of_kind(candidate_events, {"FILE_COPY"}, trigger_ts)
        external_events = [
            event
            for event in candidate_events
            if event["event_ts"] <= trigger_ts and _has_external_signal(event)
        ]

        A = _after_hours_component(logon_event, history_events)
        U = _usb_component(usb_event, candidate_events, history_events, trigger_ts, trigger.machine_id)
        F = _file_copy_component(file_events, history_events, trigger_ts)
        D = _domain_component(external_events, history_events)
        C1 = _continuity_component(
            A=A,
            U=U,
            F=F,
            D=D,
            logon_event=logon_event,
            usb_event=usb_event,
            file_events=file_events,
            external_events=external_events,
            trigger_ts=trigger_ts,
        )
        components = {"A": A, "U": U, "F": F, "D": D, "C1": C1}

        evidence_events = _ordered_evidence(logon_event, usb_event, file_events, external_events)
        evidence_ids = tuple(event["event_id"] for event in evidence_events)
        machine_ids = tuple(sorted({event["machine_id"] for event in evidence_events if event.get("machine_id")}))
        evidence_start_ts = evidence_events[0]["event_ts"] if evidence_events else trigger_ts
        evidence_end_ts = evidence_events[-1]["event_ts"] if evidence_events else trigger_ts

        return DetectionScore(
            score=score_uc1(A=A, U=U, F=F, D=D, C1=C1),
            components=components,
            evidence_event_ids=evidence_ids,
            machine_ids=machine_ids or (trigger.machine_id,),
            evidence_start_ts=evidence_start_ts,
            evidence_end_ts=evidence_end_ts,
            baseline_sizes={
                "logon_hours": sum(1 for event in history_events if event["kind"] == "LOGON"),
                "usb_days": len(_daily_counts(history_events, {"DEVICE_CONNECT"})),
                "file_copy_days": len(_daily_counts(history_events, {"FILE_COPY"})),
                "domains": sum(1 for event in history_events if event.get("domain")),
            },
        )

    def evaluate(self, trigger: Event, context: Mapping[str, Any], threshold: float) -> AlertRecord | None:
        scored = self.score(trigger, context)
        if scored.components["U"] <= 0.0:
            return None
        if scored.components["C1"] < UC1_MIN_CONTINUITY:
            return None
        if scored.score < threshold:
            return None
        return AlertRecord(
            alert_id=f"{UC1_DETECTOR}|{trigger.event_id}",
            detector=UC1_DETECTOR,
            score=scored.score,
            threshold=threshold,
            trigger_event_id=trigger.event_id,
            event_time=trigger.event_time,
            components=scored.components,
            user_ids=(trigger.user_id,),
            machine_ids=scored.machine_ids,
            evidence_event_ids=scored.evidence_event_ids,
            evidence_start_ts=scored.evidence_start_ts,
            evidence_end_ts=scored.evidence_end_ts,
        )


def _trigger_record(trigger: Event) -> dict[str, Any]:
    record = trigger.to_record()
    return {
        "event_id": record["event_id"],
        "source": record["source"],
        "kind": record["kind"],
        "event_ts": int(record["event_ts"]),
        "user_id": record["user_id"],
        "machine_id": record["machine_id"],
        **record.get("properties", {}),
    }


def _normalise_events(events: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    normalised = []
    for raw in events:
        if raw is None:
            continue
        event_id = raw.get("event_id") or raw.get("id")
        kind = raw.get("kind")
        event_ts = raw.get("event_ts")
        if not event_id or not kind or event_ts is None:
            continue
        record = dict(raw)
        record["event_id"] = str(event_id)
        record["kind"] = str(kind)
        record["event_ts"] = int(event_ts)
        if record.get("machine_id") is not None:
            record["machine_id"] = str(record["machine_id"])
        return_record = {key: value for key, value in record.items() if value is not None}
        normalised.append(return_record)
    return normalised


def _latest_event(events: Sequence[Mapping[str, Any]], kinds: set[str], trigger_ts: int) -> dict[str, Any] | None:
    matching = [
        event
        for event in events
        if event.get("kind") in kinds and int(event.get("event_ts", 0)) <= trigger_ts
    ]
    return max(matching, key=lambda event: (event["event_ts"], event["event_id"]), default=None)


def _events_of_kind(events: Sequence[Mapping[str, Any]], kinds: set[str], trigger_ts: int) -> list[dict[str, Any]]:
    return [
        dict(event)
        for event in events
        if event.get("kind") in kinds and int(event.get("event_ts", 0)) <= trigger_ts
    ]


def _after_hours_component(logon_event: Mapping[str, Any] | None, history_events: Sequence[Mapping[str, Any]]) -> float:
    if not logon_event:
        return 0.0
    hour_counts = Counter(
        _hour(event["event_ts"])
        for event in history_events
        if event.get("kind") == "LOGON"
    )
    return logon_hour_anomaly(_hour(logon_event["event_ts"]), hour_counts)


def _usb_component(
    usb_event: Mapping[str, Any] | None,
    candidate_events: Sequence[Mapping[str, Any]],
    history_events: Sequence[Mapping[str, Any]],
    trigger_ts: int,
    trigger_machine_id: str,
) -> float:
    if not usb_event:
        return 0.0
    current_day = _day(trigger_ts)
    current_daily_count = sum(
        1
        for event in candidate_events
        if event.get("kind") == "DEVICE_CONNECT" and _day(event["event_ts"]) == current_day
    )
    daily_history = list(_daily_counts(history_events, {"DEVICE_CONNECT"}).values())
    seen_before = any(
        event.get("kind") == "DEVICE_CONNECT" and event.get("machine_id") == trigger_machine_id
        for event in history_events
    )
    return usb_deviation(current_daily_count, daily_history, seen_before=seen_before)


def _file_copy_component(
    file_events: Sequence[Mapping[str, Any]],
    history_events: Sequence[Mapping[str, Any]],
    trigger_ts: int,
) -> float:
    if not file_events:
        return 0.0
    current_day = _day(trigger_ts)
    current_count = sum(1 for event in file_events if _day(event["event_ts"]) == current_day)
    daily_history = list(_daily_counts(history_events, {"FILE_COPY"}).values())
    if current_count > 0 and not daily_history:
        return 1.0
    return robust_deviation(current_count, daily_history)


def _domain_component(
    external_events: Sequence[Mapping[str, Any]],
    history_events: Sequence[Mapping[str, Any]],
) -> float:
    domains = [str(event["domain"]).lower() for event in external_events if event.get("domain")]
    if not domains:
        return 0.0
    prior_counts = Counter(
        str(event["domain"]).lower()
        for event in history_events
        if event.get("domain")
    )
    return max(domain_novelty(prior_counts[domain]) for domain in domains)


def _continuity_component(
    *,
    A: float,
    U: float,
    F: float,
    D: float,
    logon_event: Mapping[str, Any] | None,
    usb_event: Mapping[str, Any] | None,
    file_events: Sequence[Mapping[str, Any]],
    external_events: Sequence[Mapping[str, Any]],
    trigger_ts: int,
) -> float:
    first_file = min(file_events, key=lambda event: event["event_ts"], default=None)
    first_external = min(external_events, key=lambda event: event["event_ts"], default=None)
    stage_events = [event for event in (logon_event, usb_event, first_file, first_external) if event]
    if not stage_events:
        return 0.0
    if len({event.get("machine_id") for event in stage_events if event.get("machine_id")}) > 1:
        return 0.0

    order = temporal_order(
        [
            (_event_ts(logon_event), _event_ts(usb_event)),
            (_event_ts(logon_event), _event_ts(first_file)),
            (_event_ts(usb_event), _event_ts(first_file)),
            (_event_ts(first_file), _event_ts(first_external)),
            (_event_ts(usb_event), _event_ts(first_external)),
        ]
    )
    if order == 0.0:
        return 0.0

    execution_coverage = weighted_coverage(
        {
            "after_hours": A > 0.0,
            "usb": U > 0.0,
            "file_copy": F > 0.0,
            "leak_cloud": D > 0.0 or any(_has_external_signal(event) for event in external_events),
        },
        {
            "after_hours": 0.20,
            "usb": 0.25,
            "file_copy": 0.25,
            "leak_cloud": 0.30,
        },
    )
    intent_coverage = weighted_coverage(
        {
            "job_competitor": any(_has_job_signal(event) for event in external_events),
            "usb_spike": U > 0.0,
            "file_copy_burst": F > 0.0,
            "external_signal": D > 0.0 or any(_has_external_signal(event) for event in external_events),
        },
        {
            "job_competitor": 0.25,
            "usb_spike": 0.30,
            "file_copy_burst": 0.25,
            "external_signal": 0.20,
        },
    )
    duration = max(0, max(event["event_ts"] for event in stage_events) - min(event["event_ts"] for event in stage_events))
    execution_score = execution_coverage * order * time_decay(duration, 8 * 60 * 60)
    intent_score = intent_coverage * time_decay(max(0, trigger_ts - min(event["event_ts"] for event in stage_events)), 30 * SECONDS_PER_DAY)
    return min(execution_score, intent_score)


def _ordered_evidence(
    logon_event: Mapping[str, Any] | None,
    usb_event: Mapping[str, Any] | None,
    file_events: Sequence[Mapping[str, Any]],
    external_events: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    by_id = {}
    for event in [logon_event, usb_event, *file_events, *external_events]:
        if event:
            by_id[event["event_id"]] = dict(event)
    return sorted(by_id.values(), key=lambda event: (event["event_ts"], event["event_id"]))


def _daily_counts(events: Sequence[Mapping[str, Any]], kinds: set[str]) -> dict[int, int]:
    counts: dict[int, int] = defaultdict(int)
    for event in events:
        if event.get("kind") in kinds:
            counts[_day(event["event_ts"])] += 1
    return dict(counts)


def _has_external_signal(event: Mapping[str, Any]) -> bool:
    return bool(
        event.get("kind") == "HTTP"
        and (
            event.get("domain")
            or event.get("leak_signal")
            or event.get("cloud_signal")
            or event.get("job_signal")
        )
    )


def _has_job_signal(event: Mapping[str, Any]) -> bool:
    return bool(event.get("job_signal") or _contains_keyword(event.get("domain"), {"job", "career", "competitor"}))


def _contains_keyword(value: Any, keywords: set[str]) -> bool:
    text = str(value or "").lower()
    return any(keyword in text for keyword in keywords)


def _event_ts(event: Mapping[str, Any] | None) -> int | None:
    if not event:
        return None
    return int(event["event_ts"])


def _hour(event_ts: int) -> int:
    return datetime.fromtimestamp(int(event_ts), tz=timezone.utc).hour


def _day(event_ts: int) -> int:
    return int(event_ts) // SECONDS_PER_DAY
