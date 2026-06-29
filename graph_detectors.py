from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence

from baselines import (
    domain_novelty,
    email_fanout_deviation,
    logon_hour_anomaly,
    robust_deviation,
    score_uc1,
    score_uc2,
    social_neighborhood_novelty,
    temporal_order,
    time_decay,
    usb_deviation,
    weighted_coverage,
)
from event_model import Event
from graph_repository import AlertRecord


UC1_DETECTOR = "uc1_exfiltration_motif"
UC1_MIN_CONTINUITY = 0.60
UC2_DETECTOR = "uc2_credential_pivot_motif"
UC2_MIN_MACHINE_RISK = 0.60
UC2_MIN_KEYLOGGER_BRIDGE = 0.40
UC2_MIN_CONTINUITY = 0.50
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


class UC2Detector:
    """Incremental graph score for credential pivot and victim email fan-out motifs."""

    def score(self, trigger: Event, context: Mapping[str, Any]) -> DetectionScore:
        trigger_record = _trigger_record(trigger)
        trigger_ts = int(context.get("trigger_ts") or trigger.event_ts)
        victim_user_id = trigger.user_id
        target_machine_id = str(context.get("target_machine_id") or context.get("machine_id") or trigger.machine_id)
        current_recipients = _current_recipients(trigger, context)

        stage_events = [
            event
            for event in _normalise_events(context.get("stage_events") or context.get("window_events") or ())
            if event["event_ts"] <= trigger_ts
        ]
        if trigger_record["event_id"] not in {event["event_id"] for event in stage_events}:
            stage_events.append(trigger_record)
        stage_events.sort(key=lambda event: (event["event_ts"], event["event_id"]))

        attacker_user_id = _infer_attacker_user(context, stage_events, victim_user_id)
        source_machine_id = str(context.get("source_machine_id") or _infer_source_machine(stage_events, attacker_user_id, target_machine_id) or "")

        M = _machine_risk_component(context)
        K, k_evidence = _keylogger_bridge_component(
            stage_events=stage_events,
            attacker_user_id=attacker_user_id,
            source_machine_id=source_machine_id,
            target_machine_id=target_machine_id,
            trigger_ts=trigger_ts,
        )
        E = email_fanout_deviation(
            current_email_count=len(current_recipients),
            current_window_count=int(context.get("current_window_recipient_count") or len(current_recipients)),
            per_email_history=[int(value) for value in context.get("per_email_history", ())],
            window_history=[int(value) for value in context.get("window_fanout_history", ())],
        )
        R = social_neighborhood_novelty(
            current=current_recipients,
            historical=context.get("recipient_history", ()),
        )
        C2, c2_evidence = _credential_continuity_component(
            stage_events=stage_events,
            k_evidence=k_evidence,
            attacker_user_id=attacker_user_id,
            victim_user_id=victim_user_id,
            target_machine_id=target_machine_id,
            trigger_ts=trigger_ts,
            trigger_event_id=trigger.event_id,
        )
        components = {"M": M, "K": K, "E": E, "R": R, "C2": C2}

        evidence_events = _ordered_unique_events([*k_evidence.values(), *c2_evidence.values(), trigger_record])
        evidence_ids = [event["event_id"] for event in evidence_events]
        historical_recipients = set(context.get("recipient_history", ()))
        evidence_ids.extend(
            f"recipient:{recipient}"
            for recipient in sorted(set(current_recipients) - historical_recipients)
        )
        machine_ids = tuple(
            sorted(
                {
                    machine
                    for machine in [source_machine_id, target_machine_id, *[event.get("machine_id") for event in evidence_events]]
                    if machine
                }
            )
        )
        evidence_start_ts = evidence_events[0]["event_ts"] if evidence_events else trigger_ts
        evidence_end_ts = trigger_ts

        return DetectionScore(
            score=score_uc2(M=M, K=K, E=E, R=R, C2=C2),
            components=components,
            evidence_event_ids=tuple(evidence_ids),
            machine_ids=machine_ids or (target_machine_id,),
            evidence_start_ts=evidence_start_ts,
            evidence_end_ts=evidence_end_ts,
            baseline_sizes={
                "recipient_history": len(context.get("recipient_history", ())),
                "per_email_history": len(context.get("per_email_history", ())),
                "window_fanout_history": len(context.get("window_fanout_history", ())),
            },
        )

    def evaluate(self, trigger: Event, context: Mapping[str, Any], threshold: float) -> AlertRecord | None:
        scored = self.score(trigger, context)
        if scored.components["M"] < UC2_MIN_MACHINE_RISK:
            return None
        if scored.components["K"] < UC2_MIN_KEYLOGGER_BRIDGE:
            return None
        if scored.components["C2"] < UC2_MIN_CONTINUITY:
            return None
        if scored.score < threshold:
            return None

        attacker_user_id = str(context.get("attacker_user_id") or "")
        user_ids = tuple(user_id for user_id in (attacker_user_id, trigger.user_id) if user_id)
        if not user_ids:
            user_ids = (trigger.user_id,)
        return AlertRecord(
            alert_id=f"{UC2_DETECTOR}|{trigger.event_id}",
            detector=UC2_DETECTOR,
            score=scored.score,
            threshold=threshold,
            trigger_event_id=trigger.event_id,
            event_time=trigger.event_time,
            components=scored.components,
            user_ids=tuple(dict.fromkeys(user_ids)),
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
    external_floor = max(
        event["event_ts"]
        for event in (usb_event, first_file)
        if event
    ) if (usb_event or first_file) else None
    ordered_external_events = [
        event
        for event in external_events
        if external_floor is None or event["event_ts"] >= external_floor
    ]
    first_external = min(
        ordered_external_events or external_events,
        key=lambda event: event["event_ts"],
        default=None,
    )
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
    intent_score = intent_coverage * order * time_decay(max(0, trigger_ts - min(event["event_ts"] for event in stage_events)), 30 * SECONDS_PER_DAY)
    return max(execution_score, intent_score)


def _machine_risk_component(context: Mapping[str, Any]) -> float:
    owner_confidence = float(context.get("owner_confidence", 1.0))
    probability = context.get("user_machine_probability")
    if probability is None:
        machine_use = context.get("machine_use") or {}
        count = float(machine_use.get("count", 0.0) or 0.0)
        total = float(machine_use.get("total_count", 0.0) or 0.0)
        probability = count / total if total > 0 else 0.0
    return max(0.0, min(1.0, (1.0 - float(probability)) * owner_confidence))


def _keylogger_bridge_component(
    *,
    stage_events: Sequence[Mapping[str, Any]],
    attacker_user_id: str | None,
    source_machine_id: str,
    target_machine_id: str,
    trigger_ts: int,
) -> tuple[float, dict[str, dict[str, Any]]]:
    attacker_events = [
        event
        for event in stage_events
        if event.get("user_id") == attacker_user_id and event["event_ts"] <= trigger_ts
    ]
    q_event = _first_matching(attacker_events, lambda event: _has_keylogger_or_download_signal(event))
    source_usb = _first_matching(
        attacker_events,
        lambda event: event.get("kind") == "DEVICE_CONNECT" and event.get("machine_id") == source_machine_id,
    )
    file_event = _first_matching(attacker_events, lambda event: _is_executable_filecopy(event))
    pivot_event = _first_matching(
        attacker_events,
        lambda event: event.get("kind") == "LOGON" and event.get("machine_id") == target_machine_id,
    )
    target_usb = _first_matching(
        attacker_events,
        lambda event: event.get("kind") == "DEVICE_CONNECT" and event.get("machine_id") == target_machine_id,
    )
    evidence = {
        key: event
        for key, event in {
            "q": q_event,
            "s": source_usb,
            "f": file_event,
            "p": pivot_event,
            "t": target_usb,
        }.items()
        if event
    }
    if not evidence:
        return 0.0, {}

    coverage = weighted_coverage(
        {
            "q": q_event is not None,
            "s": source_usb is not None,
            "f": file_event is not None,
            "p": pivot_event is not None,
            "t": target_usb is not None,
        },
        {"q": 0.25, "s": 0.15, "f": 0.20, "p": 0.25, "t": 0.15},
    )
    order = temporal_order(
        [
            (_event_ts(q_event), _event_ts(source_usb)),
            (_event_ts(source_usb), _event_ts(file_event)),
            (_event_ts(file_event), _event_ts(pivot_event)),
            (_event_ts(pivot_event), _event_ts(target_usb)),
            (_event_ts(pivot_event), trigger_ts),
            (_event_ts(target_usb), trigger_ts),
        ]
    )
    if pivot_event and any(
        event and event["event_ts"] > pivot_event["event_ts"]
        for event in (q_event, source_usb, file_event)
    ):
        order *= 0.35
    duration = max(0, trigger_ts - min(event["event_ts"] for event in evidence.values()))
    return coverage * order * time_decay(duration, 48 * 60 * 60), evidence


def _credential_continuity_component(
    *,
    stage_events: Sequence[Mapping[str, Any]],
    k_evidence: Mapping[str, Mapping[str, Any]],
    attacker_user_id: str | None,
    victim_user_id: str,
    target_machine_id: str,
    trigger_ts: int,
    trigger_event_id: str,
) -> tuple[float, dict[str, dict[str, Any]]]:
    if not attacker_user_id or attacker_user_id == victim_user_id:
        return 0.0, {}
    victim_logon = _first_matching(
        stage_events,
        lambda event: event.get("user_id") == victim_user_id
        and event.get("kind") == "LOGON"
        and event.get("machine_id") == target_machine_id,
    )
    trigger_event = _first_matching(stage_events, lambda event: event.get("event_id") == trigger_event_id)
    source_compromise = any(key in k_evidence for key in ("q", "s", "f"))
    target_pivot = any(key in k_evidence for key in ("p", "t"))
    victim_email = trigger_event is not None and trigger_event.get("kind") == "EMAIL"
    hop_coverage = sum([source_compromise, target_pivot, victim_email]) / 3.0
    if hop_coverage == 0.0:
        return 0.0, {}
    first_source = min(
        [event for key, event in k_evidence.items() if key in {"q", "s", "f"}],
        key=lambda event: event["event_ts"],
        default=None,
    )
    first_target = min(
        [event for key, event in k_evidence.items() if key in {"p", "t"}],
        key=lambda event: event["event_ts"],
        default=None,
    )
    order = temporal_order(
        [
            (_event_ts(first_source), _event_ts(first_target)),
            (_event_ts(first_target), _event_ts(victim_logon)),
            (_event_ts(victim_logon), trigger_ts),
            (_event_ts(first_target), trigger_ts),
        ]
    )
    if order == 0.0:
        return 0.0, {}
    evidence = {
        key: dict(event)
        for key, event in {
            "source": first_source,
            "target": first_target,
            "victim_logon": victim_logon,
            "trigger": trigger_event,
        }.items()
        if event
    }
    duration = max(0, trigger_ts - min(event["event_ts"] for event in evidence.values()))
    return hop_coverage * order * time_decay(duration, 48 * 60 * 60), evidence


def _current_recipients(trigger: Event, context: Mapping[str, Any]) -> tuple[str, ...]:
    recipients = context.get("current_recipients")
    if recipients is None:
        recipients = trigger.properties.get("recipients", ())
    return tuple(str(recipient) for recipient in recipients)


def _infer_attacker_user(
    context: Mapping[str, Any],
    stage_events: Sequence[Mapping[str, Any]],
    victim_user_id: str,
) -> str | None:
    if context.get("attacker_user_id"):
        return str(context["attacker_user_id"])
    for event in stage_events:
        user_id = event.get("user_id")
        if user_id and user_id != victim_user_id and event.get("kind") in {"HTTP", "DEVICE_CONNECT", "FILE_COPY", "LOGON"}:
            return str(user_id)
    return None


def _infer_source_machine(
    stage_events: Sequence[Mapping[str, Any]],
    attacker_user_id: str | None,
    target_machine_id: str,
) -> str | None:
    for event in stage_events:
        if event.get("user_id") == attacker_user_id and event.get("machine_id") != target_machine_id:
            return str(event.get("machine_id"))
    return None


def _first_matching(
    events: Sequence[Mapping[str, Any]],
    predicate,
) -> dict[str, Any] | None:
    matching = [event for event in events if predicate(event)]
    return min(matching, key=lambda event: (event["event_ts"], event["event_id"]), default=None)


def _has_keylogger_or_download_signal(event: Mapping[str, Any]) -> bool:
    if event.get("kind") != "HTTP":
        return False
    return bool(
        event.get("keylogger_signal")
        or event.get("download_signal")
        or _contains_keyword(event.get("url"), {"keylog", ".exe", "download"})
        or _contains_keyword(event.get("domain"), {"keylog", "download"})
    )


def _is_executable_filecopy(event: Mapping[str, Any]) -> bool:
    if event.get("kind") != "FILE_COPY":
        return False
    extension = str(event.get("extension") or "").lower()
    filename = str(event.get("filename") or "").lower()
    return extension in {".exe", ".dll", ".bat", ".ps1"} or filename.endswith((".exe", ".dll", ".bat", ".ps1"))


def _ordered_unique_events(events: Iterable[Mapping[str, Any] | None]) -> list[dict[str, Any]]:
    by_id = {}
    for event in events:
        if event:
            by_id[event["event_id"]] = dict(event)
    return sorted(by_id.values(), key=lambda event: (event["event_ts"], event["event_id"]))


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
