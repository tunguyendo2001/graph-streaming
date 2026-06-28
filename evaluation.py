from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from statistics import mean
from typing import Iterable, Sequence

from cert_extractor import Incident, load_incidents as _load_incidents_file


@dataclass(frozen=True)
class EvaluationAlert:
    alert_id: str
    detector: str
    user_id: str
    event_time: datetime
    processing_latency_seconds: float = 0.0


@dataclass
class EvaluationReport:
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float
    false_positives_per_user_day: float
    mean_time_to_detect_seconds: float
    mean_processing_latency_seconds: float
    matched_incident_ids: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        return asdict(self)


def load_ground_truth(answers_dir: Path) -> list[Incident]:
    answers_dir = Path(answers_dir)
    source = answers_dir / "insiders.csv" if answers_dir.is_dir() else answers_dir
    return _load_incidents_file(source)


def evaluate_alerts(alerts: Iterable[EvaluationAlert], incidents: Sequence[Incident]) -> EvaluationReport:
    sorted_alerts = sorted(alerts, key=lambda alert: (alert.event_time, alert.alert_id))
    sorted_incidents = list(incidents)
    matched_incidents: dict[str, EvaluationAlert] = {}
    false_positives = 0
    duplicate_matches = 0

    for alert in sorted_alerts:
        compatible = [
            incident
            for incident in sorted_incidents
            if _incident_id(incident) not in matched_incidents
            and _matches(alert, incident)
        ]
        if compatible:
            incident = min(compatible, key=lambda item: (item.start, item.end, item.user_id))
            matched_incidents[_incident_id(incident)] = alert
            continue
        if any(_matches(alert, incident) for incident in sorted_incidents):
            duplicate_matches += 1
            continue
        false_positives += 1

    true_positives = len(matched_incidents)
    false_negatives = len(sorted_incidents) - true_positives
    precision = true_positives / max(1, true_positives + false_positives)
    recall = true_positives / max(1, true_positives + false_negatives)
    f1 = 0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall)
    user_days = {(alert.user_id, alert.event_time.date()) for alert in sorted_alerts}
    detection_times = [
        (alert.event_time - _incident_by_id(sorted_incidents, incident_id).start).total_seconds()
        for incident_id, alert in matched_incidents.items()
    ]
    latencies = [float(alert.processing_latency_seconds) for alert in sorted_alerts]
    return EvaluationReport(
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        precision=precision,
        recall=recall,
        f1=f1,
        false_positives_per_user_day=false_positives / max(1, len(user_days)),
        mean_time_to_detect_seconds=mean(detection_times) if detection_times else 0.0,
        mean_processing_latency_seconds=mean(latencies) if latencies else 0.0,
        matched_incident_ids=tuple(sorted(matched_incidents)),
    )


def compare_detectors(graph_report: EvaluationReport, rule_report: EvaluationReport) -> dict:
    return {
        "precision_delta": graph_report.precision - rule_report.precision,
        "recall_delta": graph_report.recall - rule_report.recall,
        "f1_delta": graph_report.f1 - rule_report.f1,
        "false_positive_delta": graph_report.false_positives - rule_report.false_positives,
        "mean_time_to_detect_delta_seconds": (
            graph_report.mean_time_to_detect_seconds - rule_report.mean_time_to_detect_seconds
        ),
    }


def _matches(alert: EvaluationAlert, incident: Incident) -> bool:
    return (
        alert.user_id == incident.user_id
        and incident.start <= alert.event_time <= incident.end
        and incident.scenario in _detector_scenarios(alert.detector)
    )


def _detector_scenarios(detector: str) -> set[int]:
    detector = detector.lower()
    if "uc1" in detector:
        return {1, 2}
    if "uc2" in detector:
        return {3}
    return set()


def _incident_id(incident: Incident) -> str:
    return f"{incident.scenario}|{incident.user_id}|{incident.start.isoformat()}|{incident.end.isoformat()}"


def _incident_by_id(incidents: Sequence[Incident], incident_id: str) -> Incident:
    for incident in incidents:
        if _incident_id(incident) == incident_id:
            return incident
    raise KeyError(incident_id)


def write_report(path: Path, report: EvaluationReport) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
