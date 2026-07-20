from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Any, Iterable, Sequence

from cert_extractor import Incident, load_incidents as _load_incidents_file
from event_model import Event, load_sorted_stream
from rule_detectors import RuleUC1Detector, RuleUC2Detector


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


def run_rule_baseline(
    stream_path: Path,
    *,
    uc1_file_threshold: int = 20,
    uc2_recipient_threshold: int = 10,
) -> list[EvaluationAlert]:
    uc1 = RuleUC1Detector(file_threshold=uc1_file_threshold)
    uc2 = RuleUC2Detector(recipient_threshold=uc2_recipient_threshold)
    alerts: list[EvaluationAlert] = []
    for event in _load_stream_events(stream_path):
        for detector in (uc1, uc2):
            rule_alert = detector.observe(event)
            if rule_alert is None:
                continue
            alerts.append(
                EvaluationAlert(
                    alert_id=rule_alert.alert_id,
                    detector=rule_alert.detector,
                    user_id=rule_alert.user_id,
                    event_time=rule_alert.event_time,
                )
            )
    return alerts


def graph_alerts_from_rows(rows: Iterable[dict[str, Any]]) -> list[EvaluationAlert]:
    alerts: list[EvaluationAlert] = []
    for row in rows:
        alert_id = str(row.get("alert_id") or row.get("id") or "")
        detector = str(row.get("detector") or "")
        user_id = _first_user(row)
        event_time = _coerce_datetime(row.get("event_time"))
        if not (alert_id and detector and user_id and event_time):
            continue
        alerts.append(
            EvaluationAlert(
                alert_id=alert_id,
                detector=detector,
                user_id=user_id,
                event_time=event_time,
                processing_latency_seconds=float(row.get("processing_latency_seconds") or 0.0),
            )
        )
    return alerts


def load_graph_alerts_from_json(path: Path) -> list[EvaluationAlert]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = payload.get("alerts", payload) if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        raise ValueError(f"graph alert JSON must contain a list or {{'alerts': [...]}}: {path}")
    return graph_alerts_from_rows(rows)


def load_graph_alerts_from_memgraph(
    *,
    uri: str,
    username: str | None = None,
    password: str | None = None,
    database: str | None = None,
) -> list[EvaluationAlert]:
    try:
        from neo4j import GraphDatabase
    except ImportError as exc:  # pragma: no cover - dependency is environment-specific
        raise RuntimeError("neo4j package is required to read graph alerts from Memgraph") from exc

    auth = (username, password) if username else None
    driver = GraphDatabase.driver(uri, auth=auth)
    try:
        session_kwargs = {"database": database} if database else {}
        with driver.session(**session_kwargs) as session:
            rows = session.execute_read(_fetch_alert_rows)
    finally:
        driver.close()
    return graph_alerts_from_rows(rows)


def evaluate_and_write(
    *,
    answers_dir: Path,
    stream_path: Path,
    graph_alerts: Sequence[EvaluationAlert],
    graph_output: Path,
    rule_output: Path,
    comparison_output: Path,
    uc1_rule_file_threshold: int = 20,
    uc2_rule_recipient_threshold: int = 10,
) -> dict[str, Any]:
    incidents = load_ground_truth(answers_dir)
    rule_alerts = run_rule_baseline(
        stream_path,
        uc1_file_threshold=uc1_rule_file_threshold,
        uc2_recipient_threshold=uc2_rule_recipient_threshold,
    )
    graph_report = evaluate_alerts(graph_alerts, incidents)
    rule_report = evaluate_alerts(rule_alerts, incidents)
    comparison = compare_detectors(graph_report, rule_report)

    write_report(graph_output, graph_report)
    write_report(rule_output, rule_report)
    write_json(comparison_output, comparison)
    return {
        "graph": graph_report,
        "rule": rule_report,
        "comparison": comparison,
        "graph_alert_count": len(graph_alerts),
        "rule_alert_count": len(rule_alerts),
    }


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
        (
            _normalized_datetime(alert.event_time)
            - _normalized_datetime(_incident_by_id(sorted_incidents, incident_id).start)
        ).total_seconds()
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
    alert_time = _normalized_datetime(alert.event_time)
    incident_start = _normalized_datetime(incident.start)
    incident_end = _normalized_datetime(incident.end)
    return (
        alert.user_id == incident.user_id
        and incident_start <= alert_time <= incident_end
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


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=_json_default), encoding="utf-8")


def _load_stream_events(stream_path: Path) -> Iterable[Event]:
    events, _late_events, _recomputes = load_sorted_stream(Path(stream_path))
    try:
        yield from events
    finally:
        events.close()


def _fetch_alert_rows(tx):
    return tx.run(
        """
        MATCH (alert:Alert)
        RETURN alert.id AS alert_id,
               alert.detector AS detector,
               alert.user_ids AS user_ids,
               alert.event_time AS event_time,
               coalesce(alert.processing_latency_seconds, 0.0) AS processing_latency_seconds
        ORDER BY alert.event_time, alert.id
        """
    ).data()


def _first_user(row: dict[str, Any]) -> str:
    if row.get("user_id"):
        return str(row["user_id"])
    user_ids = row.get("user_ids") or []
    if isinstance(user_ids, str):
        return user_ids
    return str(user_ids[0]) if user_ids else ""


def _coerce_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if hasattr(value, "to_native"):
        native = value.to_native()
        if isinstance(native, datetime):
            return native
    text = str(value).strip()
    if not text:
        return None
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def _normalized_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if hasattr(value, "to_dict"):
        return value.to_dict()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def main(argv: Sequence[str] | None = None) -> dict[str, Any]:
    parser = argparse.ArgumentParser(description="Evaluate graph motif alerts against flat rule baselines.")
    parser.add_argument("--answers-dir", default="data/cert-r4.2/answers")
    parser.add_argument("--stream", default="artifacts/evaluation_stream.jsonl")
    parser.add_argument("--uri", default="bolt://localhost:7687")
    parser.add_argument("--database", default=None)
    parser.add_argument("--user", default=None)
    parser.add_argument("--password", default=None)
    parser.add_argument("--graph-alerts-json", default=None, help="Read graph alerts from JSON instead of Memgraph.")
    parser.add_argument("--graph-output", default="artifacts/graph_metrics.json")
    parser.add_argument("--rule-output", default="artifacts/rule_metrics.json")
    parser.add_argument("--comparison-output", default="artifacts/comparison.json")
    parser.add_argument("--uc1-rule-file-threshold", type=int, default=20)
    parser.add_argument("--uc2-rule-recipient-threshold", type=int, default=10)
    args = parser.parse_args(argv)

    if args.graph_alerts_json:
        graph_alerts = load_graph_alerts_from_json(Path(args.graph_alerts_json))
    else:
        graph_alerts = load_graph_alerts_from_memgraph(
            uri=args.uri,
            username=args.user,
            password=args.password,
            database=args.database,
        )

    result = evaluate_and_write(
        answers_dir=Path(args.answers_dir),
        stream_path=Path(args.stream),
        graph_alerts=graph_alerts,
        graph_output=Path(args.graph_output),
        rule_output=Path(args.rule_output),
        comparison_output=Path(args.comparison_output),
        uc1_rule_file_threshold=args.uc1_rule_file_threshold,
        uc2_rule_recipient_threshold=args.uc2_rule_recipient_threshold,
    )
    graph = result["graph"]
    rule = result["rule"]
    print(
        "[EVAL] done "
        f"graph_f1={graph.f1:.3f} graph_recall={graph.recall:.3f} "
        f"rule_f1={rule.f1:.3f} rule_recall={rule.recall:.3f}"
    )
    print(f"[EVAL] graph={Path(args.graph_output).resolve()}")
    print(f"[EVAL] rule={Path(args.rule_output).resolve()}")
    print(f"[EVAL] comparison={Path(args.comparison_output).resolve()}")
    return result


if __name__ == "__main__":
    main()
