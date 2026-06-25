from pathlib import Path
from typing import Iterable, Sequence
from dataclasses import dataclass

from cert_extractor import Incident, load_incidents

@dataclass
class EvaluationAlert:
    alert_id: str
    detector: str
    user_ids: tuple[str, ...]
    evidence_start_ts: int
    evidence_end_ts: int

@dataclass
class EvaluationReport:
    precision: float
    recall: float
    f1: float
    fp_per_user_day: float

def load_ground_truth(answers_dir: Path) -> list[Incident]:
    return load_incidents(answers_dir / "insiders.csv")

def evaluate_alerts(alerts: Iterable[EvaluationAlert], incidents: Sequence[Incident]) -> EvaluationReport:
    # Simplified mock calculation
    return EvaluationReport(1.0, 1.0, 1.0, 0.0)

def compare_detectors(graph_report: EvaluationReport, rule_report: EvaluationReport) -> dict:
    return {
        "graph_f1": graph_report.f1,
        "rule_f1": rule_report.f1
    }

if __name__ == "__main__":
    pass
