import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cert_extractor import Incident
from evaluation import EvaluationAlert, compare_detectors, evaluate_alerts, load_ground_truth


BASE = datetime(2010, 1, 1, 12, 0, tzinfo=timezone.utc)


def incident(scenario, user_id, start_offset, end_offset, details="details.csv"):
    return Incident(
        scenario=scenario,
        details_file=details,
        user_id=user_id,
        start=BASE + timedelta(seconds=start_offset),
        end=BASE + timedelta(seconds=end_offset),
    )


def alert(alert_id, detector, user_id, offset, latency=0.0):
    return EvaluationAlert(
        alert_id=alert_id,
        detector=detector,
        user_id=user_id,
        event_time=BASE + timedelta(seconds=offset),
        processing_latency_seconds=latency,
    )


class EvaluationTest(unittest.TestCase):
    def test_load_ground_truth_reads_answers_incidents(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "insiders.csv"
            path.write_text(
                "\n".join(
                    [
                        "dataset,scenario,details,user,start,end",
                        "4.2,1,r4.2-1/U001.csv,U001,01/01/2010 12:00:00,01/01/2010 13:00:00",
                        "5.2,1,ignored.csv,U999,01/01/2010 12:00:00,01/01/2010 13:00:00",
                    ]
                ),
                encoding="utf-8",
            )

            incidents = load_ground_truth(Path(temp_dir))

        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].user_id, "U001")
        self.assertEqual(incidents[0].scenario, 1)

    def test_evaluate_alerts_counts_incident_level_metrics_and_wrong_scenario(self):
        incidents = [
            incident(1, "U001", 0, 100),
            incident(2, "U002", 0, 100),
            incident(3, "U003", 100, 200),
        ]
        alerts = [
            alert("a1", "uc1_exfiltration_motif", "U001", 10, latency=0.10),
            alert("a2", "rule_uc1", "U001", 20, latency=0.20),
            alert("a3", "uc2_credential_pivot_motif", "U003", 130, latency=0.30),
            alert("wrong-scenario", "uc2_credential_pivot_motif", "U002", 50, latency=0.40),
        ]

        report = evaluate_alerts(alerts, incidents)

        self.assertEqual(report.true_positives, 2)
        self.assertEqual(report.false_positives, 1)
        self.assertEqual(report.false_negatives, 1)
        self.assertAlmostEqual(report.precision, 2 / 3)
        self.assertAlmostEqual(report.recall, 2 / 3)
        self.assertAlmostEqual(report.f1, 2 / 3)
        self.assertAlmostEqual(report.mean_time_to_detect_seconds, (10 + 30) / 2)
        self.assertAlmostEqual(report.mean_processing_latency_seconds, 0.25)
        self.assertAlmostEqual(report.false_positives_per_user_day, 1 / 3)

    def test_compare_detectors_reports_graph_lift_over_rule(self):
        incidents = [
            incident(1, "U001", 0, 100),
            incident(3, "U003", 100, 200),
        ]
        graph = evaluate_alerts(
            [
                alert("g1", "uc1_exfiltration_motif", "U001", 10),
                alert("g2", "uc2_credential_pivot_motif", "U003", 130),
            ],
            incidents,
        )
        rule = evaluate_alerts([alert("r1", "rule_uc1", "U001", 10)], incidents)

        comparison = compare_detectors(graph, rule)

        self.assertGreater(comparison["recall_delta"], 0)
        self.assertGreater(comparison["f1_delta"], 0)


if __name__ == "__main__":
    unittest.main()
