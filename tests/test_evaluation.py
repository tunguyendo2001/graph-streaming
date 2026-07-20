import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cert_extractor import Incident
from event_model import Event
from evaluation import (
    EvaluationAlert,
    compare_detectors,
    evaluate_alerts,
    graph_alerts_from_rows,
    load_ground_truth,
    main,
    run_rule_baseline,
)


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


def stream_event(event_id, kind, offset, user_id="U001", machine_id="PC-001", **properties):
    return Event(
        event_id=event_id,
        source=kind.lower(),
        kind=kind,
        event_time=BASE + timedelta(seconds=offset),
        user_id=user_id,
        machine_id=machine_id,
        properties=properties,
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

    def test_rule_baseline_reads_jsonl_stream(self):
        events = [
            stream_event("logon-1", "LOGON", -5 * 60 * 60),
            stream_event("usb-1", "DEVICE_CONNECT", -5 * 60 * 60 + 1),
            stream_event("file-1", "FILE_COPY", -5 * 60 * 60 + 2),
            stream_event("file-2", "FILE_COPY", -5 * 60 * 60 + 3),
            stream_event("email-1", "EMAIL", 4, user_id="U003", recipients=["a", "b", "c"], recipient_count=3),
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            stream_path = Path(temp_dir) / "stream.jsonl"
            stream_path.write_text(
                "\n".join(json.dumps(event.to_record(), sort_keys=True) for event in events),
                encoding="utf-8",
            )

            alerts = run_rule_baseline(stream_path, uc1_file_threshold=2, uc2_recipient_threshold=3)

        self.assertTrue(any(item.detector == "rule_uc1" for item in alerts))
        self.assertTrue(any(item.detector == "rule_uc2" for item in alerts))

    def test_graph_alert_rows_convert_to_evaluation_alerts(self):
        alerts = graph_alerts_from_rows(
            [
                {
                    "alert_id": "g1",
                    "detector": "uc1_exfiltration_motif",
                    "user_ids": ["U001"],
                    "event_time": BASE.isoformat(),
                    "processing_latency_seconds": 0.25,
                }
            ]
        )

        self.assertEqual(alerts[0].alert_id, "g1")
        self.assertEqual(alerts[0].user_id, "U001")
        self.assertAlmostEqual(alerts[0].processing_latency_seconds, 0.25)

    def test_cli_writes_graph_rule_and_comparison_reports_from_json_alerts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            answers_dir = root / "answers"
            answers_dir.mkdir()
            (answers_dir / "insiders.csv").write_text(
                "\n".join(
                    [
                        "dataset,scenario,details,user,start,end",
                        "4.2,1,r4.2-1/U001.csv,U001,01/01/2010 12:00:00,01/01/2010 12:10:00",
                    ]
                ),
                encoding="utf-8",
            )
            stream_path = root / "stream.jsonl"
            stream_path.write_text(
                json.dumps(stream_event("http-1", "HTTP", 5).to_record(), sort_keys=True),
                encoding="utf-8",
            )
            graph_alerts_path = root / "graph_alerts.json"
            graph_alerts_path.write_text(
                json.dumps(
                    [
                        {
                            "alert_id": "g1",
                            "detector": "uc1_exfiltration_motif",
                            "user_ids": ["U001"],
                            "event_time": "2010-01-01T12:00:05+00:00",
                        }
                    ]
                ),
                encoding="utf-8",
            )

            main(
                [
                    "--answers-dir",
                    str(answers_dir),
                    "--stream",
                    str(stream_path),
                    "--graph-alerts-json",
                    str(graph_alerts_path),
                    "--graph-output",
                    str(root / "graph_metrics.json"),
                    "--rule-output",
                    str(root / "rule_metrics.json"),
                    "--comparison-output",
                    str(root / "comparison.json"),
                ]
            )

            self.assertEqual(json.loads((root / "graph_metrics.json").read_text())["true_positives"], 1)
            self.assertTrue((root / "rule_metrics.json").exists())
            self.assertIn("f1_delta", json.loads((root / "comparison.json").read_text()))


if __name__ == "__main__":
    unittest.main()
