import unittest
from datetime import datetime, timezone
from pathlib import Path

from baselines import logon_hour_anomaly
from event_model import Event
from graph_detectors import UC1Detector


def dt(year, month, day, hour, minute=0):
    return datetime(year, month, day, hour, minute, tzinfo=timezone.utc)


def ts(year, month, day, hour, minute=0):
    return int(dt(year, month, day, hour, minute).timestamp())


def event_dict(event_id, kind, event_ts, machine_id="PC-1", **properties):
    record = {
        "event_id": event_id,
        "kind": kind,
        "event_ts": event_ts,
        "machine_id": machine_id,
    }
    record.update(properties)
    return record


def trigger(kind="HTTP", event_id="http-trigger", event_time=None, **properties):
    event_time = event_time or dt(2010, 1, 31, 2, 25)
    defaults = {
        "domain": "dropbox-leak.example",
        "leak_signal": True,
        "cloud_signal": True,
    }
    defaults.update(properties)
    return Event(
        event_id=event_id,
        source="http" if kind == "HTTP" else "file",
        kind=kind,
        event_time=event_time,
        user_id="U001",
        machine_id="PC-1",
        properties=defaults,
    )


def base_context(*, candidate_events, history_events=None, trigger_time=None):
    trigger_ts = int((trigger_time or dt(2010, 1, 31, 2, 25)).timestamp())
    return {
        "user_id": "U001",
        "history_start_ts": ts(2010, 1, 1, 0),
        "motif_start_ts": trigger_ts - 48 * 60 * 60,
        "trigger_ts": trigger_ts,
        "history_events": list(history_events or []),
        "candidate_events": list(candidate_events),
    }


def normal_history(logon_hour=9):
    history = []
    for day in range(1, 11):
        history.append(event_dict(f"hist-logon-{day}", "LOGON", ts(2010, 1, day, logon_hour), activity="LOGON"))
        history.append(event_dict(f"hist-file-{day}", "FILE_COPY", ts(2010, 1, day, 10, 5), filename="routine.txt"))
    history.extend(
        [
            event_dict("hist-domain-1", "HTTP", ts(2010, 1, 6, 11), domain="intranet.example"),
            event_dict("hist-domain-2", "HTTP", ts(2010, 1, 7, 11), domain="intranet.example"),
        ]
    )
    return history


def full_uc1_candidates(machine_id="PC-1", *, logon_minute=0, usb_minute=5, file_start_minute=10, http_minute=25):
    trigger_day = (2010, 1, 31)
    events = [
        event_dict("logon-1", "LOGON", ts(*trigger_day, 2, logon_minute), machine_id=machine_id, activity="LOGON"),
        event_dict("usb-1", "DEVICE_CONNECT", ts(*trigger_day, 2, usb_minute), machine_id=machine_id, activity="CONNECT"),
    ]
    for offset in range(5):
        events.append(
            event_dict(
                f"file-{offset}",
                "FILE_COPY",
                ts(*trigger_day, 2, file_start_minute + offset),
                machine_id=machine_id,
                filename=f"secret-{offset}.doc",
            )
        )
    events.append(
        event_dict(
            "http-trigger",
            "HTTP",
            ts(*trigger_day, 2, http_minute),
            machine_id=machine_id,
            domain="dropbox-leak.example",
            leak_signal=True,
            cloud_signal=True,
        )
    )
    return events


class UC1DetectorTest(unittest.TestCase):
    def test_new_after_hours_usb_filecopy_novel_leak_domain_alerts(self):
        detector = UC1Detector()
        event = trigger()
        context = base_context(
            history_events=normal_history(),
            candidate_events=full_uc1_candidates(),
            trigger_time=event.event_time,
        )

        alert = detector.evaluate(event, context, threshold=0.70)

        self.assertIsNotNone(alert)
        self.assertEqual(alert.detector, "uc1_exfiltration_motif")
        self.assertEqual(alert.trigger_event_id, "http-trigger")
        self.assertEqual(alert.user_ids, ("U001",))
        self.assertEqual(alert.machine_ids, ("PC-1",))
        self.assertGreaterEqual(alert.score, 0.70)
        self.assertGreaterEqual(alert.components["A"], 0.8)
        self.assertEqual(alert.components["U"], 1.0)
        self.assertEqual(alert.components["F"], 1.0)
        self.assertEqual(alert.components["D"], 1.0)
        self.assertGreaterEqual(alert.components["C1"], 0.60)
        self.assertEqual(alert.evidence_event_ids[0], "logon-1")
        self.assertEqual(alert.evidence_event_ids[-1], "http-trigger")

    def test_single_novel_domain_without_usb_does_not_alert(self):
        detector = UC1Detector()
        event = trigger()
        context = base_context(
            history_events=normal_history(),
            candidate_events=[
                event_dict(
                    "http-trigger",
                    "HTTP",
                    int(event.event_time.timestamp()),
                    domain="new-domain.example",
                    leak_signal=True,
                )
            ],
            trigger_time=event.event_time,
        )

        self.assertIsNone(detector.evaluate(event, context, threshold=0.20))

    def test_user_who_normally_logs_on_at_two_has_low_after_hours_component(self):
        detector = UC1Detector()
        event = trigger()
        context = base_context(
            history_events=normal_history(logon_hour=2),
            candidate_events=full_uc1_candidates(),
            trigger_time=event.event_time,
        )

        score = detector.score(event, context)

        expected = logon_hour_anomaly(2, {2: 10})
        self.assertAlmostEqual(score.components["A"], expected)
        self.assertLess(score.components["A"], 0.10)

    def test_event_ordering_violation_reduces_continuity_below_gate(self):
        detector = UC1Detector()
        event = trigger()
        candidates = full_uc1_candidates(logon_minute=20, usb_minute=5, file_start_minute=10, http_minute=25)
        context = base_context(
            history_events=normal_history(),
            candidate_events=candidates,
            trigger_time=event.event_time,
        )

        score = detector.score(event, context)

        self.assertLess(score.components["C1"], 0.60)
        self.assertIsNone(detector.evaluate(event, context, threshold=0.0))

    def test_different_machine_stages_set_continuity_to_zero(self):
        detector = UC1Detector()
        event = trigger()
        candidates = full_uc1_candidates()
        candidates[0]["machine_id"] = "PC-OTHER"
        context = base_context(
            history_events=normal_history(),
            candidate_events=candidates,
            trigger_time=event.event_time,
        )

        score = detector.score(event, context)

        self.assertEqual(score.components["C1"], 0.0)
        self.assertIsNone(detector.evaluate(event, context, threshold=0.0))

    def test_trigger_timestamp_is_excluded_from_baseline_lists(self):
        detector = UC1Detector()
        event = trigger(kind="FILE_COPY", event_id="file-trigger", event_time=dt(2010, 1, 31, 2, 14), filename="secret.doc")
        history = normal_history()
        history.extend(
            [
                event_dict("leaky-logon-at-trigger", "LOGON", int(event.event_time.timestamp()), activity="LOGON"),
                event_dict("leaky-file-at-trigger", "FILE_COPY", int(event.event_time.timestamp()), filename="secret.doc"),
            ]
        )
        context = base_context(
            history_events=history,
            candidate_events=full_uc1_candidates(http_minute=14)[:-1],
            trigger_time=event.event_time,
        )

        score = detector.score(event, context)

        self.assertGreater(score.components["A"], 0.8)
        self.assertEqual(score.baseline_sizes["logon_hours"], 10)
        self.assertEqual(score.baseline_sizes["file_copy_days"], 10)


class UC1EvidenceQueryTest(unittest.TestCase):
    def test_query_contains_temporal_bounds_and_graph_traversals(self):
        query = Path("queries/uc1_evidence.cypher").read_text(encoding="utf-8")

        self.assertIn("MATCH (u:User {id: $user_id})", query)
        self.assertIn("history.event_ts < $trigger_ts", query)
        self.assertIn("candidate.event_ts <= $trigger_ts", query)
        self.assertIn(":ACTED", query)
        self.assertIn(":ON_MACHINE", query)
        self.assertIn(":IN_USB_SESSION|BOUNDARY_OF", query)
        self.assertIn(":VISITED", query)
        self.assertIn("history_events", query)
        self.assertIn("candidate_events", query)


if __name__ == "__main__":
    unittest.main()
