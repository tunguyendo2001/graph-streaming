import json
import tempfile
import unittest
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from event_model import Event
from graph_repository import AlertRecord, WriteResult
from event_replay import ReplayConfig, ReplayEngine


BASE_TIME = datetime(2010, 1, 1, 0, 0, tzinfo=timezone.utc)


def make_event(event_id, kind, *, offset_seconds=0, user_id="U001", machine_id="PC-1", **properties):
    return Event(
        event_id=event_id,
        source=kind.lower(),
        kind=kind,
        event_time=BASE_TIME + timedelta(seconds=offset_seconds),
        user_id=user_id,
        machine_id=machine_id,
        properties=properties,
    )


def write_jsonl(events):
    temp = tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".jsonl", delete=False)
    with temp:
        for event in events:
            temp.write(json.dumps(event.to_record(), sort_keys=True) + "\n")
    return Path(temp.name)


@dataclass
class FakeScore:
    score: float
    components: dict[str, float]


class FakeRepository:
    def __init__(self, duplicate_ids=None):
        self.duplicate_ids = set(duplicate_ids or ())
        self.seen_ids = set()
        self.writes = []
        self.alerts = []
        self.order = []
        self.uc1_context_events = []
        self.uc2_context_events = []
        self.baseline_updates = []

    def write_event(self, event, ingest_time):
        self.order.append(("write", event.event_id))
        self.writes.append(event)
        created = event.event_id not in self.duplicate_ids and event.event_id not in self.seen_ids
        self.seen_ids.add(event.event_id)
        return WriteResult(event_id=event.event_id, created=created)

    def fetch_uc1_context(self, user_id, trigger_ts):
        event_id = self.writes[-1].event_id
        self.order.append(("fetch_uc1", event_id))
        self.uc1_context_events.append(event_id)
        return {"event_id": event_id, "trigger_ts": trigger_ts, "detector": "uc1"}

    def fetch_uc2_context(self, user_id, machine_id, trigger_ts):
        event_id = self.writes[-1].event_id
        self.order.append(("fetch_uc2", event_id))
        self.uc2_context_events.append(event_id)
        return {"event_id": event_id, "trigger_ts": trigger_ts, "detector": "uc2"}

    def upsert_alert(self, alert):
        self.order.append(("upsert_alert", alert.trigger_event_id))
        self.alerts.append(alert)

    def update_baselines(self, event):
        self.order.append(("update_baselines", event.event_id))
        self.baseline_updates.append(event.event_id)

    def prune_events(self, before_ts):
        self.order.append(("prune", before_ts))
        return 0


class FakeDetector:
    def __init__(self, detector, scores=None, alert=True):
        self.detector = detector
        self.scores = dict(scores or {})
        self.alert = alert
        self.scored = []
        self.evaluated = []

    def score(self, event, context):
        self.scored.append((event.event_id, context["event_id"]))
        return FakeScore(score=self.scores.get(event.event_id, 1.0), components={self.detector: 1.0})

    def evaluate(self, event, context, threshold):
        self.evaluated.append((event.event_id, threshold, context["event_id"]))
        if not self.alert or self.scores.get(event.event_id, 1.0) < threshold:
            return None
        return AlertRecord(
            alert_id=f"{self.detector}|{event.event_id}",
            detector=self.detector,
            score=self.scores.get(event.event_id, 1.0),
            threshold=threshold,
            trigger_event_id=event.event_id,
            event_time=event.event_time,
            components={self.detector: self.scores.get(event.event_id, 1.0)},
            user_ids=(event.user_id,),
            machine_ids=(event.machine_id,),
            evidence_event_ids=(event.event_id,),
            evidence_start_ts=event.event_ts,
            evidence_end_ts=event.event_ts,
        )


class ReplayEngineTest(unittest.TestCase):
    def test_jsonl_events_are_consumed_in_event_time_then_id_order(self):
        path = write_jsonl(
            [
                make_event("b", "HTTP", offset_seconds=20),
                make_event("a", "HTTP", offset_seconds=10),
            ]
        )
        repo = FakeRepository()
        engine = ReplayEngine(repo, FakeDetector("uc1", alert=False), FakeDetector("uc2", alert=False), ReplayConfig(calibration_days=0))

        engine.replay(path)

        self.assertEqual([event.event_id for event in repo.writes], ["a", "b"])

    def test_duplicate_events_do_not_invoke_detectors_twice(self):
        path = write_jsonl(
            [
                make_event("dup", "HTTP", offset_seconds=10),
                make_event("dup", "HTTP", offset_seconds=20),
            ]
        )
        repo = FakeRepository()
        uc1 = FakeDetector("uc1")
        uc2 = FakeDetector("uc2")
        engine = ReplayEngine(repo, uc1, uc2, ReplayConfig(calibration_days=0))

        summary = engine.replay(path)

        self.assertEqual(summary.duplicate_events, 1)
        self.assertEqual(len(uc1.evaluated), 1)
        self.assertEqual(len(uc2.evaluated), 1)

    def test_context_is_scored_before_baseline_update(self):
        event = make_event("http-1", "HTTP", offset_seconds=10)
        path = write_jsonl([event])
        repo = FakeRepository()
        engine = ReplayEngine(repo, FakeDetector("uc1"), FakeDetector("uc2", alert=False), ReplayConfig(calibration_days=0))

        engine.replay(path)

        self.assertEqual(
            repo.order[:4],
            [
                ("write", "http-1"),
                ("fetch_uc1", "http-1"),
                ("upsert_alert", "http-1"),
                ("fetch_uc2", "http-1"),
            ],
        )
        self.assertEqual(repo.order[-1], ("update_baselines", "http-1"))

    def test_detector_trigger_routing_matches_usecase_scope(self):
        events = [
            make_event("logon", "LOGON", offset_seconds=1),
            make_event("usb", "DEVICE_CONNECT", offset_seconds=2),
            make_event("copy", "FILE_COPY", offset_seconds=3),
            make_event("http", "HTTP", offset_seconds=4),
            make_event("email", "EMAIL", offset_seconds=5, recipients=("a@example.com",), recipient_count=1),
        ]
        path = write_jsonl(events)
        repo = FakeRepository()
        uc1 = FakeDetector("uc1", alert=False)
        uc2 = FakeDetector("uc2", alert=False)
        engine = ReplayEngine(repo, uc1, uc2, ReplayConfig(calibration_days=0))

        engine.replay(path)

        self.assertEqual([item[0] for item in uc1.evaluated], ["logon", "usb", "copy", "http"])
        self.assertEqual([item[0] for item in uc2.evaluated], ["logon", "usb", "copy", "http", "email"])

    def test_calibration_scores_freeze_to_995_percentile_before_alerting(self):
        events = [
            make_event("cal-low", "HTTP", offset_seconds=1),
            make_event("cal-high", "HTTP", offset_seconds=2),
            make_event("post", "HTTP", offset_seconds=31 * 24 * 60 * 60),
        ]
        path = write_jsonl(events)
        repo = FakeRepository()
        uc1 = FakeDetector("uc1", scores={"cal-low": 0.10, "cal-high": 0.90, "post": 0.90})
        uc2 = FakeDetector("uc2", alert=False)
        engine = ReplayEngine(repo, uc1, uc2, ReplayConfig(calibration_days=30, uc1_fallback_threshold=0.75))

        summary = engine.replay(path)

        self.assertEqual(summary.thresholds["uc1"], 0.90)
        self.assertEqual([alert.trigger_event_id for alert in repo.alerts], ["post"])
        self.assertEqual(summary.calibration_events, 2)

    def test_late_events_inside_forty_eight_hours_increment_recompute_counter(self):
        path = write_jsonl(
            [
                make_event("newer", "HTTP", offset_seconds=1000),
                make_event("late", "HTTP", offset_seconds=900),
            ]
        )
        repo = FakeRepository()
        engine = ReplayEngine(repo, FakeDetector("uc1", alert=False), FakeDetector("uc2", alert=False), ReplayConfig(calibration_days=0))

        summary = engine.replay(path)

        self.assertEqual(summary.late_events, 1)
        self.assertEqual(summary.recomputed_neighborhoods, 1)

    def test_processing_counters_are_populated(self):
        path = write_jsonl([make_event("one", "HTTP", offset_seconds=1)])
        repo = FakeRepository()
        engine = ReplayEngine(repo, FakeDetector("uc1", alert=False), FakeDetector("uc2", alert=False), ReplayConfig(calibration_days=0))

        summary = engine.replay(path)

        self.assertEqual(summary.processed_events, 1)
        self.assertGreaterEqual(summary.processing_seconds, 0.0)
        self.assertGreaterEqual(summary.throughput_events_per_second, 0.0)
        self.assertGreater(summary.peak_python_rss_mb, 0.0)


if __name__ == "__main__":
    unittest.main()
