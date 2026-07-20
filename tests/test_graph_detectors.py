import unittest
from datetime import datetime, timezone
from pathlib import Path

from baselines import logon_hour_anomaly
from event_model import Event
from graph_detectors import UC1Detector, UC2Detector


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


def email_trigger(recipients=None, event_time=None):
    recipients = tuple(recipients or [f"new{i}@external.example" for i in range(11)])
    event_time = event_time or dt(2010, 2, 1, 15, 0)
    return Event(
        event_id="email-final",
        source="email",
        kind="EMAIL",
        event_time=event_time,
        user_id="FAW0032",
        machine_id="PC-5866",
        properties={
            "recipients": recipients,
            "recipient_count": len(recipients),
            "size": 50_000,
            "attachments": 0,
        },
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


def uc2_stage_events(*, pivot_before_keylogger=False, attacker_user_id="BBS0039"):
    keylogger_ts = ts(2010, 2, 1, 10, 0)
    source_usb_ts = ts(2010, 2, 1, 10, 5)
    source_file_ts = ts(2010, 2, 1, 10, 10)
    pivot_ts = ts(2010, 2, 1, 13, 0)
    if pivot_before_keylogger:
        pivot_ts = ts(2010, 2, 1, 9, 0)
    return [
        event_dict(
            "bbs-keylogger",
            "HTTP",
            keylogger_ts,
            user_id=attacker_user_id,
            machine_id="PC-9436",
            domain="keylogger.example",
            keylogger_signal=True,
        ),
        event_dict(
            "bbs-usb-source",
            "DEVICE_CONNECT",
            source_usb_ts,
            user_id=attacker_user_id,
            machine_id="PC-9436",
            activity="CONNECT",
        ),
        event_dict(
            "bbs-copy-exe",
            "FILE_COPY",
            source_file_ts,
            user_id=attacker_user_id,
            machine_id="PC-9436",
            filename="collector.exe",
            extension=".exe",
        ),
        event_dict(
            "bbs-logon-target",
            "LOGON",
            pivot_ts,
            user_id=attacker_user_id,
            machine_id="PC-5866",
            activity="LOGON",
        ),
        event_dict(
            "bbs-usb-target",
            "DEVICE_CONNECT",
            ts(2010, 2, 1, 13, 5),
            user_id=attacker_user_id,
            machine_id="PC-5866",
            activity="CONNECT",
        ),
        event_dict(
            "faw-logon-target",
            "LOGON",
            ts(2010, 2, 1, 14, 40),
            user_id="FAW0032",
            machine_id="PC-5866",
            activity="LOGON",
        ),
    ]


def uc2_context(*, recipients=None, stage_events=None, owner_confidence=1.0, user_machine_probability=0.0, attacker_user_id="BBS0039"):
    event = email_trigger(recipients=recipients)
    recipients = tuple(event.properties["recipients"])
    old_recipients = recipients[:3]
    return {
        "user_id": "FAW0032",
        "machine_id": "PC-5866",
        "trigger_ts": event.event_ts,
        "window_start_ts": event.event_ts - 48 * 60 * 60,
        "attacker_user_id": attacker_user_id,
        "source_machine_id": "PC-9436",
        "target_machine_id": "PC-5866",
        "owner_confidence": owner_confidence,
        "user_machine_probability": user_machine_probability,
        "stage_events": list(stage_events if stage_events is not None else uc2_stage_events(attacker_user_id=attacker_user_id)),
        "recipient_history": list(old_recipients),
        "current_recipients": list(recipients),
        "per_email_history": [2, 2, 3, 3, 4],
        "window_fanout_history": [4, 4, 5, 5, 6],
        "current_window_recipient_count": len(recipients),
    }


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


class UC2DetectorTest(unittest.TestCase):
    def test_final_mass_email_after_attacker_machine_bridge_alerts(self):
        detector = UC2Detector()
        event = email_trigger()
        context = uc2_context()

        alert = detector.evaluate(event, context, threshold=0.75)

        self.assertIsNotNone(alert)
        self.assertEqual(alert.detector, "uc2_credential_pivot_motif")
        self.assertEqual(alert.user_ids, ("BBS0039", "FAW0032"))
        self.assertEqual(alert.machine_ids, ("PC-5866", "PC-9436"))
        self.assertGreaterEqual(alert.score, 0.75)
        self.assertGreaterEqual(alert.components["M"], 0.90)
        self.assertGreaterEqual(alert.components["K"], 0.60)
        self.assertEqual(alert.components["E"], 1.0)
        self.assertGreaterEqual(alert.components["C2"], 0.50)
        self.assertIn("bbs-keylogger", alert.evidence_event_ids)
        self.assertIn("email-final", alert.evidence_event_ids)
        self.assertIn("recipient:new10@external.example", alert.evidence_event_ids)

    def test_shared_machine_with_low_owner_confidence_reduces_m_below_gate(self):
        detector = UC2Detector()
        event = email_trigger()
        context = uc2_context(owner_confidence=0.50)

        score = detector.score(event, context)

        self.assertEqual(score.components["M"], 0.50)
        self.assertIsNone(detector.evaluate(event, context, threshold=0.0))

    def test_mass_email_without_attacker_victim_machine_bridge_does_not_alert(self):
        detector = UC2Detector()
        event = email_trigger()
        context = uc2_context(stage_events=[])

        score = detector.score(event, context)

        self.assertEqual(score.components["K"], 0.0)
        self.assertEqual(score.components["C2"], 0.0)
        self.assertIsNone(detector.evaluate(event, context, threshold=0.0))

    def test_k_decreases_when_pivot_precedes_keylogger_and_usb_stages(self):
        detector = UC2Detector()
        event = email_trigger()
        ordered = detector.score(event, uc2_context())
        reordered = detector.score(
            event,
            uc2_context(stage_events=uc2_stage_events(pivot_before_keylogger=True)),
        )

        self.assertLess(reordered.components["K"], ordered.components["K"])
        self.assertLess(reordered.components["K"], 0.40)
        self.assertIsNone(
            detector.evaluate(
                event,
                uc2_context(stage_events=uc2_stage_events(pivot_before_keylogger=True)),
                threshold=0.0,
            )
        )

    def test_recipient_novelty_is_fraction_outside_social_neighborhood(self):
        detector = UC2Detector()
        event = email_trigger()

        score = detector.score(event, uc2_context())

        self.assertAlmostEqual(score.components["R"], 8 / 11)

    def test_same_attacker_and_victim_zeroes_identity_bridge(self):
        detector = UC2Detector()
        event = Event(
            event_id="email-final",
            source="email",
            kind="EMAIL",
            event_time=dt(2010, 2, 1, 15, 0),
            user_id="FAW0032",
            machine_id="PC-5866",
            properties={
                "recipients": tuple(f"new{i}@external.example" for i in range(11)),
                "recipient_count": 11,
            },
        )
        context = uc2_context(attacker_user_id="FAW0032", stage_events=uc2_stage_events(attacker_user_id="FAW0032"))

        score = detector.score(event, context)

        self.assertEqual(score.components["C2"], 0.0)
        self.assertIsNone(detector.evaluate(event, context, threshold=0.0))


class UC2EvidenceQueryTest(unittest.TestCase):
    def test_query_contains_identity_bridge_and_email_neighborhood_terms(self):
        query = Path("queries/uc2_evidence.cypher").read_text(encoding="utf-8")

        self.assertIn("MATCH (victim:User {id: $user_id})", query)
        self.assertIn("target_machine:Machine {id: $machine_id}", query)
        self.assertIn("attacker.id <> victim.id", query)
        self.assertIn("keylogger_signal", query)
        self.assertIn(":USED_MACHINE", query)
        self.assertIn(":EMAILED", query)
        self.assertIn("recipient_history", query)
        self.assertIn("current_recipients", query)


if __name__ == "__main__":
    unittest.main()
