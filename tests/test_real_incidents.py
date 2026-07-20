import csv
import unittest
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from cert_extractor import load_incidents
from event_model import Event, parse_cert_row
from graph_detectors import UC1Detector, UC2Detector


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _data_root() -> Path:
    repo = _repo_root()
    candidates = [
        repo / "data" / "cert-r4.2",
        repo.parent.parent / "data" / "cert-r4.2",
    ]
    for candidate in candidates:
        if (candidate / "answers" / "insiders.csv").exists():
            return candidate
    return candidates[0]


DATA_ROOT = _data_root()


def _answer_events(relative_path: str) -> list[Event]:
    source = DATA_ROOT / "answers" / relative_path
    with source.open("r", encoding="utf-8", newline="") as handle:
        return [_event_from_answer_row(row) for row in csv.reader(handle)]


def _event_from_answer_row(row: list[str]) -> Event:
    source, event_id, timestamp, user_id, machine_id = row[:5]
    event_time = datetime.strptime(timestamp, "%m/%d/%Y %H:%M:%S").replace(tzinfo=timezone.utc)
    common = {
        "event_id": event_id,
        "source": source,
        "event_time": event_time,
        "user_id": user_id,
        "machine_id": machine_id,
    }
    if source == "logon":
        activity = row[5].upper()
        return Event(kind=activity, properties={"activity": activity}, **common)
    if source == "device":
        activity = row[5].upper()
        kind = "DEVICE_CONNECT" if activity == "CONNECT" else "DEVICE_DISCONNECT"
        return Event(kind=kind, properties={"activity": activity}, **common)
    if source == "file":
        filename = row[5]
        return Event(kind="FILE_COPY", properties={"filename": filename, "extension": Path(filename).suffix.lower()}, **common)
    if source == "http":
        url = row[5]
        content = row[6] if len(row) > 6 else ""
        text = f"{url} {content}".lower()
        return Event(
            kind="HTTP",
            properties={
                "url": url,
                "domain": (urlparse(url).hostname or "").lower(),
                "keylogger_signal": any(term in text for term in ("keylog", "spectorsoft", "monitoring")),
                "job_signal": any(term in text for term in ("job", "career", "resume", "monster", "linkedin", "northropgrumman")),
                "leak_signal": any(term in text for term in ("wikileaks", "confidential", "top-secret", "surveillance")),
                "cloud_signal": any(term in text for term in ("dropbox", "drive", "cloud")),
            },
            **common,
        )
    if source == "email":
        recipients = tuple(_split_addresses(*row[5:8]))
        return Event(
            kind="EMAIL",
            properties={
                "sender": row[8],
                "recipients": recipients,
                "recipient_count": len(recipients),
                "size": int(row[9]),
                "attachments": int(row[10]),
            },
            **common,
        )
    raise ValueError(source)


def _split_addresses(*values: str) -> list[str]:
    addresses: list[str] = []
    for value in values:
        addresses.extend(address.strip() for address in value.split(";") if address.strip())
    return addresses


def _record(event: Event) -> dict:
    record = event.to_record()
    return {
        "event_id": record["event_id"],
        "source": record["source"],
        "kind": record["kind"],
        "user_id": record["user_id"],
        "machine_id": record["machine_id"],
        "event_ts": record["event_ts"],
        **record["properties"],
    }


def _main_events(source: str, user_id: str, before_ts: int, limit: int) -> list[Event]:
    events: list[Event] = []
    path = DATA_ROOT / "r4.2" / f"{source}.csv"
    if not path.exists():
        path = DATA_ROOT / f"{source}.csv"
    with path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            if row.get("user") != user_id:
                continue
            event = parse_cert_row(source, row)
            if event.event_ts < before_ts:
                events.append(event)
                if len(events) >= limit:
                    break
    return events


def _uc1_context(user_id: str, trigger: Event, candidate_events: list[Event], history_events: list[Event] | None = None) -> dict:
    return {
        "user_id": user_id,
        "history_start_ts": trigger.event_ts - 30 * 24 * 60 * 60,
        "motif_start_ts": trigger.event_ts - 48 * 60 * 60,
        "trigger_ts": trigger.event_ts,
        "history_events": [_record(event) for event in (history_events or [])],
        "candidate_events": [_record(event) for event in candidate_events],
    }


@unittest.skipUnless((DATA_ROOT / "answers" / "insiders.csv").exists(), "CERT r4.2 data is not available")
class RealIncidentSmokeTest(unittest.TestCase):
    def test_scenario1_aam0658_completes_uc1_leak_motif(self):
        incidents = load_incidents(DATA_ROOT / "answers" / "insiders.csv")
        self.assertTrue(any(incident.scenario == 1 and incident.user_id == "AAM0658" for incident in incidents))
        events = _answer_events("r4.2-1/r4.2-1-AAM0658.csv")
        trigger = [event for event in events if event.kind == "HTTP"][-1]
        candidate = [event for event in events if event.event_ts >= trigger.event_ts - 8 * 60 * 60 and event.event_ts <= trigger.event_ts]
        history = _main_events("logon", "AAM0658", trigger.event_ts, limit=20)

        alert = UC1Detector().evaluate(trigger, _uc1_context("AAM0658", trigger, candidate, history), threshold=0.55)

        self.assertIsNotNone(alert)
        self.assertIn(trigger.event_id, alert.evidence_event_ids)
        self.assertGreaterEqual(alert.components["C1"], 0.60)

    def test_scenario2_vss0154_completes_uc1_intent_usb_spike_motif(self):
        incidents = load_incidents(DATA_ROOT / "answers" / "insiders.csv")
        self.assertTrue(any(incident.scenario == 2 and incident.user_id == "VSS0154" for incident in incidents))
        events = _answer_events("r4.2-2/r4.2-2-VSS0154.csv")
        trigger = next(event for event in events if event.event_id == "{I7A3-X8IY76QF-0814NXMC}")
        candidate = [event for event in events if event.event_ts >= trigger.event_ts - 2 * 60 * 60 and event.event_ts <= trigger.event_ts]
        history = _main_events("logon", "VSS0154", trigger.event_ts, limit=20)

        alert = UC1Detector().evaluate(trigger, _uc1_context("VSS0154", trigger, candidate, history), threshold=0.50)

        self.assertIsNotNone(alert)
        self.assertGreaterEqual(alert.components["U"], 1.0)
        self.assertGreaterEqual(alert.components["C1"], 0.60)

    def test_scenario3_bbs0039_completes_uc2_multi_identity_motif(self):
        incidents = load_incidents(DATA_ROOT / "answers" / "insiders.csv")
        self.assertTrue(any(incident.scenario == 3 and incident.user_id == "BBS0039" for incident in incidents))
        events = _answer_events("r4.2-3/r4.2-3-BBS0039.csv")
        trigger = next(event for event in events if event.event_id == "{V0A3-P6AV43QU-3599SLER}")
        context = {
            "user_id": "FAW0032",
            "machine_id": "PC-5866",
            "target_machine_id": "PC-5866",
            "source_machine_id": "PC-9436",
            "attacker_user_id": "BBS0039",
            "owner_confidence": 1.0,
            "user_machine_probability": 0.0,
            "trigger_ts": trigger.event_ts,
            "stage_events": [_record(event) for event in events if event.event_ts <= trigger.event_ts],
            "recipient_history": ["Frances.Alisa.Wiggins@dtaa.com"],
            "current_recipients": trigger.properties["recipients"],
            "per_email_history": [1, 1],
            "window_fanout_history": [1, 1],
            "current_window_recipient_count": len(trigger.properties["recipients"]),
        }

        alert = UC2Detector().evaluate(trigger, context, threshold=0.65)

        self.assertIsNotNone(alert)
        self.assertEqual(alert.user_ids, ("BBS0039", "FAW0032"))
        self.assertIn("PC-5866", alert.machine_ids)
        self.assertIn("PC-9436", alert.machine_ids)

    def test_real_control_logon_does_not_exceed_uc1_gate(self):
        insiders = {incident.user_id for incident in load_incidents(DATA_ROOT / "answers" / "insiders.csv")}
        path = DATA_ROOT / "r4.2" / "logon.csv"
        if not path.exists():
            path = DATA_ROOT / "logon.csv"
        with path.open("r", encoding="utf-8", newline="") as handle:
            control = next(
                parse_cert_row("logon", row)
                for row in csv.DictReader(handle)
                if row["user"] not in insiders and row["activity"].lower() == "logon"
            )

        alert = UC1Detector().evaluate(control, _uc1_context(control.user_id, control, [control], []), threshold=0.0)

        self.assertIsNone(alert)


if __name__ == "__main__":
    unittest.main()
