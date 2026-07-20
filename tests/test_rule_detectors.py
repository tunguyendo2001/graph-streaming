import inspect
import unittest
from datetime import datetime, timedelta, timezone

from event_model import Event
from rule_detectors import RuleUC1Detector, RuleUC2Detector


BASE = datetime(2010, 1, 1, tzinfo=timezone.utc)


def event(event_id, kind, *, seconds=0, user_id="U001", machine_id="PC-1", **properties):
    return Event(
        event_id=event_id,
        source=kind.lower(),
        kind=kind,
        event_time=BASE + timedelta(seconds=seconds),
        user_id=user_id,
        machine_id=machine_id,
        properties=properties,
    )


class RuleDetectorTest(unittest.TestCase):
    def test_uc1_requires_after_hours_connect_and_external_signal(self):
        detector = RuleUC1Detector()

        self.assertIsNone(detector.observe(event("work-logon", "LOGON", seconds=9 * 3600, activity="LOGON")))
        self.assertIsNone(detector.observe(event("usb", "DEVICE_CONNECT", seconds=9 * 3600 + 60, activity="CONNECT")))
        self.assertIsNone(
            detector.observe(
                event("http", "HTTP", seconds=9 * 3600 + 120, domain="leak.example", leak_signal=True)
            )
        )

        detector = RuleUC1Detector()
        detector.observe(event("night-logon", "LOGON", seconds=2 * 3600, activity="LOGON"))
        detector.observe(event("night-usb", "DEVICE_CONNECT", seconds=2 * 3600 + 60, activity="CONNECT"))
        alert = detector.observe(event("night-http", "HTTP", seconds=2 * 3600 + 120, domain="leak.example", leak_signal=True))

        self.assertIsNotNone(alert)
        self.assertEqual(alert.detector, "rule_uc1")

    def test_uc1_alerts_on_fixed_file_count_after_after_hours_usb(self):
        detector = RuleUC1Detector(file_threshold=3)
        detector.observe(event("night-logon", "LOGON", seconds=2 * 3600, activity="LOGON"))
        detector.observe(event("night-usb", "DEVICE_CONNECT", seconds=2 * 3600 + 60, activity="CONNECT"))

        self.assertIsNone(detector.observe(event("file-1", "FILE_COPY", seconds=2 * 3600 + 120, filename="a.txt")))
        self.assertIsNone(detector.observe(event("file-2", "FILE_COPY", seconds=2 * 3600 + 121, filename="b.txt")))
        alert = detector.observe(event("file-3", "FILE_COPY", seconds=2 * 3600 + 122, filename="c.txt"))

        self.assertIsNotNone(alert)
        self.assertEqual(alert.reason, "after_hours_usb_file_threshold")

    def test_uc2_alerts_on_keylogger_usb_mass_email_and_unseen_machine(self):
        detector = RuleUC2Detector(recipient_threshold=10)

        detector.observe(event("keylogger", "HTTP", seconds=1, keylogger_signal=True))
        keylogger_usb_alert = detector.observe(event("usb", "DEVICE_CONNECT", seconds=2, activity="CONNECT"))
        mass_email_alert = detector.observe(
            event("email", "EMAIL", seconds=3, recipients=tuple(f"u{i}@x.test" for i in range(10)), recipient_count=10)
        )
        unseen_machine_alert = detector.observe(event("new-machine", "LOGON", seconds=4, machine_id="PC-2", activity="LOGON"))

        self.assertEqual(keylogger_usb_alert.reason, "keylogger_usb")
        self.assertEqual(mass_email_alert.reason, "recipient_threshold")
        self.assertEqual(unseen_machine_alert.reason, "unseen_machine")

    def test_rules_do_not_import_or_reference_graph_repository(self):
        import rule_detectors

        source = inspect.getsource(rule_detectors)
        self.assertNotIn("GraphRepository", source)
        self.assertNotIn("fetch_uc", source)


if __name__ == "__main__":
    unittest.main()
