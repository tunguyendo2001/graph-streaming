import unittest
from datetime import datetime

from event_model import Event
from graph_detectors import UC1Detector


class UC1DetectorTest(unittest.TestCase):
    def test_alert_generation(self):
        detector = UC1Detector()
        trigger = Event("e1", "http", "HTTP", datetime(2010, 1, 1, 12, 0, 0), "u1", "m1", {})
        context = {
            "C1": 0.8,
            "U_current_daily": 5,
            "U_daily_counts": [1, 2],
            "U_seen_before": False
        }
        alert = detector.evaluate(trigger, context, 0.5)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.detector, "UC1")

    def test_uc2_alert_generation(self):
        from graph_detectors import UC2Detector
        detector = UC2Detector()
        trigger = Event("e2", "email", "EMAIL", datetime(2010, 1, 1, 12, 0, 0), "u2", "m1", {})
        context = {
            "M": 0.8,
            "K": 0.6,
            "E": 0.5,
            "R": 0.5,
            "C2": 0.7
        }
        alert = detector.evaluate(trigger, context, 0.5)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.detector, "UC2")

if __name__ == "__main__":
    unittest.main()

