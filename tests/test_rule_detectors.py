import unittest
from datetime import datetime
from event_model import Event
from rule_detectors import RuleUC1Detector, RuleUC2Detector

class RuleDetectorTest(unittest.TestCase):
    def test_rule_uc1(self):
        det = RuleUC1Detector()
        e = Event("e1", "file", "FILE_COPY", datetime.now(), "u1", "m1")
        alert = det.observe(e)
        self.assertIsNotNone(alert)
        
    def test_rule_uc2(self):
        det = RuleUC2Detector()
        e = Event("e2", "email", "EMAIL", datetime.now(), "u1", "m1", {"recipient_count": 15})
        alert = det.observe(e)
        self.assertIsNotNone(alert)

if __name__ == "__main__":
    unittest.main()
