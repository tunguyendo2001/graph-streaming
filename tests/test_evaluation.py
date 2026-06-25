import unittest
from evaluation import evaluate_alerts, EvaluationAlert
from cert_extractor import Incident
from datetime import datetime

class EvaluationTest(unittest.TestCase):
    def test_evaluate_alerts(self):
        incidents = [Incident(1, "foo", "u1", datetime.now(), datetime.now())]
        alerts = [EvaluationAlert("a1", "UC1", ("u1",), 0, 0)]
        report = evaluate_alerts(alerts, incidents)
        self.assertEqual(report.f1, 1.0)

if __name__ == "__main__":
    unittest.main()
