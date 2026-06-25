import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from cert_extractor import extract_evaluation_stream
from tests.test_cert_extractor import FIXTURES

class StreamExtractionTest(unittest.TestCase):
    def test_extract_keeps_only_cohort_and_discards_content(self):
        with TemporaryDirectory() as tmp:
            output = Path(tmp) / "out.jsonl"
            result = extract_evaluation_stream(
                input_dir=FIXTURES,
                cohort={"INSIDER1", "CONTROL1"},
                output_path=output,
                run_size=2,
            )
            records = [json.loads(line) for line in output.read_text().splitlines()]
            self.assertTrue({record["user_id"] for record in records} <= {"INSIDER1", "CONTROL1"})
            self.assertTrue(all("content" not in json.dumps(record) for record in records))
            self.assertEqual(result.event_count, len(records))

    def test_external_merge_orders_by_event_time_then_event_id(self):
        with TemporaryDirectory() as tmp:
            output = Path(tmp) / "out.jsonl"
            extract_evaluation_stream(
                input_dir=FIXTURES,
                cohort={"INSIDER1", "CONTROL1"},
                output_path=output,
                run_size=2,
            )
            records = [json.loads(line) for line in output.read_text().splitlines()]
            ordering = [(record["event_ts"], record["event_id"]) for record in records]
            self.assertEqual(ordering, sorted(ordering))
            
if __name__ == "__main__":
    unittest.main()
