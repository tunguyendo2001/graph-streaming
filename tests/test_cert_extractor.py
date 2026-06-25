import json
import unittest
from pathlib import Path

from cert_extractor import (
    ActivityProfile,
    load_incidents,
    select_matched_controls,
)

FIXTURES = Path(__file__).parent / "fixtures"

def fixture_profiles():
    return {
        "INSIDER1": ActivityProfile("INSIDER1", {"2010-01-01"}, 1, 0, 0, 0, 0),
        "INSIDER2": ActivityProfile("INSIDER2", {"2010-02-01"}, 1, 0, 0, 0, 0),
        "CONTROL1": ActivityProfile("CONTROL1", {"2010-01-01"}, 1, 0, 0, 0, 0),
        "CONTROL2": ActivityProfile("CONTROL2", {"2010-01-01"}, 2, 0, 0, 0, 0),
        "CONTROL3": ActivityProfile("CONTROL3", {"2010-01-01"}, 3, 0, 0, 0, 0),
        "CONTROL4": ActivityProfile("CONTROL4", {"2010-01-01"}, 4, 0, 0, 0, 0),
    }

class CohortSelectionTest(unittest.TestCase):
    def test_load_incidents_keeps_only_dataset_4_2(self):
        incidents = load_incidents(FIXTURES / "answers" / "insiders.csv")
        self.assertEqual({item.user_id for item in incidents}, {"INSIDER1", "INSIDER2"})

    def test_controls_never_include_ground_truth_users(self):
        controls = select_matched_controls(
            profiles=fixture_profiles(),
            insider_ids={"INSIDER1", "INSIDER2"},
            controls_per_insider=2,
        )
        self.assertFalse(set(controls) & {"INSIDER1", "INSIDER2"})

    def test_control_selection_is_deterministic(self):
        first = select_matched_controls(fixture_profiles(), {"INSIDER1"}, 2)
        second = select_matched_controls(fixture_profiles(), {"INSIDER1"}, 2)
        self.assertEqual(first, second)

if __name__ == "__main__":
    unittest.main()
