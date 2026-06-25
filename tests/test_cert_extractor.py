import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from cert_extractor import (
    ActivityProfile,
    build_activity_profiles,
    load_incidents,
    robust_standardize,
    select_matched_controls,
    write_cohort_manifest,
)


FIXTURES = Path(__file__).resolve().parent / "fixtures"


class CohortSelectionTest(unittest.TestCase):
    def test_load_incidents_keeps_only_dataset_4_2(self):
        incidents = load_incidents(FIXTURES / "answers" / "insiders.csv")

        self.assertEqual([item.user_id for item in incidents], ["INSIDER1", "INSIDER2"])
        self.assertEqual([item.scenario for item in incidents], [1, 2])
        self.assertEqual(
            [item.details_file for item in incidents],
            ["r4.2-1-INSIDER1.csv", "r4.2-2-INSIDER2.csv"],
        )

    def test_load_incidents_rejects_extra_csv_columns_with_file_and_row_context(self):
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "insiders.csv"
            path.write_text(
                "\n".join(
                    [
                        "dataset,scenario,details,user,start,end",
                        "4.2,1,r4.2-1-INSIDER1.csv,INSIDER1,01/02/2010 07:00:00,01/05/2010 18:00:00,EXTRA",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, r"insiders\.csv row 2.*extra columns"):
                load_incidents(path)

    def test_load_incidents_rejects_missing_required_values_with_file_and_row_context(self):
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "insiders.csv"
            path.write_text(
                "\n".join(
                    [
                        "dataset,scenario,details,user,start,end",
                        "4.2,1,r4.2-1-INSIDER1.csv,INSIDER1,01/02/2010 07:00:00",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, r"insiders\.csv row 2.*missing required values: end"):
                load_incidents(path)

    def test_build_activity_profiles_counts_from_fixtures(self):
        profiles = build_activity_profiles(FIXTURES)

        insider1 = profiles["INSIDER1"]
        self.assertEqual(insider1.active_days, {"2010-01-02", "2010-01-03"})
        self.assertEqual(insider1.logon_count, 2)
        self.assertEqual(insider1.after_hours_logon_count, 1)
        self.assertEqual(insider1.device_connect_count, 1)
        self.assertEqual(insider1.file_copy_count, 2)
        self.assertEqual(insider1.email_count, 1)
        self.assertEqual(insider1.machines, {"PC-1001", "PC-1002"})
        self.assertEqual(
            insider1.vector,
            (2.0, 2.0, 0.5, 1.0, 2.0, 1.0, 2.0),
        )

        control4 = profiles["CONTROL4"]
        self.assertEqual(control4.logon_count, 2)
        self.assertEqual(control4.after_hours_logon_count, 1)
        self.assertEqual(control4.vector[2], 0.5)

    def test_build_activity_profiles_rejects_malformed_rows_with_file_and_row_context(self):
        with TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "logon.csv").write_text(
                "\n".join(
                    [
                        "id,date,user,pc,activity",
                        "{L1},01/02/2010 07:30:00,INSIDER1,PC-1001,Logon,EXTRA",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, r"logon\.csv row 2.*extra columns"):
                build_activity_profiles(temp_path)

    def test_robust_standardize_handles_zero_mad_columns(self):
        standardized = robust_standardize(
            {
                "A": (1.0, 10.0),
                "B": (2.0, 10.0),
                "C": (100.0, 10.0),
            }
        )

        self.assertAlmostEqual(standardized["A"][0], -0.6744907594765952)
        self.assertEqual(standardized["A"][1], 0.0)
        self.assertEqual(standardized["B"][1], 0.0)
        self.assertEqual(standardized["C"][1], 0.0)

    def test_robust_standardize_rejects_mixed_vector_widths(self):
        with self.assertRaisesRegex(ValueError, r"mixed vector widths"):
            robust_standardize(
                {
                    "A": (1.0, 2.0),
                    "B": (3.0,),
                }
            )

    def test_robust_standardize_rejects_non_finite_values(self):
        with self.assertRaisesRegex(ValueError, r"A.*finite numeric"):
            robust_standardize(
                {
                    "A": (1.0, float("nan")),
                    "B": (2.0, 3.0),
                }
            )

    def test_controls_never_include_ground_truth_users(self):
        controls = select_matched_controls(
            profiles=self.fixture_profiles(),
            insider_ids={"INSIDER1", "INSIDER2"},
            controls_per_insider=2,
        )

        self.assertFalse(
            {"INSIDER1", "INSIDER2"} & {control.control_id for control in controls}
        )

    def test_nearest_controls_do_not_reuse_and_stay_deterministic(self):
        first = select_matched_controls(self.fixture_profiles(), {"INSIDER1", "INSIDER2"}, 2)
        second = select_matched_controls(self.fixture_profiles(), {"INSIDER1", "INSIDER2"}, 2)

        self.assertEqual(first, second)
        self.assertEqual(
            [(match.insider_id, match.control_id) for match in first],
            [
                ("INSIDER1", "CONTROL_A"),
                ("INSIDER1", "CONTROL_B"),
                ("INSIDER2", "CONTROL_C"),
                ("INSIDER2", "CONTROL_D"),
            ],
        )
        self.assertEqual(
            len({match.control_id for match in first}),
            len(first),
        )

    def test_manifest_is_deterministic_round_trippable_and_contains_no_fabricated_users(self):
        incidents = load_incidents(FIXTURES / "answers" / "insiders.csv")
        controls = select_matched_controls(self.fixture_profiles(), {"INSIDER1", "INSIDER2"}, 2)
        expected_users = {
            "INSIDER1",
            "INSIDER2",
            "CONTROL_A",
            "CONTROL_B",
            "CONTROL_C",
            "CONTROL_D",
        }

        with TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "nested" / "cohort.json"
            write_cohort_manifest(output_path, incidents, controls)
            first_text = output_path.read_text(encoding="utf-8")
            first_payload = json.loads(first_text)

            write_cohort_manifest(output_path, incidents, controls)
            second_text = output_path.read_text(encoding="utf-8")

        self.assertEqual(first_text, second_text)
        self.assertEqual(json.loads(second_text), first_payload)
        self.assertEqual(
            {record["user_id"] for record in first_payload["incidents"]},
            {"INSIDER1", "INSIDER2"},
        )
        self.assertEqual(
            {record["control_id"] for record in first_payload["controls"]},
            {"CONTROL_A", "CONTROL_B", "CONTROL_C", "CONTROL_D"},
        )
        self.assertTrue(
            {record["user_id"] for record in first_payload["incidents"]}
            | {record["control_id"] for record in first_payload["controls"]}
            <= expected_users
        )
        self.assertTrue(
            all("is_insider" not in record["selection_features"] for record in first_payload["controls"])
        )

    @staticmethod
    def fixture_profiles():
        def make_profile(
            user_id,
            active_days,
            logon_count,
            after_hours_logon_count,
            device_connect_count,
            file_copy_count,
            email_count,
            machines,
        ):
            return ActivityProfile(
                user_id=user_id,
                active_days=set(active_days),
                logon_count=logon_count,
                after_hours_logon_count=after_hours_logon_count,
                device_connect_count=device_connect_count,
                file_copy_count=file_copy_count,
                email_count=email_count,
                machines=set(machines),
            )

        return {
            "INSIDER1": make_profile(
                "INSIDER1",
                {"2010-01-02", "2010-01-03"},
                10,
                5,
                2,
                5,
                1,
                {"PC-1", "PC-2"},
            ),
            "INSIDER2": make_profile(
                "INSIDER2",
                {"2010-01-02", "2010-01-03", "2010-01-04", "2010-01-05", "2010-01-06", "2010-01-07"},
                30,
                24,
                5,
                10,
                3,
                {"PC-3", "PC-4", "PC-5", "PC-6"},
            ),
            "CONTROL_A": make_profile(
                "CONTROL_A",
                {"2010-01-02", "2010-01-03"},
                11,
                5,
                2,
                4,
                1,
                {"PC-1", "PC-2"},
            ),
            "CONTROL_B": make_profile(
                "CONTROL_B",
                {"2010-01-02", "2010-01-03", "2010-01-04"},
                9,
                5,
                2,
                5,
                1,
                {"PC-1", "PC-2", "PC-7"},
            ),
            "CONTROL_C": make_profile(
                "CONTROL_C",
                {"2010-01-02", "2010-01-03", "2010-01-04", "2010-01-05", "2010-01-06", "2010-01-07"},
                29,
                22,
                5,
                9,
                3,
                {"PC-3", "PC-4", "PC-5", "PC-6"},
            ),
            "CONTROL_D": make_profile(
                "CONTROL_D",
                {"2010-01-02", "2010-01-03", "2010-01-04", "2010-01-05", "2010-01-06"},
                31,
                23,
                5,
                10,
                2,
                {"PC-3", "PC-4", "PC-5", "PC-6"},
            ),
        }


if __name__ == "__main__":
    unittest.main()
