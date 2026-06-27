import json
import unittest
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from cert_extractor import (
    ActivityProfile,
    Incident,
    build_activity_profiles,
    extract_evaluation_stream,
    load_incidents,
    robust_standardize,
    select_matched_controls,
    write_cohort_manifest,
)


FIXTURES = Path(__file__).resolve().parent / "fixtures"

OFFICIAL_EMAIL_HEADER = "id,date,user,pc,to,cc,bcc,from,size,attachments,content"


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

    def test_load_incidents_rejects_empty_or_whitespace_required_values_with_field_context(self):
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "insiders.csv"
            path.write_text(
                "\n".join(
                    [
                        "dataset,scenario,details,user,start,end",
                        "4.2,1,r4.2-1-INSIDER1.csv,   ,  ,01/05/2010 18:00:00",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                ValueError,
                r"insiders\.csv row 2.*missing required values: start, user|insiders\.csv row 2.*missing required values: user, start",
            ):
                load_incidents(path)

    def test_load_incidents_rejects_invalid_timestamps_with_file_row_and_column_context(self):
        for column, values in (
            ("start", ["4.2", "1", "r4.2-1-INSIDER1.csv", "INSIDER1", "not-a-date", "01/05/2010 18:00:00"]),
            ("end", ["4.2", "1", "r4.2-1-INSIDER1.csv", "INSIDER1", "01/02/2010 07:00:00", "not-a-date"]),
        ):
            with self.subTest(column=column), TemporaryDirectory() as temp_dir:
                path = Path(temp_dir) / "insiders.csv"
                path.write_text(
                    "\n".join(
                        [
                            "dataset,scenario,details,user,start,end",
                            ",".join(values),
                        ]
                    )
                    + "\n",
                    encoding="utf-8",
                )

                with self.assertRaisesRegex(
                    ValueError,
                    rf"insiders\.csv row 2 column {column}.*invalid timestamp",
                ):
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

    def test_build_activity_profiles_requires_official_cert_email_header(self):
        with TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "email.csv").write_text(
                "\n".join(
                    [
                        "date,user,pc",
                        "01/02/2010 07:45:00,INSIDER1,PC-1001",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                ValueError,
                r"email\.csv header must match official CERT fields",
            ):
                build_activity_profiles(temp_path)

    def test_build_activity_profiles_rejects_extra_shuffled_or_duplicate_email_headers(self):
        cases = (
            (
                "extra",
                OFFICIAL_EMAIL_HEADER + ",extra",
                "{E1},01/02/2010 07:45:00,INSIDER1,PC-1001,one@example.com,,,inside1@example.com,100,0,hello,ignored",
            ),
            (
                "shuffled",
                "date,id,user,pc,to,cc,bcc,from,size,attachments,content",
                "01/02/2010 07:45:00,{E1},INSIDER1,PC-1001,one@example.com,,,inside1@example.com,100,0,hello",
            ),
            (
                "duplicate",
                OFFICIAL_EMAIL_HEADER + ",content",
                "{E1},01/02/2010 07:45:00,INSIDER1,PC-1001,one@example.com,,,inside1@example.com,100,0,hello,duplicate",
            ),
        )
        for label, header, row in cases:
            with self.subTest(label=label), TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                (temp_path / "email.csv").write_text(
                    "\n".join([header, row]) + "\n",
                    encoding="utf-8",
                )

                with self.assertRaisesRegex(
                    ValueError,
                    r"email\.csv header must match official CERT fields",
                ):
                    build_activity_profiles(temp_path)

    def test_build_activity_profiles_rejects_empty_or_whitespace_required_values_with_field_context(self):
        with TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "logon.csv").write_text(
                "\n".join(
                    [
                        "id,date,user,pc,activity",
                        "{L1},01/02/2010 07:30:00,,   ,Logon",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                ValueError,
                r"logon\.csv row 2.*missing required values: pc, user|logon\.csv row 2.*missing required values: user, pc",
            ):
                build_activity_profiles(temp_path)

    def test_build_activity_profiles_rejects_invalid_activity_timestamps_with_file_row_and_column_context(self):
        cases = (
            (
                "logon.csv",
                "id,date,user,pc,activity",
                "{L1},not-a-date,INSIDER1,PC-1001,Logoff",
            ),
            (
                "device.csv",
                "id,date,user,pc,activity",
                "{D1},not-a-date,INSIDER1,PC-1001,Disconnect",
            ),
            (
                "file.csv",
                "id,date,user,pc,filename,content",
                "{F1},not-a-date,INSIDER1,PC-1001,file-a.doc,alpha",
            ),
            (
                "email.csv",
                OFFICIAL_EMAIL_HEADER,
                "{E1},not-a-date,INSIDER1,PC-1001,one@example.com,,,inside1@example.com,100,0,hello",
            ),
        )
        for source_name, header, row in cases:
            with self.subTest(source_name=source_name), TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                (temp_path / source_name).write_text(
                    "\n".join([header, row]) + "\n",
                    encoding="utf-8",
                )

                with self.assertRaisesRegex(
                    ValueError,
                    rf"{source_name} row 2 column date.*invalid timestamp",
                ):
                    build_activity_profiles(temp_path)

    def test_build_activity_profiles_rejects_blank_required_email_values(self):
        required_fields = ("id", "date", "user", "pc", "from", "size", "attachments")
        base_row = {
            "id": "{E1}",
            "date": "01/02/2010 07:45:00",
            "user": "INSIDER1",
            "pc": "PC-1001",
            "to": "one@example.com",
            "cc": "",
            "bcc": "",
            "from": "inside1@example.com",
            "size": "100",
            "attachments": "0",
            "content": "hello",
        }
        fields = OFFICIAL_EMAIL_HEADER.split(",")

        for field in required_fields:
            with self.subTest(field=field), TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                row = dict(base_row)
                row[field] = "   "
                (temp_path / "email.csv").write_text(
                    "\n".join(
                        [
                            OFFICIAL_EMAIL_HEADER,
                            ",".join(row[column] for column in fields),
                        ]
                    )
                    + "\n",
                    encoding="utf-8",
                )

                with self.assertRaisesRegex(
                    ValueError,
                    rf"email\.csv row 2.*missing required values: {field}",
                ):
                    build_activity_profiles(temp_path)

    def test_build_activity_profiles_allows_blank_optional_email_values(self):
        with TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "email.csv").write_text(
                "\n".join(
                    [
                        OFFICIAL_EMAIL_HEADER,
                        "{E1},01/02/2010 07:45:00,INSIDER1,PC-1001,,,,inside1@example.com,100,0,",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            profiles = build_activity_profiles(temp_path)

        self.assertEqual(profiles["INSIDER1"].email_count, 1)

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

    def test_select_matched_controls_rejects_mixed_keyword_aliases(self):
        incident = Incident(
            scenario=1,
            details_file="r4.2-1-INSIDER1.csv",
            user_id="INSIDER1",
            start=datetime(2010, 1, 2, 9, 0, 0),
            end=datetime(2010, 1, 5, 18, 0, 0),
        )

        with self.assertRaisesRegex(TypeError, r"cannot mix"):
            select_matched_controls(
                profiles=self.fixture_profiles(),
                incidents=[incident],
                controls_per_insider=1,
            )

        with self.assertRaisesRegex(TypeError, r"cannot mix"):
            select_matched_controls(
                input_dir=FIXTURES,
                insider_ids={"INSIDER1"},
                controls_per_insider=1,
            )

    def test_select_matched_controls_accepts_incident_keyword_path_aliases(self):
        class PathWithItems:
            def __init__(self, value):
                self.value = Path(value)

            def __fspath__(self):
                return str(self.value)

            def items(self):
                raise AssertionError("path-like object must not be treated as a mapping")

        incident = Incident(
            scenario=1,
            details_file="r4.2-1-INSIDER1.csv",
            user_id="INSIDER1",
            start=datetime(2010, 1, 2, 9, 0, 0),
            end=datetime(2010, 1, 5, 18, 0, 0),
        )

        with TemporaryDirectory() as temp_dir:
            input_dir = Path(temp_dir)
            (input_dir / "logon.csv").write_text(
                "\n".join(
                    [
                        "id,date,user,pc,activity",
                        "{I-pre},01/01/2010 08:00:00,INSIDER1,PC-I,Logon",
                        "{A-pre},01/01/2010 08:00:00,CONTROL_A,PC-I,Logon",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            controls = select_matched_controls(
                input_dir=PathWithItems(input_dir),
                incidents=[incident],
                controls_per_insider=1,
            )

        self.assertEqual([(match.insider_id, match.control_id) for match in controls], [("INSIDER1", "CONTROL_A")])

    def test_incident_matching_excludes_future_only_controls(self):
        incident = Incident(
            scenario=1,
            details_file="r4.2-1-INSIDER1.csv",
            user_id="INSIDER1",
            start=datetime(2010, 1, 2, 9, 0, 0),
            end=datetime(2010, 1, 5, 18, 0, 0),
        )

        with TemporaryDirectory() as temp_dir:
            input_dir = Path(temp_dir)
            (input_dir / "logon.csv").write_text(
                "\n".join(
                    [
                        "id,date,user,pc,activity",
                        "{I-pre},01/01/2010 08:00:00,INSIDER1,PC-I,Logon",
                        "{A-pre},01/01/2010 08:00:00,CONTROL_A,PC-A,Logon",
                        "{Z-post},01/03/2010 08:00:00,CONTROL_Z,PC-Z,Logon",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            controls = select_matched_controls(input_dir, [incident], 2)

        self.assertEqual([(match.insider_id, match.control_id) for match in controls], [("INSIDER1", "CONTROL_A")])

    def test_incident_matching_does_not_reuse_controls_when_pool_is_short(self):
        incident = Incident(
            scenario=1,
            details_file="r4.2-1-INSIDER1.csv",
            user_id="INSIDER1",
            start=datetime(2010, 1, 2, 9, 0, 0),
            end=datetime(2010, 1, 5, 18, 0, 0),
        )

        with TemporaryDirectory() as temp_dir:
            input_dir = Path(temp_dir)
            (input_dir / "logon.csv").write_text(
                "\n".join(
                    [
                        "id,date,user,pc,activity",
                        "{I-pre},01/01/2010 08:00:00,INSIDER1,PC-I,Logon",
                        "{A-pre},01/01/2010 08:00:00,CONTROL_A,PC-A,Logon",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            controls = select_matched_controls(input_dir, [incident], 3)

        self.assertEqual([(match.insider_id, match.control_id) for match in controls], [("INSIDER1", "CONTROL_A")])

    def test_incident_matching_prioritizes_earliest_cutoff_when_controls_are_scarce(self):
        earlier_incident = Incident(
            scenario=1,
            details_file="r4.2-1-Z_INSIDER.csv",
            user_id="Z_INSIDER",
            start=datetime(2010, 1, 2, 9, 0, 0),
            end=datetime(2010, 1, 5, 18, 0, 0),
        )
        later_incident = Incident(
            scenario=2,
            details_file="r4.2-2-A_INSIDER.csv",
            user_id="A_INSIDER",
            start=datetime(2010, 1, 4, 9, 0, 0),
            end=datetime(2010, 1, 6, 18, 0, 0),
        )

        with TemporaryDirectory() as temp_dir:
            input_dir = Path(temp_dir)
            (input_dir / "logon.csv").write_text(
                "\n".join(
                    [
                        "id,date,user,pc,activity",
                        "{Z-pre},01/01/2010 08:00:00,Z_INSIDER,PC-Z,Logon",
                        "{A-pre},01/03/2010 08:00:00,A_INSIDER,PC-A,Logon",
                        "{C-pre},01/01/2010 08:00:00,CONTROL_ONLY,PC-C,Logon",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            controls = select_matched_controls(input_dir, [later_incident, earlier_incident], 1)

        self.assertEqual([(match.insider_id, match.control_id) for match in controls], [("Z_INSIDER", "CONTROL_ONLY")])

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

    def test_incident_aware_matching_excludes_activity_at_or_after_incident_start(self):
        incident = Incident(
            scenario=1,
            details_file="r4.2-1-INSIDER1.csv",
            user_id="INSIDER1",
            start=datetime(2010, 1, 2, 9, 0, 0),
            end=datetime(2010, 1, 5, 18, 0, 0),
        )
        later_incident = Incident(
            scenario=2,
            details_file="r4.2-2-INSIDER1.csv",
            user_id="INSIDER1",
            start=datetime(2010, 1, 4, 9, 0, 0),
            end=datetime(2010, 1, 6, 18, 0, 0),
        )

        with TemporaryDirectory() as temp_dir:
            input_dir = Path(temp_dir)
            (input_dir / "logon.csv").write_text(
                "\n".join(
                    [
                        "id,date,user,pc,activity",
                        "{I-pre},01/01/2010 08:00:00,INSIDER1,PC-I,Logon",
                        "{I-at},01/02/2010 09:00:00,INSIDER1,PC-CUTOFF,Logon",
                        "{I-post-1},01/03/2010 19:00:00,INSIDER1,PC-POST1,Logon",
                        "{I-post-2},01/03/2010 08:00:00,INSIDER1,PC-POST2,Logon",
                        "{A-pre},01/01/2010 08:00:00,CONTROL_A,PC-I,Logon",
                        "{B-pre-1},01/01/2010 08:00:00,CONTROL_B,PC-B1,Logon",
                        "{B-pre-2},01/01/2010 19:00:00,CONTROL_B,PC-B2,Logon",
                        "{B-at},01/02/2010 09:00:00,CONTROL_B,PC-B3,Logon",
                        "{B-post},01/03/2010 08:00:00,CONTROL_B,PC-B4,Logon",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            controls = select_matched_controls(input_dir, [later_incident, incident], 1)

            output_path = input_dir / "cohort.json"
            write_cohort_manifest(output_path, [later_incident, incident], controls)
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            leaked_profiles = build_activity_profiles(input_dir)

        self.assertEqual(len(controls), 1)
        match = controls[0]
        expected_vector = (1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0)
        leaked_full_history_vector = (3.0, 4.0, 0.25, 0.0, 0.0, 0.0, 4.0)
        self.assertEqual(leaked_profiles["INSIDER1"].vector, leaked_full_history_vector)
        self.assertEqual(leaked_profiles["CONTROL_B"].vector, leaked_full_history_vector)
        self.assertNotEqual(leaked_profiles["CONTROL_A"].vector, leaked_full_history_vector)
        self.assertEqual(match.control_id, "CONTROL_A")
        self.assertEqual(match.distance, 0.0)
        self.assertEqual(match.insider_vector, expected_vector)
        self.assertEqual(match.control_vector, expected_vector)
        self.assertNotEqual(match.insider_vector, leaked_full_history_vector)

        incident_features = payload["incidents"][0]["selection_features"]
        self.assertEqual(incident_features["active_day_count"], 1.0)
        self.assertEqual(incident_features["logon_count"], 1.0)
        self.assertEqual(incident_features["distinct_machine_count"], 1.0)
        self.assertEqual(
            incident_features["standardized_vector"],
            list(match.insider_standardized_vector),
        )
        self.assertEqual(
            [record["selection_features"] for record in payload["incidents"]],
            [incident_features, incident_features],
        )

        control_features = payload["controls"][0]["selection_features"]
        self.assertEqual(control_features["active_day_count"], 1.0)
        self.assertEqual(control_features["logon_count"], 1.0)
        self.assertEqual(control_features["distinct_machine_count"], 1.0)

    def test_incident_aware_matching_uses_earliest_cutoff_for_multiple_incidents(self):
        earlier_incident = Incident(
            scenario=1,
            details_file="r4.2-1-INSIDER1.csv",
            user_id="INSIDER1",
            start=datetime(2010, 1, 2, 9, 0, 0),
            end=datetime(2010, 1, 5, 18, 0, 0),
        )
        later_incident = Incident(
            scenario=2,
            details_file="r4.2-2-INSIDER1.csv",
            user_id="INSIDER1",
            start=datetime(2010, 1, 4, 9, 0, 0),
            end=datetime(2010, 1, 6, 18, 0, 0),
        )

        with TemporaryDirectory() as temp_dir:
            input_dir = Path(temp_dir)
            (input_dir / "logon.csv").write_text(
                "\n".join(
                    [
                        "id,date,user,pc,activity",
                        "{I-pre},01/01/2010 08:00:00,INSIDER1,PC-I,Logon",
                        "{I-cutoff},01/02/2010 09:00:00,INSIDER1,PC-CUTOFF,Logon",
                        "{I-post},01/03/2010 08:00:00,INSIDER1,PC-POST,Logon",
                        "{A-pre},01/01/2010 08:00:00,CONTROL_A,PC-A,Logon",
                        "{A-cutoff},01/02/2010 09:00:00,CONTROL_A,PC-CUTOFF,Logon",
                        "{A-post},01/03/2010 08:00:00,CONTROL_A,PC-POST,Logon",
                        "{B-pre},01/01/2010 08:00:00,CONTROL_B,PC-B,Logon",
                        "{B-post},01/03/2010 08:00:00,CONTROL_B,PC-POST,Logon",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            controls = select_matched_controls(input_dir, [later_incident, earlier_incident], 1)

        self.assertEqual([(match.insider_id, match.control_id) for match in controls], [("INSIDER1", "CONTROL_A")])
        self.assertEqual(controls[0].insider_vector, (1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0))
        self.assertEqual(controls[0].control_vector, (1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0))

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

    def test_manifest_requires_selection_features_for_every_incident_user(self):
        incidents = load_incidents(FIXTURES / "answers" / "insiders.csv")
        controls = select_matched_controls(self.fixture_profiles(), {"INSIDER1"}, 1)

        with TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "cohort.json"

            with self.assertRaisesRegex(
                ValueError,
                r"missing selection features for incident users: INSIDER2",
            ):
                write_cohort_manifest(output_path, incidents, controls)

    def test_extract_keeps_only_cohort_and_discards_content(self):
        with TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "stream.jsonl"
            result = extract_evaluation_stream(
                input_dir=FIXTURES,
                cohort={"INSIDER1", "CONTROL1"},
                output_path=output_path,
                run_size=2,
            )

            records = [
                json.loads(line)
                for line in output_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]

        self.assertTrue(records)
        self.assertTrue(all(record["user_id"] in {"INSIDER1", "CONTROL1"} for record in records))
        self.assertTrue(all("content" not in record for record in records))
        self.assertTrue(all("activity" in record or "action" in record for record in records))
        self.assertIn("http", {record["source"] for record in records})
        file_record = next(record for record in records if record["source"] == "file")
        self.assertEqual(file_record["extension"], ".doc")
        email_record = next(record for record in records if record["source"] == "email")
        self.assertEqual(email_record["sender"], "inside1@example.com")
        self.assertEqual(email_record["recipient_count"], len(email_record["recipients"]))
        self.assertEqual(email_record["size"], 100)
        self.assertEqual(email_record["attachments"], 0)
        self.assertNotIn("to", email_record)
        self.assertNotIn("cc", email_record)
        self.assertNotIn("bcc", email_record)
        self.assertNotIn("from", email_record)
        http_record = next(record for record in records if record["source"] == "http")
        self.assertEqual(http_record["domain"], "example.com")
        self.assertIn("cloud_signal", http_record)
        self.assertEqual(result.event_count, len(records))

    def test_external_merge_orders_by_event_time_then_event_id(self):
        with TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "stream.jsonl"
            extract_evaluation_stream(
                input_dir=FIXTURES,
                cohort={"INSIDER1", "CONTROL1"},
                output_path=output_path,
                run_size=2,
            )

            records = [
                json.loads(line)
                for line in output_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]

        ordering = [(record["event_ts"], record["event_id"]) for record in records]
        self.assertEqual(ordering, sorted(ordering))

    def test_extract_fails_fast_when_required_source_is_missing(self):
        with TemporaryDirectory() as temp_dir:
            input_dir = Path(temp_dir)
            (input_dir / "logon.csv").write_text(
                "\n".join(
                    [
                        "id,date,user,pc,activity",
                        "{L1},01/02/2010 07:30:00,INSIDER1,PC-1001,Logon",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(FileNotFoundError, r"device\.csv"):
                extract_evaluation_stream(
                    input_dir=input_dir,
                    cohort={"INSIDER1"},
                    output_path=input_dir / "stream.jsonl",
                    run_size=2,
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
