import unittest

from cert_pipeline import (
    TARGET_USERS,
    build_cypher_payload,
    create_synthetic_events,
    normalize_file_events,
)


class CertPipelineTest(unittest.TestCase):
    def test_target_users_are_fixed_for_demo_scope(self):
        self.assertEqual(
            TARGET_USERS,
            [
                "JDE0001",
                "ACA0002",
                "BDP0003",
                "CFC0004",
                "EHB0005",
                "THIEF_U101",
                "SNOOP_U102",
            ],
        )

    def test_synthetic_events_create_theft_and_snoop_scenarios(self):
        events = create_synthetic_events("2010-01-15")

        thief_files = events[
            (events["user_id"] == "THIEF_U101")
            & (events["event_type"] == "FILE")
            & (events["file_action"] == "Copy")
        ]
        snoop_logons = events[
            (events["user_id"] == "SNOOP_U102")
            & (events["event_type"] == "LOGON")
        ]

        self.assertEqual(len(events), 38)
        self.assertEqual(len(thief_files), 30)
        self.assertTrue(thief_files["is_secret"].all())
        self.assertEqual(set(thief_files["machine_id"]), {"PC-9999"})
        self.assertEqual(len(snoop_logons), 6)
        self.assertEqual(set(snoop_logons["machine_dept"]), {"Finance"})
        self.assertEqual(
            set(snoop_logons["machine_id"]),
            {"PC-FIN-01", "PC-FIN-02", "PC-FIN-03", "PC-FIN-04", "PC-FIN-05", "PC-FIN-06"},
        )

    def test_normalize_file_events_defaults_to_open_and_non_secret(self):
        rows = [
            {
                "date": "01/02/2010 07:23:14",
                "user": "JDE0001",
                "pc": "PC-1234",
                "filename": "REPORT.doc",
            }
        ]

        events = normalize_file_events(rows)

        self.assertEqual(events.iloc[0]["event_type"], "FILE")
        self.assertEqual(events.iloc[0]["file_action"], "Open")
        self.assertFalse(bool(events.iloc[0]["is_secret"]))

    def test_build_cypher_payload_selects_query_by_event_type(self):
        logon_query, logon_params = build_cypher_payload(
            {
                "event_type": "LOGON",
                "timestamp": "2010-01-15 02:00:00",
                "user_id": "THIEF_U101",
                "machine_id": "PC-9999",
                "machine_dept": "Unknown",
            }
        )
        file_query, file_params = build_cypher_payload(
            {
                "event_type": "FILE",
                "timestamp": "2010-01-15 02:00:10",
                "user_id": "THIEF_U101",
                "file_id": "Secret_Doc_1.pdf",
                "file_action": "Copy",
                "is_secret": True,
            }
        )

        self.assertIn("LOGON", logon_query)
        self.assertEqual(logon_params["machine_id"], "PC-9999")
        self.assertIn("FILE_ACTION", file_query)
        self.assertTrue(file_params["is_secret"])


if __name__ == "__main__":
    unittest.main()
