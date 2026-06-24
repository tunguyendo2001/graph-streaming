import unittest
from datetime import datetime, timezone

from event_model import Event, parse_cert_row


class EventModelTest(unittest.TestCase):
    def test_from_record_round_trips_aware_iso_datetime_as_utc_event_ts(self):
        event = Event.from_record(
            {
                "event_id": "http:{H1}",
                "source": "http",
                "kind": "HTTP",
                "event_time": "2010-08-12T14:54:16+02:00",
                "user_id": "BBS0039",
                "machine_id": "PC-9436",
                "properties": {"domain": "dailykeylogger.com"},
            }
        )

        self.assertEqual(event.event_time, datetime.fromisoformat("2010-08-12T14:54:16+02:00"))
        self.assertEqual(
            event.event_ts,
            int(datetime(2010, 8, 12, 12, 54, 16, tzinfo=timezone.utc).timestamp()),
        )
        self.assertEqual(Event.from_record(event.to_record()).event_ts, event.event_ts)

    def test_to_record_returns_a_defensive_copy(self):
        event = parse_cert_row(
            "email",
            {
                "id": "{E1}",
                "date": "08/13/2010 19:01:01",
                "user": "FAW0032",
                "pc": "PC-5866",
                "to": "a@dtaa.com;b@dtaa.com",
                "cc": "b@dtaa.com;c@outside.net",
                "bcc": "",
                "from": "victim@dtaa.com",
                "size": "18004",
                "attachments": "0",
                "content": "discard",
            },
        )

        record = event.to_record()
        record["properties"]["recipients"].append("z@outside.net")
        record["properties"]["recipient_count"] = 99

        self.assertEqual(
            event.properties["recipients"],
            ["a@dtaa.com", "b@dtaa.com", "c@outside.net"],
        )
        self.assertEqual(event.properties["recipient_count"], 3)

    def test_from_record_defensively_copies_input_record(self):
        record = {
            "event_id": "file:{F1}",
            "source": "file",
            "kind": "FILE_COPY",
            "event_time": "2010-08-12T14:54:16",
            "user_id": "BBS0039",
            "machine_id": "PC-9436",
            "properties": {
                "filename": "GGX5KL22.exe",
                "extension": ".exe",
                "tags": ["secret"],
            },
        }

        event = Event.from_record(record)
        record["properties"]["filename"] = "changed.exe"
        record["properties"]["tags"].append("leaked")

        self.assertEqual(
            event.properties,
            {"filename": "GGX5KL22.exe", "extension": ".exe", "tags": ["secret"]},
        )

    def test_event_properties_are_not_directly_mutable(self):
        event = parse_cert_row(
            "file",
            {
                "id": "{F1}",
                "date": "08/12/2010 14:54:16",
                "user": "BBS0039",
                "pc": "PC-9436",
                "filename": "GGX5KL22.exe",
                "content": "must be discarded",
            },
        )

        with self.assertRaises(TypeError):
            event.properties["filename"] = "changed.exe"

    def test_file_row_discards_content_and_normalizes_filename_extension(self):
        event = parse_cert_row(
            "file",
            {
                "id": "{F1}",
                "date": "08/12/2010 14:54:16",
                "user": "BBS0039",
                "pc": "PC-9436",
                "filename": "GGX5KL22.exe",
                "content": "must be discarded",
            },
        )

        self.assertEqual(event.event_id, "file:{F1}")
        self.assertEqual(event.kind, "FILE_COPY")
        self.assertEqual(event.user_id, "BBS0039")
        self.assertEqual(event.machine_id, "PC-9436")
        self.assertEqual(
            event.properties,
            {"filename": "GGX5KL22.exe", "extension": ".exe"},
        )
        self.assertNotIn("content", event.to_record())

    def test_email_row_normalizes_unique_recipients_and_counts_them(self):
        event = parse_cert_row(
            "email",
            {
                "id": "{E1}",
                "date": "08/13/2010 19:01:01",
                "user": "FAW0032",
                "pc": "PC-5866",
                "to": "a@dtaa.com;b@dtaa.com",
                "cc": "b@dtaa.com;c@outside.net",
                "bcc": "",
                "from": "victim@dtaa.com",
                "size": "18004",
                "attachments": "0",
                "content": "discard",
            },
        )

        self.assertEqual(event.kind, "EMAIL")
        self.assertEqual(
            event.properties["recipients"],
            ["a@dtaa.com", "b@dtaa.com", "c@outside.net"],
        )
        self.assertEqual(event.properties["recipient_count"], 3)

    def test_http_row_extracts_domain_and_keylogger_signal(self):
        event = parse_cert_row(
            "http",
            {
                "id": "{H1}",
                "date": "08/12/2010 13:42:15",
                "user": "BBS0039",
                "pc": "PC-9436",
                "url": "http://www.dailykeylogger.com/review.html",
                "content": "discard",
            },
        )

        self.assertEqual(event.properties["domain"], "dailykeylogger.com")
        self.assertTrue(event.properties["keylogger_signal"])
        self.assertEqual(event.event_time, datetime(2010, 8, 12, 13, 42, 15))


if __name__ == "__main__":
    unittest.main()
