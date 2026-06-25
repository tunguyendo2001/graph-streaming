import unittest
from datetime import datetime

from event_model import Event, parse_cert_row


class EventModelTest(unittest.TestCase):
    def test_file_row_is_a_real_removable_media_copy(self):
        event = parse_cert_row(
            "file",
            {
                "id": "{F1}",
                "date": "08/12/2010 14:54:16",
                "user": "BBS0039",
                "pc": "PC-9436",
                "filename": "GGX5KL22.exe",
                "content": "must not be retained",
            },
        )

        self.assertEqual(event.event_id, "file:{F1}")
        self.assertEqual(event.kind, "FILE_COPY")
        self.assertEqual(event.user_id, "BBS0039")
        self.assertEqual(event.machine_id, "PC-9436")
        self.assertEqual(event.properties, {"filename": "GGX5KL22.exe", "extension": ".exe"})
        self.assertNotIn("content", event.to_record())

    def test_email_row_flattens_all_unique_recipients(self):
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
        self.assertEqual(event.properties["recipients"], ["a@dtaa.com", "b@dtaa.com", "c@outside.net"])
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
