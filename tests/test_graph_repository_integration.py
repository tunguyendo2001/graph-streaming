import os
import unittest
from datetime import datetime, timezone
from pathlib import Path

from event_model import Event


MEMGRAPH_URI = os.getenv("MEMGRAPH_URI")
MEMGRAPH_USER = os.getenv("MEMGRAPH_USER")
MEMGRAPH_PASSWORD = os.getenv("MEMGRAPH_PASSWORD")


class AlertVisualizationQueryTest(unittest.TestCase):
    def test_alert_query_file_contains_supported_views(self):
        query = Path("queries/alerts.cypher").read_text(encoding="utf-8")

        self.assertIn("MATCH p = (a:Alert)-[:ABOUT|EVIDENCE|INVOLVES*1..3]-(entity)", query)
        self.assertIn("a:Alert {id: $alert_id}", query)
        self.assertIn('detector: "uc1_exfiltration_motif"', query)
        self.assertIn('detector: "uc2_credential_pivot_motif"', query)
        self.assertIn("a.components AS components", query)
        self.assertIn("UNWIND a.evidence_event_ids", query)


@unittest.skipUnless(MEMGRAPH_URI, "MEMGRAPH_URI is not set; skipping Memgraph integration tests")
class GraphRepositoryIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from neo4j import GraphDatabase

        auth = None
        if MEMGRAPH_USER or MEMGRAPH_PASSWORD:
            auth = (MEMGRAPH_USER or "", MEMGRAPH_PASSWORD or "")
        cls.driver = GraphDatabase.driver(MEMGRAPH_URI, auth=auth)

    @classmethod
    def tearDownClass(cls):
        cls.driver.close()

    def setUp(self):
        from graph_repository import GraphRepository

        self.repo = GraphRepository(self.driver)
        self.repo.reset()

    def test_connect_filecopy_disconnect_creates_one_closed_usb_session_and_one_filecopy_attachment(self):
        connect = Event(
            event_id="device:{C1}",
            source="device",
            kind="DEVICE_CONNECT",
            event_time=datetime(2010, 1, 2, 9, 0, 0, tzinfo=timezone.utc),
            user_id="INSIDER1",
            machine_id="PC-1001",
            properties={"activity": "CONNECT"},
        )
        file_copy = Event(
            event_id="file:{F1}",
            source="file",
            kind="FILE_COPY",
            event_time=datetime(2010, 1, 2, 9, 5, 0, tzinfo=timezone.utc),
            user_id="INSIDER1",
            machine_id="PC-1001",
            properties={"filename": "evidence.zip", "extension": ".zip"},
        )
        disconnect = Event(
            event_id="device:{D1}",
            source="device",
            kind="DEVICE_DISCONNECT",
            event_time=datetime(2010, 1, 2, 9, 10, 0, tzinfo=timezone.utc),
            user_id="INSIDER1",
            machine_id="PC-1001",
            properties={"activity": "DISCONNECT"},
        )

        self.repo.write_event(connect, datetime(2010, 1, 2, 9, 0, 1, tzinfo=timezone.utc))
        self.repo.write_event(file_copy, datetime(2010, 1, 2, 9, 5, 1, tzinfo=timezone.utc))
        self.repo.write_event(disconnect, datetime(2010, 1, 2, 9, 10, 1, tzinfo=timezone.utc))

        with self.driver.session(database=None) as session:
            session_count = session.execute_read(
                lambda tx: tx.run("MATCH (s:UsbSession) RETURN count(s) AS session_count").single()["session_count"]
            )
            attachment_count = session.execute_read(
                lambda tx: tx.run(
                    "MATCH (:Event)-[:IN_USB_SESSION]->(:UsbSession) RETURN count(*) AS attachment_count"
                ).single()["attachment_count"]
            )
            closed_count = session.execute_read(
                lambda tx: tx.run(
                    "MATCH (s:UsbSession) WHERE s.closed_at IS NOT NULL RETURN count(s) AS closed_count"
                ).single()["closed_count"]
            )

        self.assertEqual(session_count, 1)
        self.assertEqual(attachment_count, 1)
        self.assertEqual(closed_count, 1)

    def test_duplicate_filecopy_creates_only_one_event_node(self):
        event = Event(
            event_id="file:{F2}",
            source="file",
            kind="FILE_COPY",
            event_time=datetime(2010, 1, 2, 10, 0, 0, tzinfo=timezone.utc),
            user_id="INSIDER1",
            machine_id="PC-1001",
            properties={"filename": "duplicate.zip", "extension": ".zip"},
        )

        self.repo.write_event(event, datetime(2010, 1, 2, 10, 0, 1, tzinfo=timezone.utc))
        self.repo.write_event(event, datetime(2010, 1, 2, 10, 0, 2, tzinfo=timezone.utc))

        with self.driver.session(database=None) as session:
            event_count = session.execute_read(
                lambda tx: tx.run(
                    """
                    MATCH (e:Event {id: $event_id})
                    RETURN count(e) AS event_count
                    """,
                    event_id=event.event_id,
                ).single()["event_count"]
            )

        self.assertEqual(event_count, 1)


if __name__ == "__main__":
    unittest.main()
