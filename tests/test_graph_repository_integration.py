import os
import unittest
from datetime import datetime
from neo4j import GraphDatabase

from event_model import Event
from graph_repository import GraphRepository

class GraphRepositoryIntegrationTest(unittest.TestCase):
    def setUp(self):
        uri = os.getenv("MEMGRAPH_URI", "bolt://localhost:7687")
        try:
            self.driver = GraphDatabase.driver(uri, auth=("", ""))
            self.repo = GraphRepository(self.driver)
            self.repo.reset()
        except Exception as e:
            self.skipTest(f"Memgraph not available at {uri}: {e}")

    def tearDown(self):
        if hasattr(self, 'driver'):
            self.driver.close()

    def test_connect_filecopy_disconnect(self):
        t1 = datetime(2010, 1, 1, 8, 0, 0)
        e1 = Event("e1", "device", "DEVICE_CONNECT", t1, "U1", "M1", {"activity": "CONNECT"})
        self.repo.write_event(e1, t1)

        t2 = datetime(2010, 1, 1, 8, 5, 0)
        e2 = Event("e2", "file", "FILE_COPY", t2, "U1", "M1", {"filename": "test.txt", "extension": ".txt"})
        self.repo.write_event(e2, t2)

        t3 = datetime(2010, 1, 1, 8, 10, 0)
        e3 = Event("e3", "device", "DEVICE_DISCONNECT", t3, "U1", "M1", {"activity": "DISCONNECT"})
        self.repo.write_event(e3, t3)

        with self.driver.session() as session:
            res = session.run("MATCH (s:UsbSession) RETURN s.closed_at AS closed")
            records = list(res)
            self.assertEqual(len(records), 1)
            self.assertIsNotNone(records[0]["closed"])

    def test_alert_query_returns_path(self):
        with self.driver.session() as session:
            # Fake an alert 
            session.run("MERGE (a:Alert {id: 'A1'}) MERGE (u:User {id: 'U1'}) MERGE (a)-[:ABOUT]->(u)")
            res = session.run("MATCH p = (a:Alert)-[:ABOUT]->(u:User) RETURN p")
            records = list(res)
            self.assertEqual(len(records), 1)

if __name__ == "__main__":
    unittest.main()

