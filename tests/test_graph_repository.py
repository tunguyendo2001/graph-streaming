import unittest
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from event_model import Event


@dataclass
class RecordedQuery:
    query: str
    params: dict


class FakeResult:
    def __init__(self, rows=None):
        self.rows = list(rows or [])

    def single(self):
        return self.rows[0] if self.rows else None

    def data(self):
        return list(self.rows)


class FakeTx:
    def __init__(self, driver):
        self._driver = driver

    def run(self, query, **params):
        self._driver.queries.append(RecordedQuery(query=query, params=params))
        if self._driver.results:
            return self._driver.results.popleft()
        return FakeResult([{}])


class FakeSession:
    def __init__(self, driver):
        self._driver = driver

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute_write(self, callback):
        return callback(FakeTx(self._driver))

    def execute_read(self, callback):
        return callback(FakeTx(self._driver))


class RecordingDriver:
    def __init__(self, results=None):
        self.results = deque(results or [])
        self.queries = []
        self.session_databases = []

    def session(self, database=None):
        self.session_databases.append(database)
        return FakeSession(self)


def make_event(kind, event_id="cert:{E1}", source="file", **properties):
    return Event(
        event_id=event_id,
        source=source,
        kind=kind,
        event_time=datetime(2010, 1, 2, 9, 0, 0, tzinfo=timezone.utc),
        user_id="INSIDER1",
        machine_id="PC-1001",
        properties=properties,
    )


class GraphRepositorySchemaTest(unittest.TestCase):
    def test_schema_contains_only_the_expected_indexes(self):
        schema_path = Path(__file__).resolve().parents[1] / "init_schema.cypher"
        lines = [line.strip() for line in schema_path.read_text(encoding="utf-8").splitlines() if line.strip()]

        self.assertEqual(
            lines,
            [
                "CREATE INDEX ON :User(id);",
                "CREATE INDEX ON :Machine(id);",
                "CREATE INDEX ON :Event(id);",
                "CREATE INDEX ON :Event(event_ts);",
                "CREATE INDEX ON :Domain(name);",
                "CREATE INDEX ON :EmailAddress(address);",
                "CREATE INDEX ON :ActivityWindow(id);",
                "CREATE INDEX ON :UsbSession(id);",
                "CREATE INDEX ON :Alert(id);",
                "CREATE INDEX ON :Alert(detector);",
            ],
        )


class GraphRepositoryTest(unittest.TestCase):
    def make_repo(self, results=None, database=None):
        from graph_repository import GraphRepository

        driver = RecordingDriver(results=results)
        return GraphRepository(driver, database=database), driver

    def test_write_event_merges_event_by_id_and_is_idempotent_at_query_level(self):
        from graph_repository import WriteResult

        repo, driver = self.make_repo(
            results=[
                FakeResult([{"created": True}]),
                FakeResult([{}]),
                FakeResult([{"created": False}]),
            ]
        )
        event = make_event("HTTP", url="http://example.com")

        first = repo.write_event(event, datetime(2010, 1, 2, 9, 1, 0, tzinfo=timezone.utc))
        second = repo.write_event(event, datetime(2010, 1, 2, 9, 2, 0, tzinfo=timezone.utc))

        self.assertEqual(first, WriteResult(event_id=event.event_id, created=True))
        self.assertEqual(second, WriteResult(event_id=event.event_id, created=False))
        event_queries = [record.query for record in driver.queries if "MERGE (e:Event {id: $event_id})" in record.query]
        self.assertGreaterEqual(len(event_queries), 2)
        self.assertTrue(all("CREATE (e:Event" not in query for query in event_queries))

    def test_write_event_parameters_include_event_ts_and_ingest_time(self):
        repo, driver = self.make_repo(results=[FakeResult([{"created": True}]), FakeResult([{}])])
        event = make_event("LOGON", source="logon", activity="LOGON")
        ingest_time = datetime(2010, 1, 2, 9, 3, 0, tzinfo=timezone.utc)

        repo.write_event(event, ingest_time)

        params = driver.queries[0].params
        query = driver.queries[0].query
        self.assertEqual(params["event_ts"], event.event_ts)
        self.assertEqual(params["ingest_time"], ingest_time)
        self.assertEqual(params["event_id"], event.event_id)
        self.assertEqual(params["kind"], event.kind)
        self.assertIn("e.user_id = $user_id", query)
        self.assertIn("e.machine_id = $machine_id", query)

    def test_file_copy_preserves_user_and_machine_relationships(self):
        repo, driver = self.make_repo(results=[FakeResult([{"created": True}]), FakeResult([{}])])
        event = make_event("FILE_COPY", source="file", filename="report.doc")

        repo.write_event(event, datetime(2010, 1, 2, 9, 4, 0, tzinfo=timezone.utc))

        queries = [record.query for record in driver.queries]
        self.assertTrue(any("MERGE (u)-[:ACTED]->(e)" in query for query in queries))
        self.assertTrue(any("MERGE (e)-[:ON_MACHINE]->(m)" in query for query in queries))
        self.assertTrue(any("IN_USB_SESSION" in query for query in queries))

    def test_device_connect_opens_usb_session_keyed_by_user_machine_and_event(self):
        repo, driver = self.make_repo(results=[FakeResult([{"created": True}]), FakeResult([{}])])
        event = make_event("DEVICE_CONNECT", source="device", activity="CONNECT")

        repo.write_event(event, datetime(2010, 1, 2, 9, 5, 0, tzinfo=timezone.utc))

        query_text = "\n".join(record.query for record in driver.queries)
        self.assertIn("UsbSession", query_text)
        self.assertIn("BOUNDARY_OF", query_text)
        usb_params = next(record.params for record in driver.queries if "usb_session_id" in record.params)
        self.assertIn("usb_session_id", usb_params)
        self.assertEqual(
            usb_params["usb_session_id"],
            f"{event.user_id}|{event.machine_id}|{event.event_id}",
        )

    def test_device_disconnect_closes_latest_open_session_for_same_user_and_machine(self):
        repo, driver = self.make_repo(results=[FakeResult([{"created": True}]), FakeResult([{}])])
        event = make_event("DEVICE_DISCONNECT", source="device", activity="DISCONNECT")

        repo.write_event(event, datetime(2010, 1, 2, 9, 6, 0, tzinfo=timezone.utc))

        query_text = "\n".join(record.query for record in driver.queries)
        self.assertIn("closed_at", query_text)
        self.assertIn("ORDER BY session.opened_at DESC", query_text)
        self.assertIn("LIMIT 1", query_text)

    def test_file_copy_attaches_to_latest_open_usb_session_or_creates_inferred_session(self):
        repo, driver = self.make_repo(results=[FakeResult([{"created": True}]), FakeResult([{}])])
        event = make_event("FILE_COPY", source="file", filename="evidence.zip")

        repo.write_event(event, datetime(2010, 1, 2, 9, 7, 0, tzinfo=timezone.utc))

        query_text = "\n".join(record.query for record in driver.queries)
        self.assertIn("MATCH (session:UsbSession)", query_text)
        self.assertIn("inferred_usb_session_id", query_text)
        self.assertIn("MERGE (session:UsbSession", query_text)
        self.assertIn("IN_USB_SESSION", query_text)

    def test_email_creates_email_address_nodes_and_emailed_aggregate_edges(self):
        repo, driver = self.make_repo(results=[FakeResult([{"created": True}]), FakeResult([{}])])
        event = make_event(
            "EMAIL",
            source="email",
            sender="victim@example.com",
            recipients=["a@dtaa.com", "b@dtaa.com"],
            recipient_count=2,
            size=1024,
            attachments=1,
        )

        repo.write_event(event, datetime(2010, 1, 2, 9, 8, 0, tzinfo=timezone.utc))

        query_text = "\n".join(record.query for record in driver.queries)
        self.assertIn("EmailAddress", query_text)
        self.assertIn("EMAILED", query_text)
        self.assertIn("SENT_TO", query_text)

    def test_reset_deletes_the_graph(self):
        repo, driver = self.make_repo(results=[FakeResult([{}])])

        repo.reset()

        self.assertIn("DETACH DELETE", driver.queries[0].query)

    def test_prune_events_deletes_old_events_by_event_ts(self):
        repo, driver = self.make_repo(
            results=[
                FakeResult([{"deleted_count": 4}]),
                FakeResult([{}]),
            ]
        )

        deleted = repo.prune_events(before_ts=1234567890)

        self.assertEqual(deleted, 4)
        self.assertIn("event_ts < $before_ts", driver.queries[0].query)
        self.assertIn("DETACH DELETE", driver.queries[1].query)

    def test_context_queries_use_expected_parameters(self):
        repo, driver = self.make_repo(
            results=[
                FakeResult([{"user_id": "INSIDER1"}]),
                FakeResult([{"user_id": "INSIDER1", "machine_id": "PC-1001"}]),
            ]
        )

        repo.fetch_uc1_context("INSIDER1", 1_600_000_000)
        repo.fetch_uc2_context("INSIDER1", "PC-1001", 1_600_000_000)

        uc1 = driver.queries[0]
        uc2 = driver.queries[1]
        self.assertEqual(uc1.params["user_id"], "INSIDER1")
        self.assertEqual(uc1.params["trigger_ts"], 1_600_000_000)
        self.assertIn("history_start_ts", uc1.params)
        self.assertIn("motif_start_ts", uc1.params)
        self.assertIn("domain: history_event.domain", uc1.query)
        self.assertIn("filename: candidate_event.filename", uc1.query)
        self.assertIn("activity: candidate_event.activity", uc1.query)
        self.assertIn("recipients: candidate_event.recipients", uc1.query)
        self.assertEqual(uc2.params["user_id"], "INSIDER1")
        self.assertEqual(uc2.params["machine_id"], "PC-1001")
        self.assertEqual(uc2.params["trigger_ts"], 1_600_000_000)
        self.assertIn("history_start_ts", uc2.params)
        self.assertIn("window_start_ts", uc2.params)
        self.assertIn("window_events", uc2.query)
        self.assertIn("machine_use", uc2.query)
        self.assertIn("stage_events", uc2.query)
        self.assertIn("attacker_user_id", uc2.query)
        self.assertIn("owner_confidence", uc2.query)
        self.assertIn("user_machine_probability", uc2.query)
        self.assertIn("attacker.id <> u.id", uc2.query)
        self.assertIn("candidate_event.event_ts >= $window_start_ts", uc2.query)
        self.assertIn("emailed.first_seen < $trigger_ts", uc2.query)
        self.assertIn("recipients: stage_event.recipients", uc2.query)

    def test_upsert_alert_merges_alert_with_components_and_evidence_metadata(self):
        from graph_repository import AlertRecord

        repo, driver = self.make_repo(results=[FakeResult([{}])])
        alert = AlertRecord(
            alert_id="alert-1",
            detector="UC1",
            score=0.91,
            threshold=0.7,
            trigger_event_id="file:{E1}",
            event_time=datetime(2010, 1, 2, 9, 9, 0, tzinfo=timezone.utc),
            components={"A": 0.2, "U": 0.3, "F": 0.4, "D": 0.1, "C1": 0.8},
            user_ids=("INSIDER1",),
            machine_ids=("PC-1001",),
            evidence_event_ids=("file:{E1}", "http:{H1}"),
            evidence_start_ts=1_234_567_890,
            evidence_end_ts=1_234_567_999,
        )

        repo.upsert_alert(alert)

        query_text = driver.queries[0].query
        self.assertIn("MERGE (alert:Alert {id: $alert_id})", query_text)
        self.assertIn("components", query_text)
        self.assertIn("evidence_event_ids", query_text)
        self.assertIn("ABOUT", query_text)
        self.assertIn("EVIDENCE", query_text)
        self.assertIn("INVOLVES", query_text)


if __name__ == "__main__":
    unittest.main()
