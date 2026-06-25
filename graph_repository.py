import datetime
from typing import Any

from neo4j import Driver

from event_model import Event


class WriteResult:
    def __init__(self, is_new: bool):
        self.is_new = is_new


class AlertRecord:
    def __init__(self, alert_id: str, detector: str, score: float, threshold: float, trigger_event_id: str,
                 event_time: datetime.datetime, components: dict[str, float], user_ids: tuple[str, ...],
                 machine_ids: tuple[str, ...], evidence_event_ids: tuple[str, ...], evidence_start_ts: int,
                 evidence_end_ts: int):
        self.alert_id = alert_id
        self.detector = detector
        self.score = score
        self.threshold = threshold
        self.trigger_event_id = trigger_event_id
        self.event_time = event_time
        self.components = components
        self.user_ids = user_ids
        self.machine_ids = machine_ids
        self.evidence_event_ids = evidence_event_ids
        self.evidence_start_ts = evidence_start_ts
        self.evidence_end_ts = evidence_end_ts


class GraphRepository:
    def __init__(self, driver: Driver, database: str | None = None):
        self._driver = driver
        self._database = database

    def reset(self) -> None:
        with self._driver.session(database=self._database) as session:
            session.run("MATCH (n) DETACH DELETE n")

    def write_event(self, event: Event, ingest_time: datetime.datetime) -> WriteResult:
        with self._driver.session(database=self._database) as session:
            # A simplified transactional block according to the requirements
            query = """
            MERGE (u:User {id: $user_id})
            MERGE (m:Machine {id: $machine_id})
            MERGE (e:Event {id: $event_id})
            ON CREATE SET e.is_new = true
            SET e.kind = $kind, e.event_ts = $event_ts, e.ingest_time = $ingest_time,
                e.source = $source
            MERGE (u)-[:ACTED]->(e)
            MERGE (e)-[:ON_MACHINE]->(m)
            
            // Increment USED_MACHINE
            MERGE (u)-[used:USED_MACHINE]->(m)
            ON CREATE SET used.count = 1, used.first_seen = $event_ts, used.last_seen = $event_ts
            ON MATCH SET used.count = used.count + 1, used.last_seen = $event_ts
            """
            
            if event.kind == "FILE_COPY":
                query += """
                SET e:FileCopyEvent, e.filename = $properties.filename, e.extension = $properties.extension
                """
            elif event.kind in ("DEVICE_CONNECT", "DEVICE_DISCONNECT"):
                query += """
                SET e:DeviceEvent, e.activity = $properties.activity
                """
                if event.kind == "DEVICE_CONNECT":
                    query += """
                    MERGE (sess:UsbSession {id: $user_id + '_' + $machine_id + '_' + $event_id})
                    ON CREATE SET sess.opened_at = $event_ts
                    MERGE (e)-[:BOUNDARY_OF]->(sess)
                    """
                else:
                    query += """
                    MATCH (e)-[:ON_MACHINE]->(m)<-[:ON_MACHINE]-(c:Event {kind: 'DEVICE_CONNECT'})<-[:ACTED]-(u)
                    WITH c ORDER BY c.event_ts DESC LIMIT 1
                    MATCH (c)-[:BOUNDARY_OF]->(sess:UsbSession)
                    WHERE sess.closed_at IS NULL
                    SET sess.closed_at = $event_ts
                    MERGE (e)-[:BOUNDARY_OF]->(sess)
                    """
            
            res = session.run(query, user_id=event.user_id, machine_id=event.machine_id, 
                              event_id=event.event_id, kind=event.kind, event_ts=event.event_ts,
                              ingest_time=ingest_time.isoformat(), source=event.source,
                              properties=event.properties)
            summary = res.consume()
            # If nodes created > 0, it was new. Actually checking ON CREATE SET e.is_new might be needed
            # but we can assume checking counters for nodes_created is a good proxy.
            is_new = summary.counters.nodes_created > 0

        return WriteResult(is_new=is_new)

    def fetch_uc1_context(self, user_id: str, trigger_ts: int) -> dict:
        return {}

    def fetch_uc2_context(self, user_id: str, machine_id: str, trigger_ts: int) -> dict:
        return {}

    def upsert_alert(self, alert: AlertRecord) -> None:
        pass

    def prune_events(self, before_ts: int) -> int:
        return 0
