from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlparse
from typing import Any

from event_model import Event


@dataclass(frozen=True)
class WriteResult:
    event_id: str
    created: bool


@dataclass(frozen=True)
class AlertRecord:
    alert_id: str
    detector: str
    score: float
    threshold: float
    trigger_event_id: str
    event_time: datetime
    components: dict[str, float]
    user_ids: tuple[str, ...]
    machine_ids: tuple[str, ...]
    evidence_event_ids: tuple[str, ...]
    evidence_start_ts: int
    evidence_end_ts: int


_UPSERT_EVENT_QUERY = """
MERGE (u:User {id: $user_id})
MERGE (m:Machine {id: $machine_id})
MERGE (e:Event {id: $event_id})
ON CREATE SET e._created = true
ON MATCH SET e._created = false
SET e.source = $source,
    e.kind = $kind,
    e.user_id = $user_id,
    e.machine_id = $machine_id,
    e.event_time = $event_time,
    e.event_ts = $event_ts,
    e.ingest_time = $ingest_time
SET e += $properties
MERGE (u)-[:ACTED]->(e)
MERGE (e)-[:ON_MACHINE]->(m)
WITH e, u, m, coalesce(e._created, false) AS created
REMOVE e._created
RETURN created
"""

_USED_MACHINE_QUERY = """
MERGE (u:User {id: $user_id})
MERGE (m:Machine {id: $machine_id})
MERGE (u)-[used:USED_MACHINE]->(m)
SET used.count = coalesce(used.count, 0) + 1,
    used.first_seen = CASE
        WHEN used.first_seen IS NULL OR $event_ts < used.first_seen THEN $event_ts
        ELSE used.first_seen
    END,
    used.last_seen = CASE
        WHEN used.last_seen IS NULL OR $event_ts > used.last_seen THEN $event_ts
        ELSE used.last_seen
    END
"""

_OPEN_ACTIVITY_WINDOW_QUERY = """
MERGE (w:ActivityWindow {id: $activity_window_id})
SET w.user_id = $user_id,
    w.machine_id = $machine_id,
    w.opened_at = $event_ts,
    w.closed_at = NULL,
    w.inferred = false
WITH w
MATCH (e:Event {id: $event_id})
MERGE (e)-[:IN_ACTIVITY_WINDOW]->(w)
"""

_CLOSE_ACTIVITY_WINDOW_QUERY = """
MATCH (w:ActivityWindow)
WHERE w.user_id = $user_id
  AND w.machine_id = $machine_id
  AND w.closed_at IS NULL
WITH w
ORDER BY w.opened_at DESC
LIMIT 1
SET w.closed_at = $event_ts
WITH w
MATCH (e:Event {id: $event_id})
MERGE (e)-[:IN_ACTIVITY_WINDOW]->(w)
RETURN w.id AS activity_window_id
"""

_OPEN_USB_SESSION_QUERY = """
MERGE (session:UsbSession {id: $usb_session_id})
SET session.user_id = $user_id,
    session.machine_id = $machine_id,
    session.connect_event_id = $event_id,
    session.opened_at = $event_ts,
    session.closed_at = NULL,
    session.inferred = false
WITH session
MATCH (e:Event {id: $event_id})
MERGE (e)-[:BOUNDARY_OF]->(session)
RETURN session.id AS session_id
"""

_CLOSE_USB_SESSION_QUERY = """
MATCH (session:UsbSession)
WHERE session.user_id = $user_id
  AND session.machine_id = $machine_id
  AND session.closed_at IS NULL
WITH session
ORDER BY session.opened_at DESC
LIMIT 1
SET session.closed_at = $event_ts
WITH session
MATCH (e:Event {id: $event_id})
MERGE (e)-[:BOUNDARY_OF]->(session)
RETURN session.id AS session_id
"""

_ATTACH_USB_SESSION_QUERY = """
MATCH (session:UsbSession)
WHERE session.user_id = $user_id
  AND session.machine_id = $machine_id
  AND session.closed_at IS NULL
WITH session
ORDER BY session.opened_at DESC
LIMIT 1
WITH session
MATCH (e:Event {id: $event_id})
MERGE (e)-[:IN_USB_SESSION]->(session)
RETURN session.id AS session_id
"""

_CREATE_INFERRED_USB_SESSION_QUERY = """
MERGE (session:UsbSession {id: $inferred_usb_session_id})
SET session.user_id = $user_id,
    session.machine_id = $machine_id,
    session.opened_at = $event_ts,
    session.closed_at = $event_ts,
    session.inferred = true
WITH session
MATCH (e:Event {id: $event_id})
MERGE (e)-[:IN_USB_SESSION]->(session)
RETURN session.id AS session_id
"""

_VISIT_DOMAIN_QUERY = """
MERGE (d:Domain {name: $domain})
WITH d
MATCH (u:User {id: $user_id})
MERGE (u)-[visited:VISITED_DOMAIN]->(d)
SET visited.count = coalesce(visited.count, 0) + 1,
    visited.first_seen = CASE
        WHEN visited.first_seen IS NULL OR $event_ts < visited.first_seen THEN $event_ts
        ELSE visited.first_seen
    END,
    visited.last_seen = CASE
        WHEN visited.last_seen IS NULL OR $event_ts > visited.last_seen THEN $event_ts
        ELSE visited.last_seen
    END
WITH d
MATCH (e:Event {id: $event_id})
MERGE (e)-[:VISITED]->(d)
RETURN d.name AS domain_name
"""

_EMAIL_QUERY = """
WITH $recipients AS recipients
UNWIND recipients AS recipient
MERGE (addr:EmailAddress {address: recipient})
WITH addr, recipient
MATCH (u:User {id: $user_id})
MERGE (u)-[emailed:EMAILED]->(addr)
SET emailed.count = coalesce(emailed.count, 0) + 1,
    emailed.first_seen = CASE
        WHEN emailed.first_seen IS NULL OR $event_ts < emailed.first_seen THEN $event_ts
        ELSE emailed.first_seen
    END,
    emailed.last_seen = CASE
        WHEN emailed.last_seen IS NULL OR $event_ts > emailed.last_seen THEN $event_ts
        ELSE emailed.last_seen
    END
WITH addr
MATCH (e:Event {id: $event_id})
MERGE (e)-[:SENT_TO]->(addr)
RETURN collect(addr.address) AS email_addresses
"""

_RESET_QUERY = """
MATCH (n)
DETACH DELETE n
"""

_PRUNE_COUNT_QUERY = """
MATCH (e:Event)
WHERE e.event_ts < $before_ts
RETURN count(e) AS deleted_count
"""

_PRUNE_DELETE_QUERY = """
MATCH (e:Event)
WHERE e.event_ts < $before_ts
DETACH DELETE e
"""

_UC1_CONTEXT_QUERY = """
MATCH (u:User {id: $user_id})

CALL {
  WITH u
  MATCH (history_event:Event)
  WHERE history_event.event_ts >= $history_start_ts
    AND history_event.event_ts < $trigger_ts
    AND history_event.user_id = u.id
  WITH collect({
      event_id: history_event.id,
      source: history_event.source,
      kind: history_event.kind,
      user_id: history_event.user_id,
      event_ts: history_event.event_ts,
      machine_id: history_event.machine_id,
      activity: history_event.activity,
      filename: history_event.filename,
      extension: history_event.extension,
      domain: history_event.domain,
      url: history_event.url,
      keylogger_signal: history_event.keylogger_signal,
      job_signal: history_event.job_signal,
      leak_signal: history_event.leak_signal,
      cloud_signal: history_event.cloud_signal,
      recipient_count: history_event.recipient_count,
      recipients: history_event.recipients,
      size: history_event.size,
      attachments: history_event.attachments
  }) AS history_events
  RETURN history_events
}

CALL {
  WITH u
  MATCH (candidate_event:Event)
  WHERE candidate_event.event_ts >= $motif_start_ts
    AND candidate_event.event_ts <= $trigger_ts
    AND candidate_event.user_id = u.id
  WITH collect({
      event_id: candidate_event.id,
      source: candidate_event.source,
      kind: candidate_event.kind,
      user_id: candidate_event.user_id,
      event_ts: candidate_event.event_ts,
      machine_id: candidate_event.machine_id,
      activity: candidate_event.activity,
      filename: candidate_event.filename,
      extension: candidate_event.extension,
      domain: candidate_event.domain,
      url: candidate_event.url,
      keylogger_signal: candidate_event.keylogger_signal,
      job_signal: candidate_event.job_signal,
      leak_signal: candidate_event.leak_signal,
      cloud_signal: candidate_event.cloud_signal,
      recipient_count: candidate_event.recipient_count,
      recipients: candidate_event.recipients,
      size: candidate_event.size,
      attachments: candidate_event.attachments
  }) AS candidate_events
  RETURN candidate_events
}

RETURN {
    user_id: u.id,
    history_start_ts: $history_start_ts,
    motif_start_ts: $motif_start_ts,
    trigger_ts: $trigger_ts,
    history_events: history_events,
    candidate_events: candidate_events
} AS context
"""

_UC2_CONTEXT_QUERY = """
MATCH (u:User {id: $user_id})
OPTIONAL MATCH (trigger_machine:Machine {id: $machine_id})
WITH u, trigger_machine

CALL {
  WITH u
  MATCH (history_event:Event)
  WHERE history_event.event_ts >= $history_start_ts
    AND history_event.event_ts < $trigger_ts
    AND history_event.user_id = u.id
  WITH collect({
      event_id: history_event.id,
      source: history_event.source,
      kind: history_event.kind,
      user_id: history_event.user_id,
      event_ts: history_event.event_ts,
      machine_id: history_event.machine_id,
      activity: history_event.activity,
      filename: history_event.filename,
      extension: history_event.extension,
      domain: history_event.domain,
      url: history_event.url,
      keylogger_signal: history_event.keylogger_signal,
      job_signal: history_event.job_signal,
      leak_signal: history_event.leak_signal,
      cloud_signal: history_event.cloud_signal,
      recipient_count: history_event.recipient_count,
      recipients: history_event.recipients,
      size: history_event.size,
      attachments: history_event.attachments
  }) AS history_events
  RETURN history_events
}

CALL {
  WITH u
  OPTIONAL MATCH (u)-[emailed:EMAILED]->(address:EmailAddress)
  WHERE emailed.first_seen < $trigger_ts
  RETURN collect(address.address) AS recipient_history
}

CALL {
  WITH u, trigger_machine
  OPTIONAL MATCH (u)-[used:USED_MACHINE]->(trigger_machine)
  RETURN coalesce(used.count, 0) AS victim_machine_count,
         used.first_seen AS victim_machine_first_seen,
         used.last_seen AS victim_machine_last_seen
}

CALL {
  WITH u
  OPTIONAL MATCH (u)-[all_used:USED_MACHINE]->(:Machine)
  RETURN sum(coalesce(all_used.count, 0)) AS victim_total_machine_count
}

CALL {
  WITH trigger_machine
  OPTIONAL MATCH (owner:User)-[owner_used:USED_MACHINE]->(trigger_machine)
  WITH owner, owner_used
  ORDER BY coalesce(owner_used.count, 0) DESC
  RETURN collect({user_id: owner.id, count: coalesce(owner_used.count, 0)}) AS machine_owners,
         sum(coalesce(owner_used.count, 0)) AS machine_total_count
}

CALL {
  WITH u, trigger_machine
  MATCH (candidate_event:Event)
  WHERE candidate_event.event_ts >= $window_start_ts
    AND candidate_event.event_ts <= $trigger_ts
  WITH u, trigger_machine, collect(candidate_event) AS window_events
  UNWIND (CASE WHEN size(window_events) = 0 THEN [NULL] ELSE window_events END) AS candidate_event
  WITH u, trigger_machine, candidate_event
  OPTIONAL MATCH (attacker:User)-[:ACTED]->(candidate_event)
  OPTIONAL MATCH (candidate_event)-[:ON_MACHINE]->(candidate_machine:Machine)
  WITH u, attacker, candidate_event, candidate_machine,
       (
          candidate_event IS NOT NULL
          AND attacker IS NOT NULL
          AND attacker.id <> u.id
          AND (candidate_machine.id = $machine_id OR candidate_event.keylogger_signal = true)
       ) AS is_valid_candidate
  WITH u,
       CASE WHEN is_valid_candidate THEN attacker ELSE NULL END AS attacker,
       CASE WHEN is_valid_candidate THEN candidate_event ELSE NULL END AS stage_event,
       CASE WHEN is_valid_candidate THEN candidate_machine ELSE NULL END AS stage_machine
  ORDER BY (stage_event IS NULL), stage_event.event_ts DESC
  LIMIT $max_stage_events
  WITH u, collect(CASE WHEN stage_event IS NULL THEN NULL ELSE {
      event_id: stage_event.id,
      source: stage_event.source,
      kind: stage_event.kind,
      user_id: attacker.id,
      event_ts: stage_event.event_ts,
      machine_id: stage_machine.id,
      activity: stage_event.activity,
      filename: stage_event.filename,
      extension: stage_event.extension,
      domain: stage_event.domain,
      url: stage_event.url,
      keylogger_signal: stage_event.keylogger_signal,
      download_signal: stage_event.download_signal,
      job_signal: stage_event.job_signal,
      leak_signal: stage_event.leak_signal,
      cloud_signal: stage_event.cloud_signal,
      recipient_count: stage_event.recipient_count,
      recipients: stage_event.recipients,
      size: stage_event.size,
      attachments: stage_event.attachments
  } END) AS raw_stage_events
  WITH u, reduce(acc = [], event IN raw_stage_events | CASE WHEN event IS NOT NULL THEN acc + [event] ELSE acc END) AS stage_events
  RETURN stage_events,
         reduce(acc = [], event IN stage_events | CASE WHEN event.user_id <> u.id THEN acc + [event.user_id] ELSE acc END) AS attacker_ids
}

WITH u, trigger_machine, history_events, recipient_history, victim_machine_count, victim_machine_first_seen, victim_machine_last_seen, victim_total_machine_count, machine_owners, machine_total_count, stage_events, attacker_ids,
     CASE WHEN size(machine_owners) > 0 THEN machine_owners[0] ELSE NULL END AS primary_machine_owner
RETURN {
    user_id: u.id,
    machine_id: $machine_id,
    target_machine_id: $machine_id,
    attacker_user_id: CASE WHEN size(attacker_ids) = 0 THEN NULL ELSE attacker_ids[0] END,
    owner_confidence: CASE
        WHEN machine_total_count IS NULL OR machine_total_count = 0 OR primary_machine_owner IS NULL THEN 0.0
        ELSE toFloat(primary_machine_owner.count) / machine_total_count
    END,
    user_machine_probability: CASE
        WHEN victim_total_machine_count IS NULL OR victim_total_machine_count = 0 THEN 0.0
        ELSE toFloat(victim_machine_count) / victim_total_machine_count
    END,
    history_start_ts: $history_start_ts,
    window_start_ts: $window_start_ts,
    trigger_ts: $trigger_ts,
    history_events: history_events,
    stage_events: stage_events,
    window_events: stage_events,
    per_email_history: reduce(acc = [], event IN history_events | CASE WHEN event.kind = 'EMAIL' THEN acc + [coalesce(event.recipient_count, 0)] ELSE acc END),
    window_fanout_history: reduce(acc = [], event IN history_events | CASE WHEN event.kind = 'EMAIL' AND event.event_ts >= $trigger_ts - 600 THEN acc + [coalesce(event.recipient_count, 0)] ELSE acc END),
    recipient_history: recipient_history,
    machine_use: {
        count: victim_machine_count,
        total_count: coalesce(victim_total_machine_count, 0),
        first_seen: victim_machine_first_seen,
        last_seen: victim_machine_last_seen
    }
} AS context
"""

_UPSERT_ALERT_QUERY = """
MERGE (alert:Alert {id: $alert_id})
SET alert.detector = $detector,
    alert.score = $score,
    alert.threshold = $threshold,
    alert.trigger_event_id = $trigger_event_id,
    alert.event_time = $event_time,
    alert.components = $components,
    alert.user_ids = $user_ids,
    alert.machine_ids = $machine_ids,
    alert.evidence_event_ids = $evidence_event_ids,
    alert.evidence_start_ts = $evidence_start_ts,
    alert.evidence_end_ts = $evidence_end_ts
WITH alert
MATCH (trigger:Event {id: $trigger_event_id})
MERGE (alert)-[:EVIDENCE]->(trigger)
WITH alert
UNWIND $user_ids AS user_id
MERGE (user:User {id: user_id})
MERGE (alert)-[:ABOUT]->(user)
WITH alert
UNWIND $machine_ids AS machine_id
MERGE (machine:Machine {id: machine_id})
MERGE (alert)-[:INVOLVES]->(machine)
RETURN alert.id AS alert_id
"""


def _derive_domain(value: str | None) -> str | None:
    if not value:
        return None
    host = (urlparse(value).hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


class GraphRepository:
    def __init__(self, driver, database: str | None = None):
        self._driver = driver
        self.database = database

    def _session(self):
        if self.database is None:
            return self._driver.session()
        return self._driver.session(database=self.database)

    @staticmethod
    def _record_to_params(event: Event, ingest_time: datetime) -> dict[str, Any]:
        record = event.to_record()
        return {
            "event_id": record["event_id"],
            "source": record["source"],
            "kind": record["kind"],
            "event_time": record["event_time"],
            "event_ts": record["event_ts"],
            "ingest_time": ingest_time.isoformat(sep=" "),
            "user_id": record["user_id"],
            "machine_id": record["machine_id"],
            "properties": record["properties"],
        }

    def _execute_write(self, callback):
        with self._session() as session:
            return session.execute_write(callback)

    def _execute_read(self, callback):
        with self._session() as session:
            return session.execute_read(callback)

    def reset(self) -> None:
        def tx_fn(tx):
            tx.run(_RESET_QUERY)

        self._execute_write(tx_fn)

    def write_event(self, event: Event, ingest_time: datetime) -> WriteResult:
        params = self._record_to_params(event, ingest_time)

        def tx_fn(tx):
            created_row = tx.run(_UPSERT_EVENT_QUERY, **params).single() or {}
            created = bool(created_row.get("created"))
            if not created:
                return False

            tx.run(_USED_MACHINE_QUERY, **params)

            if event.kind == "LOGON":
                tx.run(
                    _OPEN_ACTIVITY_WINDOW_QUERY,
                    activity_window_id=f"{event.user_id}|{event.machine_id}|{event.event_id}",
                    **params,
                )
            elif event.kind == "LOGOFF":
                tx.run(_CLOSE_ACTIVITY_WINDOW_QUERY, **params)
            elif event.kind == "DEVICE_CONNECT":
                tx.run(
                    _OPEN_USB_SESSION_QUERY,
                    usb_session_id=f"{event.user_id}|{event.machine_id}|{event.event_id}",
                    **params,
                )
            elif event.kind == "DEVICE_DISCONNECT":
                tx.run(_CLOSE_USB_SESSION_QUERY, **params)
            elif event.kind == "FILE_COPY":
                attach_row = tx.run(_ATTACH_USB_SESSION_QUERY, **params).single() or {}
                if not attach_row.get("session_id"):
                    tx.run(
                        _CREATE_INFERRED_USB_SESSION_QUERY,
                        inferred_usb_session_id=f"inferred|{event.user_id}|{event.machine_id}|{event.event_id}",
                        **params,
                    )
            elif event.kind == "HTTP":
                domain = event.properties.get("domain") or _derive_domain(event.properties.get("url"))
                if domain:
                    tx.run(_VISIT_DOMAIN_QUERY, domain=domain, **params)
            elif event.kind == "EMAIL":
                tx.run(_EMAIL_QUERY, recipients=tuple(event.properties.get("recipients", ())), **params)

            return created

        created = self._execute_write(tx_fn)
        return WriteResult(event_id=event.event_id, created=bool(created))

    def fetch_uc1_context(self, user_id: str, trigger_ts: int) -> dict:
        params = {
            "user_id": user_id,
            "trigger_ts": trigger_ts,
            "history_start_ts": trigger_ts - 30 * 24 * 60 * 60,
            "motif_start_ts": trigger_ts - 48 * 60 * 60,
        }

        def tx_fn(tx):
            row = tx.run(_UC1_CONTEXT_QUERY, **params).single() or {}
            return row.get("context", row)

        return self._execute_read(tx_fn)

    def fetch_uc2_context(self, user_id: str, machine_id: str, trigger_ts: int) -> dict:
        params = {
            "user_id": user_id,
            "machine_id": machine_id,
            "trigger_ts": trigger_ts,
            "history_start_ts": trigger_ts - 90 * 24 * 60 * 60,
            "window_start_ts": trigger_ts - 48 * 60 * 60,
            # Chặn OPTIONAL MATCH (attacker)-[:ACTED]->(stage_event) phình vô hạn: điều kiện
            # lọc "kind IN [HTTP, DEVICE_CONNECT, FILE_COPY, LOGON]" gần như khớp mọi event
            # phổ biến của MỌI user khác trong cửa sổ 48h, nên với cohort có volume HTTP lớn
            # (vd hàng chục nghìn event/ngày) mỗi lần trigger sẽ collect hàng nghìn record đầy
            # field, đủ để Memgraph OOM dù cohort chỉ vài user. Giữ N event gần nhất theo
            # event_ts là đủ cho tín hiệu continuity/order mà UC2Detector cần.
            "max_stage_events": int(os.getenv("UC2_MAX_STAGE_EVENTS", "500")),
        }

        def tx_fn(tx):
            row = tx.run(_UC2_CONTEXT_QUERY, **params).single() or {}
            return row.get("context", row)

        return self._execute_read(tx_fn)

    def upsert_alert(self, alert: AlertRecord) -> None:
        params = {
            "alert_id": alert.alert_id,
            "detector": alert.detector,
            "score": alert.score,
            "threshold": alert.threshold,
            "trigger_event_id": alert.trigger_event_id,
            "event_time": alert.event_time.isoformat(sep=" "),
            "components": alert.components,
            "user_ids": list(alert.user_ids),
            "machine_ids": list(alert.machine_ids),
            "evidence_event_ids": list(alert.evidence_event_ids),
            "evidence_start_ts": alert.evidence_start_ts,
            "evidence_end_ts": alert.evidence_end_ts,
        }

        def tx_fn(tx):
            tx.run(_UPSERT_ALERT_QUERY, **params)

        self._execute_write(tx_fn)

    def prune_events(self, before_ts: int) -> int:
        def tx_fn(tx):
            row = tx.run(_PRUNE_COUNT_QUERY, before_ts=before_ts).single() or {}
            deleted_count = int(row.get("deleted_count") or 0)
            tx.run(_PRUNE_DELETE_QUERY, before_ts=before_ts)
            return deleted_count

        return self._execute_write(tx_fn)
