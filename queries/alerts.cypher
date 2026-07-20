// All alert evidence paths.
MATCH p = (a:Alert)-[:ABOUT|EVIDENCE|INVOLVES*1..3]-(entity)
RETURN p
ORDER BY a.event_time DESC;

// Specific alert ID.
// :param alert_id => "uc1_exfiltration_motif|event-id";
MATCH p = (a:Alert {id: $alert_id})-[:ABOUT|EVIDENCE|INVOLVES*1..3]-(entity)
RETURN p
ORDER BY a.event_time DESC;

// All UC1 exfiltration motif alerts.
MATCH p = (a:Alert {detector: "uc1_exfiltration_motif"})-[:ABOUT|EVIDENCE|INVOLVES*1..3]-(entity)
RETURN p
ORDER BY a.score DESC, a.event_time DESC;

// All UC2 credential-pivot motif alerts.
MATCH p = (a:Alert {detector: "uc2_credential_pivot_motif"})-[:ABOUT|EVIDENCE|INVOLVES*1..3]-(entity)
RETURN p
ORDER BY a.score DESC, a.event_time DESC;

// Component score table.
MATCH (a:Alert)
RETURN
  a.id AS alert_id,
  a.detector AS detector,
  a.score AS score,
  a.threshold AS threshold,
  a.components AS components,
  a.user_ids AS users,
  a.machine_ids AS machines,
  a.evidence_event_ids AS evidence
ORDER BY a.score DESC, a.event_time DESC;

// Evidence event timeline for a specific alert.
// :param alert_id => "uc1_exfiltration_motif|event-id";
MATCH (a:Alert {id: $alert_id})
UNWIND a.evidence_event_ids AS evidence_id
MATCH (e:Event {id: evidence_id})
OPTIONAL MATCH (e)-[:ON_MACHINE]->(m:Machine)
RETURN
  evidence_id,
  e.event_ts AS event_ts,
  e.event_time AS event_time,
  e.kind AS kind,
  e.user_id AS user_id,
  coalesce(m.id, e.machine_id) AS machine_id,
  e.domain AS domain,
  e.filename AS filename,
  e.recipient_count AS recipient_count
ORDER BY event_ts, evidence_id;
