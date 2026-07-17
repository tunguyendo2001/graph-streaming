// UC1 evidence query: anomalous LOGON -> USB -> FILE_COPY -> external domain.
// Parameters:
//   $user_id, $history_start_ts, $motif_start_ts, $trigger_ts

MATCH (u:User {id: $user_id})
OPTIONAL MATCH (u)-[:ACTED]->(history:Event)-[:ON_MACHINE]->(history_machine:Machine)
WHERE history.event_ts >= $history_start_ts
  AND history.event_ts < $trigger_ts
WITH u, collect(CASE WHEN history IS NULL THEN NULL ELSE {
  event_id: history.id,
  source: history.source,
  kind: history.kind,
  event_ts: history.event_ts,
  machine_id: history_machine.id,
  activity: history.activity,
  filename: history.filename,
  extension: history.extension,
  domain: history.domain,
  leak_signal: history.leak_signal,
  cloud_signal: history.cloud_signal,
  job_signal: history.job_signal
} END) AS history_events
OPTIONAL MATCH (u)-[:ACTED]->(candidate:Event)-[:ON_MACHINE]->(candidate_machine:Machine)
WHERE candidate.event_ts >= $motif_start_ts
  AND candidate.event_ts <= $trigger_ts
OPTIONAL MATCH (candidate)-[:IN_USB_SESSION|BOUNDARY_OF]->(usb_session:UsbSession)
OPTIONAL MATCH (candidate)-[:VISITED]->(domain:Domain)
WITH u, history_events, collect(CASE WHEN candidate IS NULL THEN NULL ELSE {
  event_id: candidate.id,
  source: candidate.source,
  kind: candidate.kind,
  event_ts: candidate.event_ts,
  machine_id: candidate_machine.id,
  activity: candidate.activity,
  filename: candidate.filename,
  extension: candidate.extension,
  domain: coalesce(domain.name, candidate.domain),
  leak_signal: candidate.leak_signal,
  cloud_signal: candidate.cloud_signal,
  job_signal: candidate.job_signal,
  usb_session_id: usb_session.id
} END) AS candidate_events
WITH u,
     history_events,
     candidate_events
RETURN {
  user_id: u.id,
  history_start_ts: $history_start_ts,
  motif_start_ts: $motif_start_ts,
  trigger_ts: $trigger_ts,
  history_events: history_events,
  candidate_events: candidate_events,
  active_usb_session_ids: [event IN candidate_events WHERE event.usb_session_id IS NOT NULL | event.usb_session_id],
  logon_hours: [event IN history_events WHERE event.kind = 'LOGON' | event.event_ts],
  historical_daily_usb_events: [event IN history_events WHERE event.kind = 'DEVICE_CONNECT' | event.event_ts],
  historical_file_copy_events: [event IN history_events WHERE event.kind = 'FILE_COPY' | event.event_ts],
  historical_domains: [event IN history_events WHERE event.domain IS NOT NULL | event.domain]
} AS context;
