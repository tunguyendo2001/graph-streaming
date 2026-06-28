// UC2 evidence query: credential pivot -> victim email fan-out.
// Parameters:
//   $user_id, $machine_id, $history_start_ts, $window_start_ts, $trigger_ts

MATCH (victim:User {id: $user_id})
MATCH (target_machine:Machine {id: $machine_id})
OPTIONAL MATCH (victim)-[victim_use:USED_MACHINE]->(target_machine)
WITH victim,
     target_machine,
     coalesce(victim_use.count, 0) AS victim_machine_count,
     coalesce(victim_use.total_count, 0) AS victim_total_machine_count
OPTIONAL MATCH (owner:User)-[owner_use:USED_MACHINE]->(target_machine)
WITH victim,
     target_machine,
     victim_machine_count,
     victim_total_machine_count,
     owner,
     owner_use
ORDER BY coalesce(owner_use.count, 0) DESC
WITH victim,
     target_machine,
     victim_machine_count,
     victim_total_machine_count,
     collect({user_id: owner.id, count: coalesce(owner_use.count, 0)}) AS owners
WITH victim,
     target_machine,
     victim_machine_count,
     victim_total_machine_count,
     owners[0] AS dominant_owner
OPTIONAL MATCH (attacker:User)-[:ACTED]->(stage:Event)-[:ON_MACHINE]->(stage_machine:Machine)
WHERE attacker.id <> victim.id
  AND stage.event_ts >= $window_start_ts
  AND stage.event_ts <= $trigger_ts
  AND (
    stage_machine.id = target_machine.id
    OR stage.keylogger_signal = true
    OR stage.kind IN ['DEVICE_CONNECT', 'FILE_COPY', 'HTTP', 'LOGON']
  )
WITH victim,
     target_machine,
     victim_machine_count,
     victim_total_machine_count,
     dominant_owner,
     attacker,
     collect(CASE WHEN stage IS NULL THEN NULL ELSE {
       event_id: stage.id,
       source: stage.source,
       kind: stage.kind,
       user_id: attacker.id,
       event_ts: stage.event_ts,
       machine_id: stage_machine.id,
       activity: stage.activity,
       filename: stage.filename,
       extension: stage.extension,
       domain: stage.domain,
       url: stage.url,
       keylogger_signal: stage.keylogger_signal,
       download_signal: stage.download_signal,
       recipients: stage.recipients,
       recipient_count: stage.recipient_count
     } END) AS raw_stage_events
WITH victim,
     target_machine,
     victim_machine_count,
     victim_total_machine_count,
     dominant_owner,
     attacker,
     [event IN raw_stage_events WHERE event IS NOT NULL] AS stage_events
OPTIONAL MATCH (victim)-[emailed:EMAILED]->(recipient:EmailAddress)
WHERE emailed.first_seen < $trigger_ts
WITH victim,
     target_machine,
     victim_machine_count,
     victim_total_machine_count,
     dominant_owner,
     attacker,
     stage_events,
     collect(recipient.address) AS recipient_history
OPTIONAL MATCH (victim)-[:ACTED]->(history_email:Event)
WHERE history_email.kind = 'EMAIL'
  AND history_email.event_ts >= $history_start_ts
  AND history_email.event_ts < $trigger_ts
WITH victim,
     target_machine,
     victim_machine_count,
     victim_total_machine_count,
     dominant_owner,
     attacker,
     stage_events,
     recipient_history,
     collect(history_email.recipient_count) AS per_email_history
OPTIONAL MATCH (victim)-[:ACTED]->(current_email:Event)
WHERE current_email.kind = 'EMAIL'
  AND current_email.event_ts <= $trigger_ts
  AND current_email.event_ts >= $trigger_ts - 600
WITH victim,
     target_machine,
     victim_machine_count,
     victim_total_machine_count,
     dominant_owner,
     attacker,
     stage_events,
     recipient_history,
     per_email_history,
     collect(current_email.recipient_count) AS current_window_counts
RETURN {
  user_id: victim.id,
  machine_id: target_machine.id,
  attacker_user_id: attacker.id,
  target_machine_id: target_machine.id,
  owner_confidence: CASE
    WHEN dominant_owner.count IS NULL OR dominant_owner.count = 0 THEN 0.0
    ELSE 1.0
  END,
  user_machine_probability: CASE
    WHEN victim_total_machine_count = 0 THEN 0.0
    ELSE toFloat(victim_machine_count) / victim_total_machine_count
  END,
  window_start_ts: $window_start_ts,
  trigger_ts: $trigger_ts,
  stage_events: stage_events,
  recipient_history: recipient_history,
  per_email_history: per_email_history,
  window_fanout_history: current_window_counts,
  current_recipients: []
} AS context;
