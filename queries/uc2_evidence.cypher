MATCH (victim:User {id: $user_id})-[:ACTED]->(trigger:Event)-[:ON_MACHINE]->(target:Machine {id: $machine_id})
WHERE trigger.id = $trigger_event_id

// Tìm chủ nhân của máy (Machine owner & confidence)
OPTIONAL MATCH (owner:User)-[used:USED_MACHINE]->(target)
WITH victim, trigger, target, owner, used.count AS cnt
ORDER BY cnt DESC LIMIT 1

// Tìm các hành vi từ attacker khác trên cùng target machine
OPTIONAL MATCH (attacker:User)-[:ACTED]->(att_e:Event)-[:ON_MACHINE]->(target)
WHERE attacker <> victim AND att_e.event_ts >= $motif_start_ts AND att_e.event_ts < trigger.event_ts
OPTIONAL MATCH (att_e)-[:BOUNDARY_OF|IN_USB_SESSION]->(sess:UsbSession)

// Tìm email của victim
OPTIONAL MATCH (trigger)-[:SENT_TO]->(email:EmailAddress)

RETURN 
    victim.id AS victim_id,
    target.id AS machine_id,
    owner.id AS dominant_user,
    attacker.id AS attacker_id,
    att_e.id AS attacker_event_id,
    att_e.kind AS attacker_event_kind,
    att_e.event_ts AS attacker_event_ts,
    sess.id AS attacker_session,
    collect(email.address) AS current_recipients
ORDER BY att_e.event_ts ASC;

