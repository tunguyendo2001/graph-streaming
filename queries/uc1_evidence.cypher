MATCH (u:User {id: $user_id})
// Tìm các sự kiện ứng cử viên trong cửa sổ motif
MATCH (u)-[:ACTED]->(e:Event)-[:ON_MACHINE]->(m:Machine)
WHERE e.event_ts >= $motif_start_ts AND e.event_ts <= $trigger_ts
OPTIONAL MATCH (e)-[:BOUNDARY_OF|IN_USB_SESSION]->(sess:UsbSession)
OPTIONAL MATCH (e)-[:VISITED]->(d:Domain)
RETURN 
    u.id AS user_id, 
    m.id AS machine_id, 
    e.id AS event_id, 
    e.kind AS kind, 
    e.event_ts AS event_ts,
    sess.id AS session_id,
    d.name AS domain
ORDER BY e.event_ts ASC;

