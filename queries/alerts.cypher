MATCH p = (a:Alert)-[:ABOUT|EVIDENCE|INVOLVES*1..3]-(entity)
RETURN p
ORDER BY a.event_time DESC;
