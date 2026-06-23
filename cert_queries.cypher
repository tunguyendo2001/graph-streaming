// ============================================================
// CERT Insider Threat r4.2 - Memgraph Lab Queries
// ============================================================


// Use-case 1: Bắt Quả Tang Kẻ Trộm
// Tìm user có chuỗi: LOGON -> CONNECT USB -> Copy file mật trong 00:00-05:00.
// timestamp được lưu dạng "YYYY-MM-DD HH:MM:SS", nên so sánh chuỗi ISO vẫn đúng.
MATCH (u:User)-[logon:LOGON]->(m:Machine)
MATCH (u)-[usb:CONNECT]->(d:Device)
MATCH (u)-[copy:FILE_ACTION {action: "Copy"}]->(f:File {is_secret: true})
WHERE substring(logon.timestamp, 11, 8) >= "00:00:00"
  AND substring(copy.timestamp, 11, 8) <= "05:00:00"
  AND substring(logon.timestamp, 0, 10) = substring(usb.timestamp, 0, 10)
  AND substring(usb.timestamp, 0, 10) = substring(copy.timestamp, 0, 10)
  AND logon.timestamp <= usb.timestamp
  AND usb.timestamp <= copy.timestamp
WITH
  u,
  m,
  d,
  count(DISTINCT f) AS secretFileCount
WHERE secretFileCount > 0
RETURN
  u.id AS userId,
  m.id AS machineId,
  d.id AS usbId,
  secretFileCount
ORDER BY secretFileCount DESC;


// Use-case 2: Bắt Quả Tang Kẻ Dòm Ngó
// Tìm user đăng nhập vào >= 4 máy thuộc phòng Finance.
MATCH (u:User)-[:LOGON]->(m:Machine {dept: "Finance"})
WITH
  u,
  collect(DISTINCT m.id) AS financeMachines,
  count(DISTINCT m) AS financeMachineCount
WHERE financeMachineCount >= 4
RETURN
  u.id AS userId,
  financeMachineCount,
  financeMachines
ORDER BY financeMachineCount DESC;
