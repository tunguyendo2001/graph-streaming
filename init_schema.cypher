// Tạo index giúp MERGE node nhanh hơn khi stream dữ liệu CERT vào Memgraph.
CREATE INDEX ON :User(id);
CREATE INDEX ON :Machine(id);
CREATE INDEX ON :File(id);
CREATE INDEX ON :Device(id);
