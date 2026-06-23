import argparse
import csv
import os
import sys
import time
from pathlib import Path

from neo4j import GraphDatabase

from cert_pipeline import build_cypher_payload, format_stream_log


def configure_console_encoding() -> None:
    """
    Đảm bảo log tiếng Việt in được trên Windows console.
    """
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def build_auth():
    """
    Memgraph local thường không bật auth. Nếu bật auth, set biến môi trường.
    """
    user = os.getenv("MEMGRAPH_USER", "")
    password = os.getenv("MEMGRAPH_PASSWORD", "")
    if user or password:
        return user, password
    return None


def execute_write(session, callback, payload):
    """
    Tương thích neo4j-driver v4/v5.
    """
    if hasattr(session, "execute_write"):
        return session.execute_write(callback, payload)
    return session.write_transaction(callback, payload)


def write_event(tx, row: dict) -> None:
    """
    Chọn Cypher theo event_type rồi ghi một event vào Memgraph.
    """
    query, params = build_cypher_payload(row)
    tx.run(query, **params).consume()


def stream_cert_events(csv_path: Path, uri: str, delay: float, reset: bool, limit: int | None) -> None:
    """
    Stream clean_cert_stream.csv vào Memgraph theo từng dòng.
    """
    if not csv_path.exists():
        raise FileNotFoundError(f"Không tìm thấy file stream sạch: {csv_path.resolve()}")

    driver = GraphDatabase.driver(uri, auth=build_auth())

    try:
        driver.verify_connectivity()
        print(f"[STREAM] Đã kết nối Memgraph tại {uri}")

        with driver.session() as session:
            if reset:
                print("[STREAM] Xóa graph cũ trước khi stream...")
                session.run("MATCH (n) DETACH DELETE n").consume()

            with csv_path.open("r", encoding="utf-8-sig", newline="") as file:
                reader = csv.DictReader(file)
                for row_number, row in enumerate(reader, start=1):
                    if limit is not None and row_number > limit:
                        break

                    try:
                        execute_write(session, write_event, row)
                        print(format_stream_log(row))
                        time.sleep(delay)
                    except Exception as row_error:
                        print(f"[ERROR] Lỗi tại dòng {row_number}: {row_error}")

    except Exception as error:
        print(f"[FATAL] Không thể stream CERT vào Memgraph: {error}")
        raise
    finally:
        driver.close()
        print("[STREAM] Đã đóng kết nối Memgraph.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Stream clean_cert_stream.csv vào Memgraph.")
    parser.add_argument("--csv", default=os.getenv("CERT_STREAM_CSV", "clean_cert_stream.csv"))
    parser.add_argument("--uri", default=os.getenv("MEMGRAPH_URI", "bolt://localhost:7687"))
    parser.add_argument("--delay", type=float, default=float(os.getenv("CERT_STREAM_DELAY_SECONDS", "0.04")))
    parser.add_argument("--reset", action="store_true", help="Xóa graph hiện tại trước khi stream.")
    parser.add_argument("--limit", type=int, default=None, help="Giới hạn số dòng stream khi demo nhanh.")
    args = parser.parse_args()

    stream_cert_events(
        csv_path=Path(args.csv),
        uri=args.uri,
        delay=args.delay,
        reset=args.reset,
        limit=args.limit,
    )


if __name__ == "__main__":
    configure_console_encoding()
    main()
