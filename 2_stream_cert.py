import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from neo4j import GraphDatabase

from event_model import DEFAULT_SORT_RUN_SIZE
from event_replay import ReplayConfig, ReplayEngine
from graph_detectors import UC1Detector, UC2Detector
from graph_repository import GraphRepository


def configure_console_encoding() -> None:
    if os.name != "nt":
        return
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def build_auth():
    user = os.getenv("MEMGRAPH_USER", "")
    password = os.getenv("MEMGRAPH_PASSWORD", "")
    if user or password:
        return (user, password)
    return None


def limited_stream_copy(stream_path: Path, limit: int | None) -> tuple[Path, Path | None]:
    if limit is None:
        return stream_path, None
    if limit <= 0:
        raise ValueError("--limit must be positive when provided")
    handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".jsonl", delete=False)
    copied = 0
    with handle:
        with stream_path.open("r", encoding="utf-8") as source:
            for line in source:
                if not line.strip():
                    continue
                handle.write(line)
                copied += 1
                if copied >= limit:
                    break
    return Path(handle.name), Path(handle.name)


def replay_cert_stream(
    *,
    stream_path: Path,
    uri: str,
    reset: bool,
    delay: float,
    limit: int | None,
    calibration_days: int,
    allowed_lateness_seconds: int,
    replay_run_size: int,
    summary_path: Path,
) -> dict:
    if not stream_path.exists():
        raise FileNotFoundError(f"Không tìm thấy JSONL stream: {stream_path.resolve()}")

    replay_path, temporary_path = limited_stream_copy(stream_path, limit)
    driver = GraphDatabase.driver(uri, auth=build_auth())
    try:
        repository = GraphRepository(driver, database=os.getenv("MEMGRAPH_DATABASE") or None)
        if reset:
            print("[STREAM] Xóa graph cũ trước khi replay...")
            repository.reset()
        applied = repository.apply_schema()
        print(f"[STREAM] Đã đảm bảo {len(applied)} index (init_schema.cypher).")
        config = ReplayConfig(
            calibration_days=calibration_days,
            allowed_lateness_seconds=allowed_lateness_seconds,
            delay_seconds=delay,
            uc1_fallback_threshold=float(os.getenv("UC1_FALLBACK_THRESHOLD", "0.75")),
            uc2_fallback_threshold=float(os.getenv("UC2_FALLBACK_THRESHOLD", "0.75")),
            prune_after_days=int(os.getenv("PRUNE_AFTER_DAYS", "90")),
            sort_run_size=replay_run_size,
        )
        engine = ReplayEngine(repository, UC1Detector(), UC2Detector(), config)
        summary = engine.replay(replay_path).to_dict()
    finally:
        driver.close()
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)

    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    return summary


def main() -> None:
    configure_console_encoding()
    parser = argparse.ArgumentParser(description="Replay CERT r4.2 JSONL stream vào Memgraph và chạy graph detectors.")
    parser.add_argument("--stream", default=os.getenv("CERT_STREAM_JSONL", "artifacts/evaluation_stream.jsonl"))
    parser.add_argument("--uri", default=os.getenv("MEMGRAPH_URI", "bolt://localhost:7687"))
    parser.add_argument("--reset", action="store_true", help="Xóa graph hiện tại trước khi replay.")
    parser.add_argument("--delay", type=float, default=float(os.getenv("CERT_STREAM_DELAY_SECONDS", "0")))
    parser.add_argument("--limit", type=int, default=None, help="Giới hạn số event replay khi demo nhanh.")
    parser.add_argument("--calibration-days", type=int, default=int(os.getenv("CALIBRATION_DAYS", "30")))
    parser.add_argument(
        "--allowed-lateness-seconds",
        type=int,
        default=int(os.getenv("ALLOWED_LATENESS_SECONDS", "300")),
    )
    parser.add_argument(
        "--replay-run-size",
        type=int,
        default=int(os.getenv("REPLAY_RUN_SIZE", str(DEFAULT_SORT_RUN_SIZE))),
        help="Số event mỗi lô khi sắp xếp ngoài bộ nhớ (external sort); giảm giá trị này để hạ RAM đỉnh trên máy yếu.",
    )
    parser.add_argument("--summary", default=os.getenv("REPLAY_SUMMARY_JSON", "artifacts/replay_summary.json"))
    args = parser.parse_args()

    summary = replay_cert_stream(
        stream_path=Path(args.stream),
        uri=args.uri,
        reset=args.reset,
        delay=args.delay,
        limit=args.limit,
        calibration_days=args.calibration_days,
        allowed_lateness_seconds=args.allowed_lateness_seconds,
        replay_run_size=args.replay_run_size,
        summary_path=Path(args.summary),
    )
    print(
        "[STREAM] done "
        f"processed={summary['processed_events']} "
        f"alerts={summary['alerts_persisted']} "
        f"duplicates={summary['duplicate_events']} "
        f"eps={summary['throughput_events_per_second']:.1f} "
        f"rss_mb={summary['peak_python_rss_mb']:.1f} "
        f"thresholds={summary['thresholds']}"
    )
    print(f"[STREAM] summary={Path(args.summary).resolve()}")


if __name__ == "__main__":
    main()
