import argparse
import sys
from pathlib import Path

from cert_extractor import (
    extract_evaluation_stream,
    load_incidents,
    select_matched_controls,
    write_cohort_manifest,
)


def configure_console_encoding() -> None:
    """
    Đảm bảo log tiếng Việt in được trên Windows console.
    """
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Tiền xử lý CERT r4.2 thành JSONL stream sự kiện thật cho cohort đánh giá."
    )
    parser.add_argument("--input-dir", default="data/cert-r4.2/r4.2", help="Thư mục dữ liệu CERT r4.2.")
    parser.add_argument("--answers-dir", default="data/cert-r4.2/answers", help="Thư mục đáp án CERT.")
    parser.add_argument("--output", default="artifacts/evaluation_stream.jsonl", help="File JSONL đầu ra.")
    parser.add_argument("--manifest", default="artifacts/cohort.json", help="File manifest cohort đầu ra.")
    parser.add_argument(
        "--controls-per-insider",
        type=int,
        default=2,
        help="Số control ghép cho mỗi insider.",
    )
    parser.add_argument("--run-size", type=int, default=50000, help="Số event tối đa mỗi run sắp xếp.")
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    answers_dir = Path(args.answers_dir)
    output_path = Path(args.output)
    manifest_path = Path(args.manifest)

    incidents = load_incidents(answers_dir / "insiders.csv")
    controls = select_matched_controls(
        input_dir=input_dir,
        incidents=incidents,
        controls_per_insider=args.controls_per_insider,
    )
    write_cohort_manifest(manifest_path, incidents, controls)

    cohort = {incident.user_id for incident in incidents} | {match.control_id for match in controls}
    result = extract_evaluation_stream(
        input_dir=input_dir,
        cohort=cohort,
        output_path=output_path,
        run_size=args.run_size,
    )

    source_summary = ", ".join(f"{source}={count}" for source, count in sorted(result.source_counts.items()))
    print(
        "[PREP] "
        f"incidents={len(incidents)} controls={len(controls)} "
        f"events={result.event_count} "
        f"range={result.first_event_time}..{result.last_event_time} "
        f"sources={source_summary or 'none'}"
    )
    print(f"[PREP] manifest={manifest_path} output={output_path}")


if __name__ == "__main__":
    configure_console_encoding()
    main()
