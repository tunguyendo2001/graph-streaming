import argparse
import sys
from datetime import timedelta
from pathlib import Path

from cert_extractor import (
    extract_evaluation_stream,
    load_incident_detail_user_ids,
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
    parser.add_argument(
        "--insider-ids",
        default=None,
        help=(
            "Chỉ dựng cohort cho các insider này (phân tách bởi dấu phẩy), thay vì toàn bộ "
            "70 insider thật. Dùng để demo nhanh trên máy yếu: vd '--insider-ids AAM0658,BBS0039' "
            "cho ra đúng 1 alert UC1 (leak motif) và 1 alert UC2 (credential pivot)."
        ),
    )
    parser.add_argument(
        "--history-days-before",
        type=int,
        default=100,
        help=(
            "Chỉ áp dụng khi dùng --insider-ids: giới hạn stream chỉ lấy event từ N ngày trước "
            "incident sớm nhất, thay vì toàn bộ lịch sử user (có thể hơn 1 năm). 100 ngày đủ cho "
            "cả UC1 (30 ngày) lẫn UC2 (90 ngày) baseline mà không thiếu dữ liệu, nhưng giảm khối "
            "lượng event đáng kể khi replay."
        ),
    )
    parser.add_argument(
        "--days-after-incident",
        type=int,
        default=7,
        help="Chỉ áp dụng khi dùng --insider-ids: số ngày lấy thêm sau incident muộn nhất kết thúc.",
    )
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    answers_dir = Path(args.answers_dir)
    output_path = Path(args.output)
    manifest_path = Path(args.manifest)

    incidents = load_incidents(answers_dir / "insiders.csv")
    if args.insider_ids:
        wanted_ids = {user_id.strip() for user_id in args.insider_ids.split(",") if user_id.strip()}
        known_ids = {incident.user_id for incident in incidents}
        unknown_ids = wanted_ids - known_ids
        if unknown_ids:
            raise SystemExit(f"[PREP] Không tìm thấy insider trong insiders.csv: {', '.join(sorted(unknown_ids))}")
        incidents = [incident for incident in incidents if incident.user_id in wanted_ids]

    controls = select_matched_controls(
        input_dir=input_dir,
        incidents=incidents,
        controls_per_insider=args.controls_per_insider,
    )
    write_cohort_manifest(manifest_path, incidents, controls)

    cohort = {incident.user_id for incident in incidents} | {match.control_id for match in controls}
    counterpart_ids: set[str] = set()
    for incident in incidents:
        counterpart_ids |= load_incident_detail_user_ids(answers_dir, incident) - cohort
    cohort |= counterpart_ids

    extract_start = None
    extract_end = None
    if args.insider_ids and incidents:
        extract_start = min(incident.start for incident in incidents) - timedelta(days=args.history_days_before)
        extract_end = max(incident.end for incident in incidents) + timedelta(days=args.days_after_incident)

    result = extract_evaluation_stream(
        input_dir=input_dir,
        cohort=cohort,
        output_path=output_path,
        run_size=args.run_size,
        start=extract_start,
        end=extract_end,
    )

    source_summary = ", ".join(f"{source}={count}" for source, count in sorted(result.source_counts.items()))
    print(
        "[PREP] "
        f"incidents={len(incidents)} controls={len(controls)} "
        f"counterparts={sorted(counterpart_ids) or 'none'} "
        f"extract_window={extract_start or 'toàn bộ'}..{extract_end or 'toàn bộ'} "
        f"events={result.event_count} "
        f"range={result.first_event_time}..{result.last_event_time} "
        f"sources={source_summary or 'none'}"
    )
    print(f"[PREP] manifest={manifest_path} output={output_path}")


if __name__ == "__main__":
    configure_console_encoding()
    main()
