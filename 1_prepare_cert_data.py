import argparse
import sys
from pathlib import Path

from cert_pipeline import TARGET_USERS, prepare_cert_stream


def configure_console_encoding() -> None:
    """
    Đảm bảo log tiếng Việt in được trên Windows console.
    """
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Tiền xử lý CERT r4.2 thành clean_cert_stream.csv nhỏ để stream vào Memgraph."
    )
    parser.add_argument("--input-dir", default="data/cert-r4.2", help="Thư mục đã giải nén CERT r4.2.")
    parser.add_argument("--output", default="clean_cert_stream.csv", help="File CSV sạch đầu ra.")
    parser.add_argument("--max-rows", type=int, default=5000, help="Số event tối đa giữ lại để demo.")
    parser.add_argument("--chunksize", type=int, default=100_000, help="Số dòng đọc mỗi chunk Pandas.")
    parser.add_argument("--synthetic-base-date", default="2010-01-15", help="Ngày dùng để bơm kịch bản demo.")
    args = parser.parse_args()

    print(f"[PREP] Target users: {', '.join(TARGET_USERS)}")
    print("[PREP] Đọc CSV theo chunk để không nạp toàn bộ CERT dataset vào RAM.")

    prepare_cert_stream(
        input_dir=Path(args.input_dir),
        output_csv=Path(args.output),
        max_rows=args.max_rows,
        chunksize=args.chunksize,
        synthetic_base_date=args.synthetic_base_date,
    )


if __name__ == "__main__":
    configure_console_encoding()
    main()
