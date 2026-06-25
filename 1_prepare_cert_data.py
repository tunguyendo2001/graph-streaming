import argparse
from pathlib import Path

from cert_extractor import (
    build_activity_profiles,
    extract_evaluation_stream,
    load_incidents,
    select_matched_controls,
    write_cohort_manifest,
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", required=True, type=Path)
    parser.add_argument("--answers-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--controls-per-insider", type=int, default=2)
    parser.add_argument("--run-size", type=int, default=50000)
    args = parser.parse_args()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.parent.mkdir(parents=True, exist_ok=True)

    print("Loading incidents...")
    incidents = load_incidents(args.answers_dir / "insiders.csv")
    insider_ids = {i.user_id for i in incidents}

    print("Building activity profiles...")
    profiles = build_activity_profiles(args.input_dir)

    print("Selecting controls...")
    controls = select_matched_controls(profiles, insider_ids, args.controls_per_insider)

    print("Writing manifest...")
    write_cohort_manifest(args.manifest, incidents, controls)

    cohort = insider_ids.union(controls)
    print(f"Extracting evaluation stream for cohort of size {len(cohort)}...")
    result = extract_evaluation_stream(args.input_dir, cohort, args.output, run_size=args.run_size)
    print(f"Extracted {result.event_count} events.")


if __name__ == "__main__":
    main()
