import argparse
import json
from pathlib import Path
from neo4j import GraphDatabase

from graph_repository import GraphRepository
from event_replay import ReplayConfig, ReplayEngine

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stream", required=True, type=Path)
    parser.add_argument("--uri", default="bolt://localhost:7687")
    parser.add_argument("--reset", action="store_true")
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--calibration-days", type=int, default=30)
    parser.add_argument("--allowed-lateness-seconds", type=int, default=300)
    parser.add_argument("--summary", type=Path, default=Path("artifacts/replay_summary.json"))
    args = parser.parse_args()

    driver = GraphDatabase.driver(args.uri, auth=("", ""))
    repo = GraphRepository(driver)
    
    if args.reset:
        repo.reset()
        
    config = ReplayConfig(
        calibration_days=args.calibration_days,
        allowed_lateness_seconds=args.allowed_lateness_seconds,
        delay_seconds=args.delay
    )
    
    engine = ReplayEngine(repo, config)
    summary = engine.replay(args.stream)
    
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    with open(args.summary, "w") as f:
        json.dump({"event_count": summary.event_count, "alerts_generated": summary.alerts_generated}, f, indent=2)

if __name__ == "__main__":
    main()
