from dataclasses import dataclass
from pathlib import Path
import json

from event_model import Event
from graph_repository import GraphRepository
from graph_detectors import UC1Detector, UC2Detector

@dataclass
class ReplayConfig:
    calibration_days: int = 30
    allowed_lateness_seconds: int = 300
    delay_seconds: float = 0.0
    uc1_fallback_threshold: float = 0.75
    uc2_fallback_threshold: float = 0.75
    prune_after_days: int = 90

@dataclass
class ReplaySummary:
    event_count: int
    alerts_generated: int

class ReplayEngine:
    def __init__(self, repo: GraphRepository, config: ReplayConfig):
        self.repo = repo
        self.config = config
        self.uc1 = UC1Detector()
        self.uc2 = UC2Detector()

    def replay(self, stream_path: Path) -> ReplaySummary:
        event_count = 0
        alerts = 0
        
        if not stream_path.exists():
            return ReplaySummary(0, 0)
            
        with open(stream_path, "r") as f:
            for line in f:
                record = json.loads(line)
                event = Event.from_record(record)
                
                # Write event
                write_result = self.repo.write_event(event, event.event_time) # using event_time as ingest_time for replay
                
                if not write_result.is_new:
                    continue
                
                # Detect UC1
                if event.kind in ("LOGON", "DEVICE_CONNECT", "FILE_COPY", "HTTP"):
                    ctx1 = self.repo.fetch_uc1_context(event.user_id, event.event_ts)
                    alert1 = self.uc1.evaluate(event, ctx1, self.config.uc1_fallback_threshold)
                    if alert1:
                        self.repo.upsert_alert(alert1)
                        alerts += 1
                        
                # Detect UC2
                if event.kind in ("LOGON", "DEVICE_CONNECT", "FILE_COPY", "HTTP", "EMAIL"):
                    ctx2 = self.repo.fetch_uc2_context(event.user_id, event.machine_id, event.event_ts)
                    alert2 = self.uc2.evaluate(event, ctx2, self.config.uc2_fallback_threshold)
                    if alert2:
                        self.repo.upsert_alert(alert2)
                        alerts += 1
                        
                event_count += 1
                
        return ReplaySummary(event_count, alerts)
