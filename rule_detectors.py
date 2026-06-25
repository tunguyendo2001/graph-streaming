from dataclasses import dataclass
from event_model import Event

@dataclass
class RuleAlert:
    alert_id: str
    detector: str
    trigger_event_id: str
    user_id: str
    machine_id: str
    event_time: float

class RuleUC1Detector:
    def __init__(self):
        self.file_threshold = 20

    def observe(self, event: Event) -> RuleAlert | None:
        if event.kind == "FILE_COPY":
            # Very simplified non-graph rule logic just as an example
            return RuleAlert(f"R_UC1_{event.event_id}", "RuleUC1", event.event_id, event.user_id, event.machine_id, event.event_ts)
        return None

class RuleUC2Detector:
    def __init__(self):
        self.recipient_threshold = 10

    def observe(self, event: Event) -> RuleAlert | None:
        if event.kind == "EMAIL" and event.properties.get("recipient_count", 0) >= self.recipient_threshold:
            return RuleAlert(f"R_UC2_{event.event_id}", "RuleUC2", event.event_id, event.user_id, event.machine_id, event.event_ts)
        return None
