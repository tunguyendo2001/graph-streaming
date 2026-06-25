from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from event_model import Event
from graph_repository import AlertRecord
from baselines import score_uc1, logon_hour_anomaly, usb_deviation, domain_novelty


class UC1Detector:
    def evaluate(self, trigger: Event, context: dict, threshold: float) -> AlertRecord | None:
        # Expected context keys:
        # A_hour_counts: dict (historical logon hour counts)
        # U_daily_counts: list (historical daily usb connect counts)
        # U_seen_before: bool
        # F_file_counts: list (historical file counts per session)
        # F_current_count: int
        # D_prior_visits: int
        # C1_stages: dict
        
        # A: Giờ logon lệch baseline cá nhân
        A = 0.0
        if trigger.kind == "LOGON":
            A = logon_hour_anomaly(trigger.event_time.hour, context.get("A_hour_counts", {}))
            
        # U: USB mới hoặc tăng mạnh
        U = 0.0
        if "U_current_daily" in context:
            U = usb_deviation(context["U_current_daily"], context.get("U_daily_counts", []), context.get("U_seen_before", True))
            
        # F: File copy deviation
        F = 0.0
        # In actual implementation this calls robust_deviation
        
        # D: Domain novelty
        D = 0.0
        if trigger.kind == "HTTP":
            D = domain_novelty(context.get("D_prior_visits", 0))
            
        # C1: Motif completeness
        C1 = context.get("C1", 0.0)
        
        S1 = score_uc1(A=A, U=U, F=F, D=D, C1=C1)
        
        if C1 >= 0.60 and U > 0 and S1 >= threshold:
            return AlertRecord(
                alert_id=f"UC1_{trigger.event_id}",
                detector="UC1",
                score=S1,
                threshold=threshold,
                trigger_event_id=trigger.event_id,
                event_time=trigger.event_time,
                components={"A": A, "U": U, "F": F, "D": D, "C1": C1},
                user_ids=(trigger.user_id,),
                machine_ids=(trigger.machine_id,),
                evidence_event_ids=(trigger.event_id,),
                evidence_start_ts=trigger.event_ts,
                evidence_end_ts=trigger.event_ts
            )
        return None

class UC2Detector:
    def evaluate(self, trigger: Event, context: dict, threshold: float) -> AlertRecord | None:
        from baselines import score_uc2
        
        M = context.get("M", 0.0)
        K = context.get("K", 0.0)
        E = context.get("E", 0.0)
        R = context.get("R", 0.0)
        C2 = context.get("C2", 0.0)
        
        S2 = score_uc2(M=M, K=K, E=E, R=R, C2=C2)
        
        if M >= 0.60 and K >= 0.40 and C2 >= 0.50 and S2 >= threshold:
            return AlertRecord(
                alert_id=f"UC2_{trigger.event_id}",
                detector="UC2",
                score=S2,
                threshold=threshold,
                trigger_event_id=trigger.event_id,
                event_time=trigger.event_time,
                components={"M": M, "K": K, "E": E, "R": R, "C2": C2},
                user_ids=(trigger.user_id, context.get("victim_id", trigger.user_id)),
                machine_ids=(trigger.machine_id,),
                evidence_event_ids=(trigger.event_id,),
                evidence_start_ts=trigger.event_ts,
                evidence_end_ts=trigger.event_ts
            )
        return None

