from __future__ import annotations

import json
import math
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from event_model import Event


UC1_TRIGGER_KINDS = {"LOGON", "DEVICE_CONNECT", "FILE_COPY", "HTTP"}
UC2_TRIGGER_KINDS = {"LOGON", "DEVICE_CONNECT", "FILE_COPY", "HTTP", "EMAIL"}
SECONDS_PER_DAY = 24 * 60 * 60


@dataclass(frozen=True)
class ReplayConfig:
    calibration_days: int = 30
    allowed_lateness_seconds: int = 300
    delay_seconds: float = 0.0
    uc1_fallback_threshold: float = 0.75
    uc2_fallback_threshold: float = 0.75
    prune_after_days: int = 90


@dataclass
class ReplaySummary:
    processed_events: int = 0
    duplicate_events: int = 0
    calibration_events: int = 0
    alerts_persisted: int = 0
    thresholds: dict[str, float] = field(default_factory=dict)
    detector_invocations: dict[str, int] = field(default_factory=lambda: {"uc1": 0, "uc2": 0})
    late_events: int = 0
    recomputed_neighborhoods: int = 0
    processing_seconds: float = 0.0
    throughput_events_per_second: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ReplayEngine:
    def __init__(self, repository, uc1_detector=None, uc2_detector=None, config: ReplayConfig | None = None):
        self.repository = repository
        self.uc1_detector = uc1_detector
        self.uc2_detector = uc2_detector
        self.config = config or ReplayConfig()

    def replay(self, stream_path: Path | str) -> ReplaySummary:
        started = time.perf_counter()
        events, late_events, recomputes = _load_events(Path(stream_path))
        events.sort(key=lambda event: (event.event_ts, event.event_id))

        summary = ReplaySummary(
            thresholds={
                "uc1": self.config.uc1_fallback_threshold,
                "uc2": self.config.uc2_fallback_threshold,
            },
            late_events=late_events,
            recomputed_neighborhoods=recomputes,
        )
        calibration_scores: dict[str, list[float]] = {"uc1": [], "uc2": []}
        calibration_end_ts = None
        thresholds_frozen = self.config.calibration_days <= 0

        for event in events:
            if calibration_end_ts is None:
                calibration_end_ts = event.event_ts + self.config.calibration_days * SECONDS_PER_DAY

            if self.config.delay_seconds > 0:
                time.sleep(self.config.delay_seconds)

            ingest_time = datetime.now(timezone.utc)
            result = self.repository.write_event(event, ingest_time)
            if not getattr(result, "created", False):
                summary.duplicate_events += 1
                continue

            summary.processed_events += 1
            in_calibration = (
                self.config.calibration_days > 0
                and calibration_end_ts is not None
                and event.event_ts < calibration_end_ts
            )
            if in_calibration:
                summary.calibration_events += 1
            elif not thresholds_frozen:
                _freeze_thresholds(summary.thresholds, calibration_scores, self.config)
                thresholds_frozen = True

            self._run_detectors(event, summary, calibration_scores, in_calibration)
            self._prune_if_configured(event)
            if hasattr(self.repository, "update_baselines"):
                self.repository.update_baselines(event)

        if not thresholds_frozen:
            _freeze_thresholds(summary.thresholds, calibration_scores, self.config)

        summary.processing_seconds = time.perf_counter() - started
        summary.throughput_events_per_second = (
            summary.processed_events / summary.processing_seconds
            if summary.processing_seconds > 0
            else 0.0
        )
        return summary

    def _run_detectors(
        self,
        event: Event,
        summary: ReplaySummary,
        calibration_scores: dict[str, list[float]],
        in_calibration: bool,
    ) -> None:
        if self.uc1_detector is not None and event.kind in UC1_TRIGGER_KINDS:
            context = self.repository.fetch_uc1_context(event.user_id, event.event_ts)
            self._score_or_alert(
                detector_key="uc1",
                detector=self.uc1_detector,
                event=event,
                context=context,
                summary=summary,
                calibration_scores=calibration_scores,
                in_calibration=in_calibration,
            )

        if self.uc2_detector is not None and event.kind in UC2_TRIGGER_KINDS:
            context = self.repository.fetch_uc2_context(event.user_id, event.machine_id, event.event_ts)
            self._score_or_alert(
                detector_key="uc2",
                detector=self.uc2_detector,
                event=event,
                context=context,
                summary=summary,
                calibration_scores=calibration_scores,
                in_calibration=in_calibration,
            )

    def _score_or_alert(
        self,
        *,
        detector_key: str,
        detector,
        event: Event,
        context: Mapping[str, Any],
        summary: ReplaySummary,
        calibration_scores: dict[str, list[float]],
        in_calibration: bool,
    ) -> None:
        summary.detector_invocations[detector_key] = summary.detector_invocations.get(detector_key, 0) + 1
        if in_calibration:
            scored = detector.score(event, context)
            calibration_scores[detector_key].append(float(scored.score))
            return

        threshold = summary.thresholds[detector_key]
        alert = detector.evaluate(event, context, threshold)
        if alert is not None:
            self.repository.upsert_alert(alert)
            summary.alerts_persisted += 1

    def _prune_if_configured(self, event: Event) -> None:
        if self.config.prune_after_days <= 0:
            return
        if hasattr(self.repository, "prune_events"):
            self.repository.prune_events(event.event_ts - self.config.prune_after_days * SECONDS_PER_DAY)


def _load_events(stream_path: Path) -> tuple[list[Event], int, int]:
    if not stream_path.exists():
        raise FileNotFoundError(f"stream file not found: {stream_path}")
    events: list[Event] = []
    late_events = 0
    recomputes = 0
    max_seen_ts: int | None = None
    with stream_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                event = Event.from_record(json.loads(stripped))
            except Exception as exc:  # pragma: no cover - message matters more than branch shape
                raise ValueError(f"invalid JSONL event at {stream_path}:{line_number}: {exc}") from exc
            if max_seen_ts is not None and event.event_ts < max_seen_ts:
                late_events += 1
                if max_seen_ts - event.event_ts <= 48 * 60 * 60:
                    recomputes += 1
            max_seen_ts = max(max_seen_ts or event.event_ts, event.event_ts)
            events.append(event)
    return events, late_events, recomputes


def _freeze_thresholds(
    thresholds: dict[str, float],
    calibration_scores: Mapping[str, Iterable[float]],
    config: ReplayConfig,
) -> None:
    thresholds["uc1"] = _percentile_995(calibration_scores.get("uc1", ()), config.uc1_fallback_threshold)
    thresholds["uc2"] = _percentile_995(calibration_scores.get("uc2", ()), config.uc2_fallback_threshold)


def _percentile_995(values: Iterable[float], fallback: float) -> float:
    sorted_values = sorted(float(value) for value in values)
    if not sorted_values:
        return fallback
    index = max(0, min(len(sorted_values) - 1, math.ceil(0.995 * len(sorted_values)) - 1))
    return sorted_values[index]
