from __future__ import annotations

import math
from statistics import median
from typing import Collection, Iterable, Mapping, Sequence


def clip(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def robust_deviation(current: float, history: Sequence[float]) -> float:
    if not history:
        return 0.0
    center = median(history)
    mad = median(abs(value - center) for value in history)
    denominator = max(1.0, 1.4826 * mad)
    z_plus = max(0.0, (float(current) - center) / denominator)
    return clip(z_plus / 4.0)


def logon_hour_anomaly(hour: int, hour_counts: Mapping[int, int]) -> float:
    if hour not in range(24):
        raise ValueError("hour must be in range(24)")
    total = sum(hour_counts.values())
    smoothed = {
        candidate: (hour_counts.get(candidate, 0) + 1) / (total + 24)
        for candidate in range(24)
    }
    return clip(1.0 - (smoothed[hour] / max(smoothed.values())))


def usb_deviation(current_daily_count: int, daily_history: Sequence[int], *, seen_before: bool) -> float:
    new_usb = 0.0 if seen_before else 1.0
    return max(new_usb, robust_deviation(current_daily_count, daily_history))


def domain_novelty(prior_visits: int) -> float:
    return 1.0 / math.sqrt(1.0 + max(0, prior_visits))


def social_neighborhood_novelty(current: Collection[str], historical: Collection[str]) -> float:
    current_set = set(current)
    if not current_set:
        return 0.0
    return len(current_set - set(historical)) / len(current_set)


def email_fanout_deviation(
    current_email_count: int,
    current_window_count: int,
    per_email_history: Sequence[int],
    window_history: Sequence[int],
) -> float:
    return max(
        robust_deviation(current_email_count, per_email_history),
        robust_deviation(current_window_count, window_history),
    )


def time_decay(duration_seconds: float, horizon_seconds: float) -> float:
    if horizon_seconds <= 0:
        raise ValueError("horizon_seconds must be positive")
    return math.exp(-max(0.0, float(duration_seconds)) / float(horizon_seconds))


def weighted_coverage(stages: Mapping[str, bool], weights: Mapping[str, float]) -> float:
    missing = [stage for stage in stages if stage not in weights]
    if missing:
        missing_list = ", ".join(sorted(missing))
        raise ValueError(f"missing weights for stages: {missing_list}")
    return clip(sum(float(weights[stage]) for stage, present in stages.items() if present))


def temporal_order(event_times: Iterable[tuple[int | None, int | None]]) -> float:
    comparable = [
        (left, right)
        for left, right in event_times
        if left is not None and right is not None
    ]
    if not comparable:
        return 0.0
    in_order = sum(1 for left, right in comparable if left <= right)
    return in_order / len(comparable)


def score_uc1(*, A: float, U: float, F: float, D: float, C1: float) -> float:
    return clip(0.20 * A + 0.25 * U + 0.25 * F + 0.15 * D + 0.15 * C1)


def score_uc2(*, M: float, K: float, E: float, R: float, C2: float) -> float:
    return clip(0.25 * M + 0.25 * K + 0.20 * E + 0.15 * R + 0.15 * C2)
