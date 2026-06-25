import csv
import json
import math
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from statistics import median


CERT_DATE_FORMAT = "%m/%d/%Y %H:%M:%S"
FEATURE_NAMES = (
    "active_day_count",
    "logon_count",
    "after_hours_ratio",
    "device_connect_count",
    "file_copy_count",
    "email_count",
    "distinct_machine_count",
)


@dataclass(frozen=True)
class Incident:
    scenario: int
    details_file: str
    user_id: str
    start: datetime
    end: datetime


@dataclass
class ActivityProfile:
    user_id: str
    active_days: set[str] = field(default_factory=set)
    logon_count: int = 0
    after_hours_logon_count: int = 0
    device_connect_count: int = 0
    file_copy_count: int = 0
    email_count: int = 0
    machines: set[str] = field(default_factory=set)

    @property
    def vector(self) -> tuple[float, ...]:
        return (
            float(len(self.active_days)),
            float(self.logon_count),
            self.after_hours_logon_count / max(1, self.logon_count),
            float(self.device_connect_count),
            float(self.file_copy_count),
            float(self.email_count),
            float(len(self.machines)),
        )


@dataclass(frozen=True)
class MatchedControl:
    insider_id: str
    control_id: str
    distance: float
    insider_vector: tuple[float, ...]
    control_vector: tuple[float, ...]
    insider_standardized_vector: tuple[float, ...]
    control_standardized_vector: tuple[float, ...]


def load_incidents(path) -> list[Incident]:
    incidents = []
    with Path(path).open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        required_columns = {"dataset", "scenario", "details", "user", "start", "end"}
        _require_columns(
            Path(path).name,
            reader.fieldnames,
            required_columns,
        )
        for row_number, row in enumerate(reader, start=2):
            row = _validate_row(Path(path).name, row_number, row, required_columns)
            if row["dataset"] != "4.2":
                continue
            incidents.append(
                Incident(
                    scenario=int(row["scenario"]),
                    details_file=row["details"],
                    user_id=row["user"],
                    start=_parse_cert_datetime(row["start"]),
                    end=_parse_cert_datetime(row["end"]),
                )
            )
    return sorted(
        incidents,
        key=lambda incident: (
            incident.start,
            incident.end,
            incident.scenario,
            incident.user_id,
            incident.details_file,
        ),
    )


def build_activity_profiles(input_dir) -> dict[str, ActivityProfile]:
    root = Path(input_dir)
    profiles: dict[str, ActivityProfile] = {}

    for source_name, expected_columns, required_nonblank_fields, handler in (
        (
            "logon.csv",
            {"id", "date", "user", "pc", "activity"},
            {"date", "user", "pc", "activity"},
            _handle_logon_row,
        ),
        (
            "device.csv",
            {"id", "date", "user", "pc", "activity"},
            {"date", "user", "pc", "activity"},
            _handle_device_row,
        ),
        (
            "file.csv",
            {"id", "date", "user", "pc", "filename", "content"},
            {"date", "user", "pc", "filename", "content"},
            _handle_file_row,
        ),
        (
            "email.csv",
            {"id", "date", "user", "pc", "to", "cc", "bcc", "from", "size", "attachments", "content"},
            {"date", "user", "pc"},
            _handle_email_row,
        ),
    ):
        source_path = root / source_name
        if not source_path.exists():
            continue
        with source_path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            _require_columns(source_name, reader.fieldnames, expected_columns)
            for row_number, row in enumerate(reader, start=2):
                row = _validate_row(source_name, row_number, row, required_nonblank_fields)
                handler(row, profiles)

    return profiles


def robust_standardize(profile_vectors) -> dict[str, tuple[float, ...]]:
    if not profile_vectors:
        return {}

    ordered_items = _validate_profile_vectors(profile_vectors)
    width = len(ordered_items[0][1])
    columns = [[vector[index] for _, vector in ordered_items] for index in range(width)]
    centers = [median(column) for column in columns]
    scales = []
    for column, center in zip(columns, centers):
        absolute_deviations = [abs(value - center) for value in column]
        scales.append(max(1.0, 1.4826 * median(absolute_deviations)))

    return {
        user_id: tuple((vector[index] - centers[index]) / scales[index] for index in range(width))
        for user_id, vector in ordered_items
    }


def select_matched_controls(
    profiles,
    insider_ids,
    controls_per_insider,
) -> tuple[MatchedControl, ...]:
    insider_ids = set(insider_ids)
    profile_vectors = {user_id: profile.vector for user_id, profile in profiles.items()}
    standardized_vectors = robust_standardize(profile_vectors)
    candidate_ids = sorted(user_id for user_id in profiles if user_id not in insider_ids)
    remaining_candidate_ids = candidate_ids.copy()
    matches: list[MatchedControl] = []

    for insider_id in sorted(insider_ids):
        if insider_id not in profiles:
            raise KeyError(f"Unknown insider profile: {insider_id}")
        for _ in range(controls_per_insider):
            pool = remaining_candidate_ids if remaining_candidate_ids else candidate_ids
            if not pool:
                break
            control_id = min(
                pool,
                key=lambda user_id: (
                    _euclidean_distance(standardized_vectors[insider_id], standardized_vectors[user_id]),
                    user_id,
                ),
            )
            distance = _euclidean_distance(
                standardized_vectors[insider_id],
                standardized_vectors[control_id],
            )
            matches.append(
                MatchedControl(
                    insider_id=insider_id,
                    control_id=control_id,
                    distance=distance,
                    insider_vector=profile_vectors[insider_id],
                    control_vector=profile_vectors[control_id],
                    insider_standardized_vector=standardized_vectors[insider_id],
                    control_standardized_vector=standardized_vectors[control_id],
                )
            )
            if control_id in remaining_candidate_ids:
                remaining_candidate_ids.remove(control_id)

    return tuple(matches)


def write_cohort_manifest(path, incidents, controls) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    incident_features = {}
    for match in controls:
        incident_features.setdefault(
            match.insider_id,
            _selection_features(match.insider_vector, match.insider_standardized_vector),
        )

    payload = {
        "incidents": [
            {
                "details_file": incident.details_file,
                "end": incident.end.isoformat(sep=" "),
                "scenario": incident.scenario,
                "selection_features": incident_features.get(incident.user_id, {}),
                "start": incident.start.isoformat(sep=" "),
                "user_id": incident.user_id,
            }
            for incident in sorted(
                incidents,
                key=lambda item: (item.start, item.end, item.scenario, item.user_id, item.details_file),
            )
        ],
        "controls": [
            {
                "control_id": match.control_id,
                "distance": match.distance,
                "insider_id": match.insider_id,
                "selection_features": _selection_features(
                    match.control_vector,
                    match.control_standardized_vector,
                ),
            }
            for match in controls
        ],
    }

    output_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _handle_logon_row(row, profiles) -> None:
    if row["activity"] != "Logon":
        return
    timestamp = _parse_cert_datetime(row["date"])
    profile = _get_profile(profiles, row["user"])
    _update_profile_context(profile, timestamp, row["pc"])
    profile.logon_count += 1
    if timestamp.hour < 8 or timestamp.hour >= 18:
        profile.after_hours_logon_count += 1


def _handle_device_row(row, profiles) -> None:
    if row["activity"] != "Connect":
        return
    timestamp = _parse_cert_datetime(row["date"])
    profile = _get_profile(profiles, row["user"])
    _update_profile_context(profile, timestamp, row["pc"])
    profile.device_connect_count += 1


def _handle_file_row(row, profiles) -> None:
    timestamp = _parse_cert_datetime(row["date"])
    profile = _get_profile(profiles, row["user"])
    _update_profile_context(profile, timestamp, row["pc"])
    profile.file_copy_count += 1


def _handle_email_row(row, profiles) -> None:
    timestamp = _parse_cert_datetime(row["date"])
    profile = _get_profile(profiles, row["user"])
    _update_profile_context(profile, timestamp, row["pc"])
    profile.email_count += 1


def _get_profile(profiles, user_id) -> ActivityProfile:
    if user_id not in profiles:
        profiles[user_id] = ActivityProfile(user_id=user_id)
    return profiles[user_id]


def _update_profile_context(profile, timestamp, machine_id) -> None:
    profile.active_days.add(timestamp.date().isoformat())
    if machine_id:
        profile.machines.add(machine_id)


def _parse_cert_datetime(value: str) -> datetime:
    return datetime.strptime(value, CERT_DATE_FORMAT)


def _require_columns(source_name, fieldnames, required_columns) -> None:
    fieldnames = fieldnames or []
    missing = sorted(required_columns - set(fieldnames))
    if missing:
        raise ValueError(f"{source_name} missing required columns: {', '.join(missing)}")


def _validate_row(source_name, row_number, row, required_columns):
    extras = row.get(None) or []
    if extras:
        raise ValueError(f"{source_name} row {row_number} has extra columns")

    missing_values = sorted(column for column in required_columns if _is_missing_required_value(row.get(column)))
    if missing_values:
        raise ValueError(
            f"{source_name} row {row_number} missing required values: {', '.join(missing_values)}"
        )
    return row


def _is_missing_required_value(value) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip() == ""
    return False


def _validate_profile_vectors(profile_vectors):
    ordered_items = []
    expected_width = None

    for user_id, values in sorted(profile_vectors.items()):
        vector = tuple(values)
        if expected_width is None:
            expected_width = len(vector)
        elif len(vector) != expected_width:
            raise ValueError(
                f"mixed vector widths: expected {expected_width}, got {len(vector)} for {user_id}"
            )

        normalized_values = []
        for value in vector:
            try:
                normalized_value = float(value)
            except (TypeError, ValueError) as error:
                raise ValueError(f"{user_id} vector must contain finite numeric values") from error
            if not math.isfinite(normalized_value):
                raise ValueError(f"{user_id} vector must contain finite numeric values")
            normalized_values.append(normalized_value)

        ordered_items.append((user_id, tuple(normalized_values)))

    return ordered_items


def _euclidean_distance(left, right) -> float:
    return math.sqrt(sum((left_value - right_value) ** 2 for left_value, right_value in zip(left, right)))


def _selection_features(raw_vector, standardized_vector) -> dict[str, object]:
    return {
        **{name: raw_vector[index] for index, name in enumerate(FEATURE_NAMES)},
        "standardized_vector": list(standardized_vector),
    }
