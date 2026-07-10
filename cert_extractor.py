import csv
import heapq
import json
import math
import tempfile
from contextlib import ExitStack
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from statistics import median

from event_model import parse_cert_row


CERT_DATE_FORMAT = "%m/%d/%Y %H:%M:%S"
INCIDENT_COLUMNS = ("dataset", "scenario", "details", "user", "start", "end")
LOGON_COLUMNS = ("id", "date", "user", "pc", "activity")
DEVICE_COLUMNS = ("id", "date", "user", "pc", "activity")
FILE_COLUMNS = ("id", "date", "user", "pc", "filename", "content")
HTTP_COLUMNS = ("id", "date", "user", "pc", "url", "content")
EMAIL_COLUMNS = (
    "id",
    "date",
    "user",
    "pc",
    "to",
    "cc",
    "bcc",
    "from",
    "size",
    "attachments",
    "content",
)
EVENT_SOURCE_FILES = ("logon.csv", "device.csv", "file.csv", "http.csv", "email.csv")
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


@dataclass(frozen=True)
class ExtractionResult:
    event_count: int
    first_event_time: int | None
    last_event_time: int | None
    source_counts: dict[str, int]


def load_incidents(path) -> list[Incident]:
    incidents = []
    source_name = Path(path).name
    with Path(path).open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        _require_columns(source_name, reader.fieldnames, INCIDENT_COLUMNS)
        for row_number, row in enumerate(reader, start=2):
            row = _validate_row(source_name, row_number, row, INCIDENT_COLUMNS)
            if row["dataset"] != "4.2":
                continue
            incidents.append(
                Incident(
                    scenario=int(row["scenario"]),
                    details_file=row["details"],
                    user_id=row["user"],
                    start=_parse_cert_datetime(row["start"], source_name, row_number, "start"),
                    end=_parse_cert_datetime(row["end"], source_name, row_number, "end"),
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


def _activity_sources():
    return (
        (
            "logon.csv",
            LOGON_COLUMNS,
            {"date", "user", "pc", "activity"},
            _handle_logon_row,
        ),
        (
            "device.csv",
            DEVICE_COLUMNS,
            {"date", "user", "pc", "activity"},
            _handle_device_row,
        ),
        (
            "file.csv",
            FILE_COLUMNS,
            {"date", "user", "pc", "filename", "content"},
            _handle_file_row,
        ),
        (
            "email.csv",
            EMAIL_COLUMNS,
            {"id", "date", "user", "pc", "from", "size", "attachments"},
            _handle_email_row,
        ),
    )


def _collect_activity_user_ids(input_dir) -> set[str]:
    root = Path(input_dir)
    user_ids: set[str] = set()

    for source_name, expected_columns, required_nonblank_fields, _handler in _activity_sources():
        source_path = root / source_name
        if not source_path.exists():
            continue
        with source_path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            _require_columns(source_name, reader.fieldnames, expected_columns)
            for row_number, row in enumerate(reader, start=2):
                row = _validate_row(source_name, row_number, row, required_nonblank_fields)
                _parse_cert_datetime(row["date"], source_name, row_number, "date")
                user_ids.add(row["user"])

    return user_ids


def build_activity_profiles(input_dir, *, before: datetime | None = None, user_ids=None) -> dict[str, ActivityProfile]:
    root = Path(input_dir)
    profiles: dict[str, ActivityProfile] = {
        user_id: ActivityProfile(user_id=user_id) for user_id in sorted(set(user_ids or ()))
    }

    for source_name, expected_columns, required_nonblank_fields, handler in _activity_sources():
        source_path = root / source_name
        if not source_path.exists():
            continue
        with source_path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            _require_columns(source_name, reader.fieldnames, expected_columns)
            for row_number, row in enumerate(reader, start=2):
                row = _validate_row(source_name, row_number, row, required_nonblank_fields)
                timestamp = _parse_cert_datetime(row["date"], source_name, row_number, "date")
                if before is not None and timestamp >= before:
                    continue
                handler(row, profiles, timestamp)

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
    profiles_or_input_dir=None,
    insider_ids_or_incidents=None,
    controls_per_insider=None,
    *,
    profiles=None,
    insider_ids=None,
    incidents=None,
    input_dir=None,
) -> tuple[MatchedControl, ...]:
    positional_arguments_used = (
        profiles_or_input_dir is not None or insider_ids_or_incidents is not None
    )
    profile_keyword_arguments_used = profiles is not None or insider_ids is not None
    incident_keyword_arguments_used = input_dir is not None or incidents is not None

    if profile_keyword_arguments_used and incident_keyword_arguments_used:
        raise TypeError(
            "select_matched_controls cannot mix profile-based and incident-aware keyword aliases"
        )

    if profile_keyword_arguments_used or incident_keyword_arguments_used:
        if positional_arguments_used:
            raise TypeError(
                "select_matched_controls accepts either positional arguments or keyword aliases, not both"
            )
        if profile_keyword_arguments_used:
            if profiles is None or insider_ids is None:
                raise TypeError(
                    "profile-based matching requires profiles and insider_ids"
                )
            profiles_or_input_dir = profiles
            insider_ids_or_incidents = insider_ids
        else:
            if input_dir is None or incidents is None:
                raise TypeError(
                    "incident-aware matching requires input_dir and incidents"
                )
            profiles_or_input_dir = input_dir
            insider_ids_or_incidents = incidents

    if controls_per_insider is None:
        raise TypeError("controls_per_insider is required")
    if profiles_or_input_dir is None or insider_ids_or_incidents is None:
        raise TypeError("select_matched_controls requires profiles/input_dir and insider ids/incidents")

    insiders_or_incidents = tuple(insider_ids_or_incidents)
    if not insiders_or_incidents:
        return ()
    if _is_incident_collection(insiders_or_incidents):
        if isinstance(profiles_or_input_dir, Mapping):
            raise TypeError(
                "incident-aware matching requires an input directory so activity can be "
                "rebuilt before each incident cutoff"
            )
        return _select_incident_matched_controls(
            profiles_or_input_dir,
            insiders_or_incidents,
            controls_per_insider,
        )

    return _select_profile_matched_controls(
        profiles_or_input_dir,
        insiders_or_incidents,
        controls_per_insider,
    )


def _is_incident_collection(items) -> bool:
    return all(isinstance(item, Incident) for item in items)


def _select_profile_matched_controls(
    profiles,
    insider_ids,
    controls_per_insider,
) -> tuple[MatchedControl, ...]:
    if not isinstance(profiles, Mapping):
        raise TypeError("profile-based matching requires a mapping of ActivityProfile objects")

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


def _profile_has_activity(profile: ActivityProfile) -> bool:
    return any(value != 0.0 for value in profile.vector)


def _select_incident_matched_controls(
    input_dir,
    incidents: tuple[Incident, ...],
    controls_per_insider,
) -> tuple[MatchedControl, ...]:
    if isinstance(input_dir, Mapping):
        raise TypeError(
            "incident-aware matching requires an input directory so activity can be "
            "rebuilt before each incident cutoff"
        )

    earliest_cutoffs: dict[str, datetime] = {}
    for incident in incidents:
        existing_cutoff = earliest_cutoffs.get(incident.user_id)
        if existing_cutoff is None or incident.start < existing_cutoff:
            earliest_cutoffs[incident.user_id] = incident.start

    if not earliest_cutoffs:
        return ()

    insider_ids = set(earliest_cutoffs)
    activity_user_ids = _collect_activity_user_ids(input_dir) | insider_ids
    candidate_ids = sorted(activity_user_ids - insider_ids)
    remaining_candidate_ids = candidate_ids.copy()
    matches: list[MatchedControl] = []
    profiles_by_cutoff: dict[datetime, dict[str, ActivityProfile]] = {}

    for insider_id in sorted(insider_ids, key=lambda user_id: (earliest_cutoffs[user_id], user_id)):
        cutoff = earliest_cutoffs[insider_id]
        profiles = profiles_by_cutoff.get(cutoff)
        if profiles is None:
            profiles = build_activity_profiles(
                input_dir,
                before=cutoff,
                user_ids=activity_user_ids,
            )
            profiles_by_cutoff[cutoff] = profiles
        eligible_candidate_ids = [
            user_id for user_id in candidate_ids if _profile_has_activity(profiles[user_id])
        ]
        eligible_candidate_id_set = set(eligible_candidate_ids)
        profile_ids = sorted(eligible_candidate_id_set | {insider_id})
        profile_vectors = {user_id: profiles[user_id].vector for user_id in profile_ids}
        standardized_vectors = robust_standardize(profile_vectors)

        for _ in range(controls_per_insider):
            pool = [
                user_id
                for user_id in remaining_candidate_ids
                if user_id in eligible_candidate_id_set
            ]
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

    incidents = tuple(incidents)
    controls = tuple(controls)
    incident_features = {}
    for match in controls:
        incident_features.setdefault(
            match.insider_id,
            _selection_features(match.insider_vector, match.insider_standardized_vector),
        )
    missing_feature_users = sorted(
        {incident.user_id for incident in incidents} - set(incident_features)
    )
    if missing_feature_users:
        raise ValueError(
            "missing selection features for incident users: "
            + ", ".join(missing_feature_users)
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


def load_incident_detail_user_ids(answers_dir, incident: Incident) -> set[str]:
    """
    Đọc file ground-truth chi tiết của 1 incident (answers/r4.2-<scenario>/<details_file>)
    và trả về mọi user_id xuất hiện trong đó. Với motif nhiều identity (vd UC2 credential
    pivot, insider đăng nhập lên máy người khác rồi email fan-out từ danh tính nạn nhân),
    chỉ đưa insider vào cohort là không đủ: thiếu hoạt động thật của nạn nhân thì Memgraph
    không có baseline "ai thường dùng máy này" / "ai thường nhận mail từ ai" để so sánh, nên
    motif sẽ không bao giờ đủ điều kiện bắn alert dù có insider trong graph.
    """
    detail_path = Path(answers_dir) / f"r4.2-{incident.scenario}" / incident.details_file
    user_ids = {incident.user_id}
    if not detail_path.exists():
        return user_ids
    with detail_path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.reader(handle):
            if len(row) > 3 and row[3].strip():
                user_ids.add(row[3].strip())
    return user_ids


def iter_source_events(source_path, source, cohort, *, start=None, end=None):
    source_path = Path(source_path)
    cohort = {str(user_id) for user_id in cohort}
    if not source_path.exists():
        raise FileNotFoundError(f"required CERT source file is missing: {source_path}")

    expected_columns, required_columns = _source_event_spec(source)
    with source_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        _require_columns(source_path.name, reader.fieldnames, expected_columns)
        for row_number, row in enumerate(reader, start=2):
            user_id = row["user"]
            if user_id not in cohort:
                continue
            row = _validate_row(source_path.name, row_number, row, required_columns)
            timestamp = _parse_cert_datetime(row["date"], source_path.name, row_number, "date")
            if start is not None and timestamp < start:
                continue
            if end is not None and timestamp > end:
                continue
            yield _normalize_source_event(source, row, timestamp)


def _require_event_sources(input_dir: Path) -> None:
    for source_name in EVENT_SOURCE_FILES:
        source_path = input_dir / source_name
        if not source_path.exists():
            raise FileNotFoundError(f"required CERT source file is missing: {source_path}")


def write_sorted_runs(events, temporary_dir, run_size):
    if run_size <= 0:
        raise ValueError("run_size must be greater than 0")

    temporary_dir = Path(temporary_dir)
    temporary_dir.mkdir(parents=True, exist_ok=True)

    run_paths: list[Path] = []
    batch: list[dict[str, object]] = []
    for event in events:
        batch.append(event)
        if len(batch) >= run_size:
            run_paths.append(_write_sorted_run(batch, temporary_dir, len(run_paths)))
            batch = []

    if batch:
        run_paths.append(_write_sorted_run(batch, temporary_dir, len(run_paths)))

    return run_paths


def merge_jsonl_runs(run_paths, output_path):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    event_count = 0
    first_event_time: int | None = None
    last_event_time: int | None = None
    source_counts: dict[str, int] = {}

    with ExitStack() as stack:
        iterators = [
            _jsonl_event_iterator(stack.enter_context(Path(run_path).open("r", encoding="utf-8")))
            for run_path in run_paths
        ]
        with output_path.open("w", encoding="utf-8") as output_handle:
            for event in heapq.merge(
                *iterators,
                key=lambda record: (record["event_ts"], record["event_id"]),
            ):
                output_handle.write(json.dumps(event, separators=(",", ":"), sort_keys=True, ensure_ascii=False))
                output_handle.write("\n")
                event_count += 1
                event_ts = event["event_ts"]
                if first_event_time is None:
                    first_event_time = event_ts
                last_event_time = event_ts
                source = event["source"]
                source_counts[source] = source_counts.get(source, 0) + 1

    return ExtractionResult(
        event_count=event_count,
        first_event_time=first_event_time,
        last_event_time=last_event_time,
        source_counts=source_counts,
    )


def extract_evaluation_stream(input_dir, cohort, output_path, run_size=50000, *, start=None, end=None) -> ExtractionResult:
    input_dir = Path(input_dir)
    output_path = Path(output_path)
    cohort = {str(user_id) for user_id in cohort}

    if run_size <= 0:
        raise ValueError("run_size must be greater than 0")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    _require_event_sources(input_dir)

    events = (
        event
        for source_name in EVENT_SOURCE_FILES
        for event in iter_source_events(input_dir / source_name, source_name[:-4], cohort, start=start, end=end)
    )

    temp_parent = output_path.parent if output_path.parent != Path("") else None
    with tempfile.TemporaryDirectory(dir=temp_parent, prefix=f".{output_path.stem}-runs-") as temporary_dir:
        temporary_dir = Path(temporary_dir)
        run_paths = write_sorted_runs(events, temporary_dir, run_size)
        return merge_jsonl_runs(run_paths, output_path)


def _handle_logon_row(row, profiles, timestamp) -> None:
    if row["activity"] != "Logon":
        return
    profile = _get_profile(profiles, row["user"])
    _update_profile_context(profile, timestamp, row["pc"])
    profile.logon_count += 1
    if timestamp.hour < 8 or timestamp.hour >= 18:
        profile.after_hours_logon_count += 1


def _handle_device_row(row, profiles, timestamp) -> None:
    if row["activity"] != "Connect":
        return
    profile = _get_profile(profiles, row["user"])
    _update_profile_context(profile, timestamp, row["pc"])
    profile.device_connect_count += 1


def _handle_file_row(row, profiles, timestamp) -> None:
    profile = _get_profile(profiles, row["user"])
    _update_profile_context(profile, timestamp, row["pc"])
    profile.file_copy_count += 1


def _handle_email_row(row, profiles, timestamp) -> None:
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


def _parse_cert_datetime(value: str, source_name: str, row_number: int, column_name: str) -> datetime:
    try:
        return datetime.strptime(value, CERT_DATE_FORMAT)
    except ValueError as exc:
        raise ValueError(
            f"{source_name} row {row_number} column {column_name} "
            f"has invalid timestamp {value!r}; expected {CERT_DATE_FORMAT}"
        ) from exc


def _require_columns(source_name, fieldnames, expected_columns) -> None:
    fieldnames = fieldnames or []
    if tuple(fieldnames) != tuple(expected_columns):
        expected = ", ".join(expected_columns)
        actual = ", ".join(fieldnames) if fieldnames else "<none>"
        raise ValueError(
            f"{source_name} header must match official CERT fields: "
            f"expected {expected}; got {actual}"
        )


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


def _source_event_spec(source: str):
    if source == "logon":
        return LOGON_COLUMNS, {"id", "date", "user", "pc", "activity"}
    if source == "device":
        return DEVICE_COLUMNS, {"id", "date", "user", "pc", "activity"}
    if source == "file":
        return FILE_COLUMNS, {"id", "date", "user", "pc", "filename", "content"}
    if source == "http":
        return HTTP_COLUMNS, {"id", "date", "user", "pc", "url"}
    if source == "email":
        return EMAIL_COLUMNS, {"id", "date", "user", "pc", "from", "size", "attachments"}
    raise ValueError(f"unknown source: {source}")


def _normalize_source_event(source: str, row: dict[str, str], timestamp: datetime) -> dict[str, object]:
    event = parse_cert_row(source, {**row, "date": timestamp.strftime(CERT_DATE_FORMAT)})
    event_record = event.to_record()
    properties = event_record.pop("properties")
    return {
        **event_record,
        "action": event.kind,
        "pc": event.machine_id,
        **properties,
    }


def _write_sorted_run(events, temporary_dir: Path, run_index: int) -> Path:
    sorted_events = sorted(events, key=lambda event: (event["event_ts"], event["event_id"]))
    run_path = temporary_dir / f"run-{run_index:06d}.jsonl"
    with run_path.open("w", encoding="utf-8") as handle:
        for event in sorted_events:
            handle.write(json.dumps(event, separators=(",", ":"), sort_keys=True, ensure_ascii=False))
            handle.write("\n")
    return run_path


def _jsonl_event_iterator(handle):
    for line in handle:
        if line.strip():
            yield json.loads(line)
