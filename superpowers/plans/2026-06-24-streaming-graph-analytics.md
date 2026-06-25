# Streaming Graph Analytics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the synthetic CERT demo with a resource-bounded Python + Memgraph pipeline that replays real CERT r4.2 events, performs incremental temporal-motif detection, and compares graph detection with flat rules using the official ground truth.

**Architecture:** A streaming extractor builds a reproducible cohort of all 70 r4.2 incidents plus matched real controls and writes an event-time JSONL stream without loading source files into memory. The replay process writes immutable events and inferred sessions to Memgraph, queries only the affected graph neighborhood, calculates explainable UC1/UC2 scores, persists alerts with evidence paths, and evaluates them only after replay against `answers/`.

**Tech Stack:** Python 3.11+, standard-library CSV/JSON/heapq/statistics, Neo4j Python driver, Memgraph Platform, `unittest`, `psutil`.

---

## File map

| Path | Responsibility |
|---|---|
| `event_model.py` | Immutable event type, parsing, serialization and lexical signals |
| `baselines.py` | Median/MAD normalization, novelty, decay and UC component formulas |
| `cert_extractor.py` | Ground-truth loading, activity profiles, control matching, external merge extraction |
| `graph_repository.py` | Idempotent event writes, sessionization, aggregate edges and evidence persistence |
| `graph_detectors.py` | Incremental UC1/UC2 candidate traversal and scoring |
| `rule_detectors.py` | Flat non-graph comparison rules |
| `event_replay.py` | Event-time replay, watermark handling, detector orchestration and metrics |
| `evaluation.py` | Ground-truth matching and metric reporting |
| `1_prepare_cert_data.py` | CLI wrapper for cohort/extraction |
| `2_stream_cert.py` | CLI wrapper for replay/detection |
| `init_schema.cypher` | Memgraph indexes for the temporal schema |
| `queries/uc1_evidence.cypher` | UC1 neighborhood and visualization query |
| `queries/uc2_evidence.cypher` | UC2 multi-identity evidence query |
| `queries/alerts.cypher` | Alert inspection query |
| `tests/fixtures/` | Small real-schema CSV fixtures and incident observables |
| `tests/test_event_model.py` | Parser tests |
| `tests/test_baselines.py` | Formula tests |
| `tests/test_cert_extractor.py` | Cohort and external-merge tests |
| `tests/test_graph_repository.py` | Query/session behavior tests with a recording transaction |
| `tests/test_graph_repository_integration.py` | Memgraph integration tests |
| `tests/test_graph_detectors.py` | Incremental detector tests |
| `tests/test_rule_detectors.py` | Rule baseline tests |
| `tests/test_evaluation.py` | Ground-truth metric tests |
| `tests/test_event_replay.py` | Replay ordering and no-baseline-leakage tests |

Remove obsolete synthetic artifacts after replacement tests are green:

```text
cert_pipeline.py
tests/test_cert_pipeline.py
clean_cert_stream.csv
show_logon_usb_copy_secret.cypher
```

Replace `cert_queries.cypher` with the focused files under `queries/`.

---

### Task 1: Define the normalized real-event model

**Files:**
- Create: `event_model.py`
- Create: `tests/test_event_model.py`
- Modify: `requirements.txt`

- [ ] **Step 1: Write failing parser tests**

Create `tests/test_event_model.py`:

```python
import unittest
from datetime import datetime

from event_model import Event, parse_cert_row


class EventModelTest(unittest.TestCase):
    def test_file_row_is_a_real_removable_media_copy(self):
        event = parse_cert_row(
            "file",
            {
                "id": "{F1}",
                "date": "08/12/2010 14:54:16",
                "user": "BBS0039",
                "pc": "PC-9436",
                "filename": "GGX5KL22.exe",
                "content": "must not be retained",
            },
        )

        self.assertEqual(event.event_id, "file:{F1}")
        self.assertEqual(event.kind, "FILE_COPY")
        self.assertEqual(event.user_id, "BBS0039")
        self.assertEqual(event.machine_id, "PC-9436")
        self.assertEqual(event.properties, {"filename": "GGX5KL22.exe", "extension": ".exe"})
        self.assertNotIn("content", event.to_record())

    def test_email_row_flattens_all_unique_recipients(self):
        event = parse_cert_row(
            "email",
            {
                "id": "{E1}",
                "date": "08/13/2010 19:01:01",
                "user": "FAW0032",
                "pc": "PC-5866",
                "to": "a@dtaa.com;b@dtaa.com",
                "cc": "b@dtaa.com;c@outside.net",
                "bcc": "",
                "from": "victim@dtaa.com",
                "size": "18004",
                "attachments": "0",
                "content": "discard",
            },
        )

        self.assertEqual(event.kind, "EMAIL")
        self.assertEqual(event.properties["recipients"], ["a@dtaa.com", "b@dtaa.com", "c@outside.net"])
        self.assertEqual(event.properties["recipient_count"], 3)

    def test_http_row_extracts_domain_and_keylogger_signal(self):
        event = parse_cert_row(
            "http",
            {
                "id": "{H1}",
                "date": "08/12/2010 13:42:15",
                "user": "BBS0039",
                "pc": "PC-9436",
                "url": "http://www.dailykeylogger.com/review.html",
                "content": "discard",
            },
        )

        self.assertEqual(event.properties["domain"], "dailykeylogger.com")
        self.assertTrue(event.properties["keylogger_signal"])
        self.assertEqual(event.event_time, datetime(2010, 8, 12, 13, 42, 15))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests and verify RED**

Run:

```powershell
python -m unittest tests.test_event_model -v
```

Expected: import failure for missing `event_model`.

- [ ] **Step 3: Implement the event model**

Create `event_model.py` with:

```python
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

CERT_TIME_FORMAT = "%m/%d/%Y %H:%M:%S"

KEYLOGGER_TERMS = ("keylogger", "spectorsoft", "keystroke", "monitoring")
JOB_TERMS = ("monster.com", "careerbuilder", "job", "resume", "linkedin")
LEAK_TERMS = ("wikileaks", "pastebin")
CLOUD_TERMS = ("dropbox", "drive.google", "box.com", "onedrive")


@dataclass(frozen=True)
class Event:
    event_id: str
    source: str
    kind: str
    event_time: datetime
    user_id: str
    machine_id: str
    properties: dict[str, Any] = field(default_factory=dict)

    @property
    def event_ts(self) -> int:
        return int(self.event_time.replace(tzinfo=timezone.utc).timestamp())

    def to_record(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "source": self.source,
            "kind": self.kind,
            "event_time": self.event_time.isoformat(sep=" "),
            "event_ts": self.event_ts,
            "user_id": self.user_id,
            "machine_id": self.machine_id,
            "properties": self.properties,
        }

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> "Event":
        return cls(
            event_id=record["event_id"],
            source=record["source"],
            kind=record["kind"],
            event_time=datetime.fromisoformat(record["event_time"]),
            user_id=record["user_id"],
            machine_id=record["machine_id"],
            properties=dict(record.get("properties", {})),
        )


def _split_addresses(*values: str) -> list[str]:
    addresses = {
        address.strip().lower()
        for value in values
        for address in (value or "").split(";")
        if address.strip()
    }
    return sorted(addresses)


def _domain(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


def _contains(value: str, terms: tuple[str, ...]) -> bool:
    lowered = value.lower()
    return any(term in lowered for term in terms)


def parse_cert_row(source: str, row: dict[str, str]) -> Event:
    event_time = datetime.strptime(row["date"], CERT_TIME_FORMAT)
    common = dict(
        event_id=f"{source}:{row['id']}",
        source=source,
        event_time=event_time,
        user_id=row["user"],
        machine_id=row["pc"],
    )

    if source == "logon":
        activity = row["activity"].upper()
        return Event(kind=activity, properties={"activity": activity}, **common)

    if source == "device":
        activity = row["activity"].upper()
        kind = "DEVICE_CONNECT" if activity == "CONNECT" else "DEVICE_DISCONNECT"
        return Event(kind=kind, properties={"activity": activity}, **common)

    if source == "file":
        filename = row["filename"]
        return Event(
            kind="FILE_COPY",
            properties={"filename": filename, "extension": Path(filename).suffix.lower()},
            **common,
        )

    if source == "http":
        url = row["url"]
        domain = _domain(url)
        searchable = f"{domain} {url}"
        return Event(
            kind="HTTP",
            properties={
                "url": url,
                "domain": domain,
                "keylogger_signal": _contains(searchable, KEYLOGGER_TERMS),
                "job_signal": _contains(searchable, JOB_TERMS),
                "leak_signal": _contains(searchable, LEAK_TERMS),
                "cloud_signal": _contains(searchable, CLOUD_TERMS),
            },
            **common,
        )

    if source == "email":
        recipients = _split_addresses(row.get("to", ""), row.get("cc", ""), row.get("bcc", ""))
        return Event(
            kind="EMAIL",
            properties={
                "sender": row.get("from", "").strip().lower(),
                "recipients": recipients,
                "recipient_count": len(recipients),
                "size": int(row.get("size") or 0),
                "attachments": int(row.get("attachments") or 0),
            },
            **common,
        )

    raise ValueError(f"Unsupported CERT source: {source}")
```

Update `requirements.txt`:

```text
neo4j>=5.20.0
psutil>=5.9.0
```

- [ ] **Step 4: Run tests and verify GREEN**

Run:

```powershell
python -m unittest tests.test_event_model -v
```

Expected: 3 tests pass.

- [ ] **Step 5: Commit**

```powershell
git add event_model.py tests/test_event_model.py requirements.txt
git commit -m "feat(events): parse real CERT activity"
```

---

### Task 2: Implement the approved score formulas as pure functions

**Files:**
- Create: `baselines.py`
- Create: `tests/test_baselines.py`

- [ ] **Step 1: Write failing formula tests**

Create `tests/test_baselines.py` covering exact approved behavior:

```python
import math
import unittest

from baselines import (
    domain_novelty,
    email_fanout_deviation,
    logon_hour_anomaly,
    robust_deviation,
    score_uc1,
    score_uc2,
    social_neighborhood_novelty,
    time_decay,
    usb_deviation,
)


class BaselineFormulaTest(unittest.TestCase):
    def test_robust_deviation_caps_at_one(self):
        self.assertEqual(robust_deviation(100, [1, 1, 2, 2, 3]), 1.0)
        self.assertEqual(robust_deviation(2, [1, 1, 2, 2, 3]), 0.0)

    def test_unseen_logon_hour_is_more_anomalous(self):
        counts = {8: 20, 9: 10}
        self.assertGreater(logon_hour_anomaly(2, counts), logon_hour_anomaly(8, counts))

    def test_new_usb_is_maximally_novel(self):
        self.assertEqual(usb_deviation(1, [], seen_before=False), 1.0)

    def test_domain_novelty_decays_with_prior_visits(self):
        self.assertEqual(domain_novelty(0), 1.0)
        self.assertAlmostEqual(domain_novelty(3), 0.5)

    def test_social_neighborhood_novelty_is_set_difference_ratio(self):
        self.assertEqual(
            social_neighborhood_novelty({"a", "b", "c"}, {"a"}),
            2 / 3,
        )

    def test_time_decay_uses_exponential_decay(self):
        self.assertAlmostEqual(time_decay(8 * 3600, 8 * 3600), math.exp(-1))

    def test_weighted_scores_match_approved_formulas(self):
        self.assertAlmostEqual(score_uc1(A=1, U=1, F=1, D=1, C1=1), 1.0)
        self.assertAlmostEqual(score_uc2(M=1, K=1, E=1, R=1, C2=1), 1.0)
```

- [ ] **Step 2: Run tests and verify RED**

Run:

```powershell
python -m unittest tests.test_baselines -v
```

Expected: import failure for missing `baselines`.

- [ ] **Step 3: Implement formulas**

Create `baselines.py`:

```python
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
    z_plus = max(0.0, (current - center) / max(1.0, 1.4826 * mad))
    return clip(z_plus / 4.0)


def logon_hour_anomaly(hour: int, hour_counts: Mapping[int, int]) -> float:
    total = sum(hour_counts.values())
    probabilities = {candidate: (hour_counts.get(candidate, 0) + 1) / (total + 24) for candidate in range(24)}
    return clip(1.0 - probabilities[hour] / max(probabilities.values()))


def usb_deviation(current_daily_count: int, daily_history: Sequence[int], seen_before: bool) -> float:
    new_usb = 0.0 if seen_before else 1.0
    return max(new_usb, robust_deviation(current_daily_count, daily_history))


def domain_novelty(prior_visits: int) -> float:
    return 1.0 / math.sqrt(1.0 + max(0, prior_visits))


def social_neighborhood_novelty(current: Collection[str], historical: Collection[str]) -> float:
    current_set = set(current)
    if not current_set:
        return 0.0
    return 1.0 - len(current_set & set(historical)) / len(current_set)


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
    return math.exp(-max(0.0, duration_seconds) / horizon_seconds)


def weighted_coverage(stages: Mapping[str, bool], weights: Mapping[str, float]) -> float:
    return sum(weights[name] for name, present in stages.items() if present)


def temporal_order(event_times: Iterable[tuple[int | None, int | None]]) -> float:
    comparable = [(left, right) for left, right in event_times if left is not None and right is not None]
    if not comparable:
        return 0.0
    return sum(left <= right for left, right in comparable) / len(comparable)


def score_uc1(*, A: float, U: float, F: float, D: float, C1: float) -> float:
    return clip(0.20 * A + 0.25 * U + 0.25 * F + 0.15 * D + 0.15 * C1)


def score_uc2(*, M: float, K: float, E: float, R: float, C2: float) -> float:
    return clip(0.25 * M + 0.25 * K + 0.20 * E + 0.15 * R + 0.15 * C2)
```

- [ ] **Step 4: Run tests and verify GREEN**

Run:

```powershell
python -m unittest tests.test_baselines -v
```

Expected: all formula tests pass.

- [ ] **Step 5: Commit**

```powershell
git add baselines.py tests/test_baselines.py
git commit -m "feat(scoring): add graph anomaly formulas"
```

---

### Task 3: Load real incidents and select matched real controls

**Files:**
- Create: `cert_extractor.py`
- Create: `tests/test_cert_extractor.py`
- Create: `tests/fixtures/answers/insiders.csv`
- Create: `tests/fixtures/logon.csv`
- Create: `tests/fixtures/device.csv`
- Create: `tests/fixtures/file.csv`
- Create: `tests/fixtures/email.csv`

- [ ] **Step 1: Write failing cohort tests**

Tests must assert:

```python
def test_load_incidents_keeps_only_dataset_4_2():
    incidents = load_incidents(FIXTURES / "answers" / "insiders.csv")
    assert {item.user_id for item in incidents} == {"INSIDER1", "INSIDER2"}


def test_controls_never_include_ground_truth_users():
    controls = select_matched_controls(
        profiles=fixture_profiles(),
        insider_ids={"INSIDER1", "INSIDER2"},
        controls_per_insider=2,
    )
    assert not set(controls) & {"INSIDER1", "INSIDER2"}


def test_control_selection_is_deterministic():
    first = select_matched_controls(fixture_profiles(), {"INSIDER1"}, 2)
    second = select_matched_controls(fixture_profiles(), {"INSIDER1"}, 2)
    assert first == second
```

Use `unittest.TestCase` assertions in the actual file.

- [ ] **Step 2: Run tests and verify RED**

Run:

```powershell
python -m unittest tests.test_cert_extractor.CohortSelectionTest -v
```

Expected: missing extractor APIs.

- [ ] **Step 3: Implement incident loading and matching**

Add these public APIs to `cert_extractor.py`:

```python
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
    active_days: set[str]
    logon_count: int = 0
    after_hours_logon_count: int = 0
    device_connect_count: int = 0
    file_copy_count: int = 0
    email_count: int = 0
    machines: set[str] = field(default_factory=set)

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
```

Implement:

```text
load_incidents(path)
build_activity_profiles(input_dir)
robust_standardize(profile_vectors)
select_matched_controls(profiles, insider_ids, controls_per_insider)
write_cohort_manifest(path, incidents, controls)
```

Requirements:

- `load_incidents` filters `dataset == "4.2"`.
- Profile readers use `csv.DictReader` and never retain content fields.
- After-hours is before 08:00 or at/after 18:00 for matching only.
- Distance is Euclidean on robust-standardized vectors.
- Each control is used once while unused candidates remain.
- Ties sort by `(distance, user_id)`.
- Output manifest records selection features but not labels used by detection.

- [ ] **Step 4: Run cohort tests and verify GREEN**

Run:

```powershell
python -m unittest tests.test_cert_extractor.CohortSelectionTest -v
```

Expected: all cohort tests pass.

- [ ] **Step 5: Commit**

```powershell
git add cert_extractor.py tests/test_cert_extractor.py tests/fixtures
git commit -m "feat(data): select real CERT evaluation cohort"
```

---

### Task 4: Build a bounded, event-time JSONL stream with external merge

**Files:**
- Modify: `cert_extractor.py`
- Modify: `tests/test_cert_extractor.py`
- Modify: `1_prepare_cert_data.py`
- Modify: `.gitignore`
- Delete after GREEN: `clean_cert_stream.csv`

- [ ] **Step 1: Write failing extraction tests**

Add tests:

```python
def test_extract_keeps_only_cohort_and_discards_content():
    result = extract_evaluation_stream(
        input_dir=FIXTURES,
        cohort={"INSIDER1", "CONTROL1"},
        output_path=output,
        run_size=2,
    )
    records = [json.loads(line) for line in output.read_text().splitlines()]
    assert {record["user_id"] for record in records} <= {"INSIDER1", "CONTROL1"}
    assert all("content" not in json.dumps(record) for record in records)
    assert result.event_count == len(records)


def test_external_merge_orders_by_event_time_then_event_id():
    records = [json.loads(line) for line in output.read_text().splitlines()]
    ordering = [(record["event_ts"], record["event_id"]) for record in records]
    assert ordering == sorted(ordering)
```

- [ ] **Step 2: Run extraction tests and verify RED**

Run:

```powershell
python -m unittest tests.test_cert_extractor.StreamExtractionTest -v
```

Expected: missing `extract_evaluation_stream`.

- [ ] **Step 3: Implement external run generation and k-way merge**

Add:

```text
iter_source_events(source_path, source, cohort)
write_sorted_runs(events, temporary_dir, run_size)
merge_jsonl_runs(run_paths, output_path)
extract_evaluation_stream(input_dir, cohort, output_path, run_size=50000)
```

Implementation rules:

- Parse one CSV row at a time.
- Keep at most `run_size` normalized events in memory.
- Sort each run by `(event_ts, event_id)`.
- Serialize one compact JSON record per line.
- Merge all run files with `heapq.merge`.
- Delete only temporary run files created under the extractor temp directory.
- Return `ExtractionResult(event_count, first_event_time, last_event_time, source_counts)`.

Rewrite `1_prepare_cert_data.py` as a CLI that:

```text
--input-dir data/cert-r4.2/r4.2
--answers-dir data/cert-r4.2/answers
--output artifacts/evaluation_stream.jsonl
--manifest artifacts/cohort.json
--controls-per-insider 2
--run-size 50000
```

Update `.gitignore`:

```text
artifacts/
dead-letter/
*.jsonl
```

- [ ] **Step 4: Run extraction tests and full unit suite**

Run:

```powershell
python -m unittest tests.test_cert_extractor -v
python -m unittest discover -s tests -v
```

Expected: extraction and existing new tests pass.

- [ ] **Step 5: Remove synthetic pipeline artifacts**

Delete:

```text
clean_cert_stream.csv
tests/test_cert_pipeline.py
```

Do not delete `cert_pipeline.py` until both CLI replacements are complete in Task 8.

- [ ] **Step 6: Commit**

```powershell
git add cert_extractor.py 1_prepare_cert_data.py .gitignore tests
git rm clean_cert_stream.csv tests/test_cert_pipeline.py
git commit -m "feat(data): extract bounded real event stream"
```

---

### Task 5: Create the temporal graph schema and repository

**Files:**
- Replace: `init_schema.cypher`
- Create: `graph_repository.py`
- Create: `tests/test_graph_repository.py`
- Create: `tests/test_graph_repository_integration.py`

- [ ] **Step 1: Write failing repository tests**

Unit tests use a `RecordingTransaction` with `run(query, **params)` and assert:

```text
1. The same event ID is written with MERGE, not CREATE.
2. Event parameters include event_ts and ingest_time.
3. FILE_COPY queries preserve user and machine relationships.
4. DEVICE_CONNECT opens UsbSession keyed by user, machine and connect event.
5. DEVICE_DISCONNECT closes the latest open session on the same user and machine.
6. FILE_COPY attaches to the latest open session or creates an inferred session.
7. EMAIL creates EmailAddress nodes and EMAILED aggregate edges.
```

- [ ] **Step 2: Run repository tests and verify RED**

Run:

```powershell
python -m unittest tests.test_graph_repository -v
```

Expected: missing `GraphRepository`.

- [ ] **Step 3: Replace the schema**

`init_schema.cypher` must create indexes:

```cypher
CREATE INDEX ON :User(id);
CREATE INDEX ON :Machine(id);
CREATE INDEX ON :Event(id);
CREATE INDEX ON :Event(event_ts);
CREATE INDEX ON :Domain(name);
CREATE INDEX ON :EmailAddress(address);
CREATE INDEX ON :ActivityWindow(id);
CREATE INDEX ON :UsbSession(id);
CREATE INDEX ON :Alert(id);
CREATE INDEX ON :Alert(detector);
```

- [ ] **Step 4: Implement `GraphRepository`**

Public interface:

```python
class GraphRepository:
    def __init__(self, driver, database: str | None = None): ...
    def reset(self) -> None: ...
    def write_event(self, event: Event, ingest_time: datetime) -> WriteResult: ...
    def fetch_uc1_context(self, user_id: str, trigger_ts: int) -> dict: ...
    def fetch_uc2_context(self, user_id: str, machine_id: str, trigger_ts: int) -> dict: ...
    def upsert_alert(self, alert: AlertRecord) -> None: ...
    def prune_events(self, before_ts: int) -> int: ...
```

`write_event` executes one transaction:

1. `MERGE` actor, machine and typed Event node.
2. `MERGE (u)-[:ACTED]->(e)` and `(e)-[:ON_MACHINE]->(m)`.
3. Update `USED_MACHINE` count, first_seen and last_seen.
4. Apply activity-window sessionization for LOGON/LOGOFF.
5. Apply USB sessionization for DEVICE_CONNECT/DISCONNECT/FILE_COPY.
6. Create Domain/EmailAddress relationships and aggregate edges.
7. Return whether the event was newly created so duplicates do not update baselines.

Use integer epoch properties for all window comparisons.

- [ ] **Step 5: Run unit tests and verify GREEN**

Run:

```powershell
python -m unittest tests.test_graph_repository -v
```

Expected: all recording-transaction tests pass.

- [ ] **Step 6: Write and run Memgraph integration tests**

Integration tests:

- Skip with a clear message if `MEMGRAPH_URI` is unavailable.
- Reset graph in `setUp`.
- Write Connect → FileCopy → Disconnect.
- Assert one closed `UsbSession` and one `IN_USB_SESSION` edge.
- Write the same FileCopy twice and assert one Event node.

Run:

```powershell
docker compose up -d
python -m unittest tests.test_graph_repository_integration -v
```

Expected: integration tests pass against Memgraph.

- [ ] **Step 7: Commit**

```powershell
git add init_schema.cypher graph_repository.py tests/test_graph_repository.py tests/test_graph_repository_integration.py
git commit -m "feat(graph): persist temporal CERT sessions"
```

---

### Task 6: Implement incremental UC1 exfiltration detection

**Files:**
- Create: `graph_detectors.py`
- Create: `queries/uc1_evidence.cypher`
- Create: `tests/test_graph_detectors.py`

- [ ] **Step 1: Write failing UC1 tests**

Build graph-context dictionaries directly in unit tests and assert:

```text
1. A new after-hours USB session with file copies and a novel leak domain exceeds threshold.
2. A single novel domain without USB does not alert.
3. A user who normally works at 02:00 receives a low A component.
4. Event ordering violation reduces C1.
5. Different-machine stages set continuity to zero.
6. The trigger event is excluded from all baseline lists.
7. The resulting alert stores A/U/F/D/C1 and ordered evidence IDs.
```

- [ ] **Step 2: Run UC1 tests and verify RED**

Run:

```powershell
python -m unittest tests.test_graph_detectors.UC1DetectorTest -v
```

Expected: missing `UC1Detector`.

- [ ] **Step 3: Add the UC1 graph query**

`queries/uc1_evidence.cypher` must:

- Start from `(:User {id: $user_id})`.
- Restrict Events to `$history_start_ts <= event_ts < $trigger_ts`.
- Restrict candidate motif Events to `$motif_start_ts <= event_ts <= $trigger_ts`.
- Traverse `ACTED`, `ON_MACHINE`, `BOUNDARY_OF`, `IN_USB_SESSION`, and `VISITED`.
- Return:
  - logon hour histogram;
  - historical daily USB counts;
  - historical file/session counts;
  - domain prior visit count;
  - candidate events with IDs, kinds, timestamps and machine IDs;
  - active USB session ID.

- [ ] **Step 4: Implement UC1 scoring**

Add:

```python
@dataclass(frozen=True)
class AlertRecord:
    alert_id: str
    detector: str
    score: float
    threshold: float
    trigger_event_id: str
    event_time: datetime
    components: dict[str, float]
    user_ids: tuple[str, ...]
    machine_ids: tuple[str, ...]
    evidence_event_ids: tuple[str, ...]
    evidence_start_ts: int
    evidence_end_ts: int


class UC1Detector:
    def evaluate(self, trigger: Event, context: dict, threshold: float) -> AlertRecord | None: ...
```

Use the approved formulas exactly:

```text
S1 = 0.20A + 0.25U + 0.25F + 0.15D + 0.15C1
C1 >= 0.60
U > 0
S1 >= threshold
```

Execution coverage weights:

```text
after-hours 0.20
USB         0.25
FileCopy    0.25
leak/cloud  0.30
```

Intent coverage weights:

```text
job/competitor    0.25
USB spike         0.30
FileCopy burst    0.25
external signal   0.20
```

Use 8-hour execution decay and 30-day intent decay.

- [ ] **Step 5: Run UC1 tests and verify GREEN**

Run:

```powershell
python -m unittest tests.test_graph_detectors.UC1DetectorTest -v
```

Expected: all UC1 tests pass.

- [ ] **Step 6: Commit**

```powershell
git add graph_detectors.py queries/uc1_evidence.cypher tests/test_graph_detectors.py
git commit -m "feat(detection): add incremental exfiltration motif"
```

---

### Task 7: Implement incremental UC2 credential-pivot detection

**Files:**
- Modify: `graph_detectors.py`
- Create: `queries/uc2_evidence.cypher`
- Modify: `tests/test_graph_detectors.py`

- [ ] **Step 1: Write failing UC2 tests**

Use the real BBS0039/FAW0032 sequence shape:

```text
BBS0039 visits keylogger domain on PC-9436
BBS0039 opens USB and copies .exe on PC-9436
BBS0039 logs into PC-5866 and connects USB
FAW0032 logs into PC-5866
FAW0032 sends to 11 unusual recipients
```

Tests assert:

```text
1. The final email produces a UC2 alert.
2. A shared machine with low owner_confidence reduces M.
3. Mass email without attacker-victim machine bridge does not alert.
4. K decreases when pivot precedes keylogger/USB stages.
5. R equals the fraction of recipients outside the 90-day neighborhood.
6. C2 is zero when attacker == victim.
7. Alert contains both identities, target machine and recipient evidence.
```

- [ ] **Step 2: Run UC2 tests and verify RED**

Run:

```powershell
python -m unittest tests.test_graph_detectors.UC2DetectorTest -v
```

Expected: missing `UC2Detector`.

- [ ] **Step 3: Add UC2 graph traversal**

`queries/uc2_evidence.cypher` must:

- Start from the trigger identity and target machine.
- Identify `DOMINANT_USER`/historical machine owner and confidence.
- Find another identity that performed keylogger HTTP, USB or FileCopy stages before
  the victim trigger on the same target machine.
- Return source-machine and target-machine stage events in the 48-hour window.
- Return victim per-email and 10-minute fan-out history before trigger.
- Return prior 90-day `EMAILED` neighborhood and current recipient set.

- [ ] **Step 4: Implement UC2 scoring**

Add:

```python
class UC2Detector:
    def evaluate(self, trigger: Event, context: dict, threshold: float) -> AlertRecord | None: ...
```

Use:

```text
M = (1 - p(user,machine)) * owner_confidence(machine)

coverage_K =
  0.25q + 0.15s + 0.20f + 0.25p + 0.15t

K = coverage_K * order_K * decay(duration, 48 hours)

E = max(per-email robust deviation, 10-minute robust deviation)

R = 1 - |current recipients intersect historical neighborhood|
        / |current recipients|

C2 = hop_coverage
     * temporal_order
     * identity_bridge
     * decay(duration, 48 hours)

S2 = 0.25M + 0.25K + 0.20E + 0.15R + 0.15C2
```

Alert gate:

```text
M >= 0.60
K >= 0.40
C2 >= 0.50
S2 >= threshold
```

- [ ] **Step 5: Run detector tests and verify GREEN**

Run:

```powershell
python -m unittest tests.test_graph_detectors -v
```

Expected: UC1 and UC2 tests pass.

- [ ] **Step 6: Commit**

```powershell
git add graph_detectors.py queries/uc2_evidence.cypher tests/test_graph_detectors.py
git commit -m "feat(detection): add credential pivot motif"
```

---

### Task 8: Orchestrate event-time replay, calibration and alert persistence

**Files:**
- Create: `event_replay.py`
- Create: `tests/test_event_replay.py`
- Replace: `2_stream_cert.py`
- Delete: `cert_pipeline.py`
- Modify: `.env.example`

- [ ] **Step 1: Write failing replay tests**

Tests use fake repository/detectors and assert:

```text
1. JSONL events are consumed in event_ts/event_id order.
2. Duplicate events do not invoke detectors twice.
3. Context is fetched and score is calculated before baseline update.
4. UC1 only runs for LOGON, DEVICE_CONNECT, FILE_COPY and HTTP triggers.
5. UC2 runs for LOGON, DEVICE_CONNECT, FILE_COPY, HTTP and EMAIL triggers.
6. First 30 days collect candidate scores without persisting alerts.
7. Frozen thresholds equal the 99.5 percentile of calibration candidates.
8. Late events inside 48 hours recompute the affected neighborhood.
9. Processing latency and throughput counters are populated.
```

- [ ] **Step 2: Run replay tests and verify RED**

Run:

```powershell
python -m unittest tests.test_event_replay -v
```

Expected: missing replay APIs.

- [ ] **Step 3: Implement replay orchestration**

Public API:

```python
@dataclass
class ReplayConfig:
    calibration_days: int = 30
    allowed_lateness_seconds: int = 300
    delay_seconds: float = 0.0
    uc1_fallback_threshold: float = 0.75
    uc2_fallback_threshold: float = 0.75
    prune_after_days: int = 90


class ReplayEngine:
    def replay(self, stream_path: Path) -> ReplaySummary: ...
```

Processing order is mandatory:

```text
write event
sessionize/update graph
fetch pre-trigger context
score detectors
persist alert
update baseline aggregates
```

Repository queries must use `< trigger_ts` for historical baseline and
`<= trigger_ts` only for candidate evidence.

Replace `2_stream_cert.py` with CLI arguments:

```text
--stream artifacts/evaluation_stream.jsonl
--uri bolt://localhost:7687
--reset
--delay 0
--limit
--calibration-days 30
--allowed-lateness-seconds 300
--summary artifacts/replay_summary.json
```

Update `.env.example` with the same settings.

- [ ] **Step 4: Run replay tests and verify GREEN**

Run:

```powershell
python -m unittest tests.test_event_replay -v
```

Expected: replay tests pass.

- [ ] **Step 5: Remove obsolete synthetic implementation**

Delete `cert_pipeline.py`. Confirm no source imports:

```powershell
rg "cert_pipeline|create_synthetic|THIEF_U101|SNOOP_U102" .
```

Expected: no production-code matches.

- [ ] **Step 6: Commit**

```powershell
git add event_replay.py 2_stream_cert.py .env.example tests/test_event_replay.py
git rm cert_pipeline.py
git commit -m "feat(stream): detect motifs during event replay"
```

---

### Task 9: Add the non-graph rule baseline and ground-truth evaluation

**Files:**
- Create: `rule_detectors.py`
- Create: `evaluation.py`
- Create: `tests/test_rule_detectors.py`
- Create: `tests/test_evaluation.py`

- [ ] **Step 1: Write failing rule tests**

Tests assert:

```text
Rule UC1 requires after-hours + Connect + leak/cloud/job keyword or fixed file count.
Rule UC2 alerts on keylogger+USB, fixed recipient count, or unseen machine.
Rules consume event records only and never call GraphRepository.
```

- [ ] **Step 2: Write failing evaluation tests**

Tests use three incidents and alerts to assert:

```text
incident-level TP/FP/FN
precision/recall/F1
false positives per user-day
incident time-to-detect
processing latency
one incident with multiple alerts counts once for recall
wrong scenario detector does not match
```

- [ ] **Step 3: Run tests and verify RED**

Run:

```powershell
python -m unittest tests.test_rule_detectors tests.test_evaluation -v
```

Expected: missing modules.

- [ ] **Step 4: Implement flat rules**

Public API:

```python
class RuleUC1Detector:
    def observe(self, event: Event) -> RuleAlert | None: ...


class RuleUC2Detector:
    def observe(self, event: Event) -> RuleAlert | None: ...
```

Fixed defaults:

```text
business hours: 08:00-18:00
UC1 file threshold: 20 files/day
UC2 recipient threshold: 10 recipients/10 minutes
new machine lookback: 30 days
keylogger/USB lookback: 48 hours
```

- [ ] **Step 5: Implement evaluation**

Public API:

```python
def load_ground_truth(answers_dir: Path) -> list[Incident]: ...
def evaluate_alerts(alerts: Iterable[EvaluationAlert], incidents: Sequence[Incident]) -> EvaluationReport: ...
def compare_detectors(graph_report: EvaluationReport, rule_report: EvaluationReport) -> dict: ...
```

UC1 maps to scenarios 1 and 2; UC2 maps to scenario 3. Ground truth is loaded only
when `evaluation.py` runs after replay.

- [ ] **Step 6: Run tests and verify GREEN**

Run:

```powershell
python -m unittest tests.test_rule_detectors tests.test_evaluation -v
```

Expected: all rule/evaluation tests pass.

- [ ] **Step 7: Commit**

```powershell
git add rule_detectors.py evaluation.py tests/test_rule_detectors.py tests/test_evaluation.py
git commit -m "feat(eval): compare graph motifs with flat rules"
```

---

### Task 10: Add alert visualization and real-incident smoke tests

**Files:**
- Create: `queries/alerts.cypher`
- Modify: `tests/test_graph_repository_integration.py`
- Create: `tests/test_real_incidents.py`
- Remove/replace: `cert_queries.cypher`
- Remove: `show_logon_usb_copy_secret.cypher`

- [ ] **Step 1: Add visualization queries**

`queries/alerts.cypher`:

```cypher
MATCH p = (a:Alert)-[:ABOUT|EVIDENCE|INVOLVES*1..3]-(entity)
RETURN p
ORDER BY a.event_time DESC;
```

Also provide parameterized sections for:

```text
specific alert ID
all UC1 alerts
all UC2 alerts
component score table
evidence event timeline
```

- [ ] **Step 2: Write real-incident tests**

Use copied, minimal observable fixtures from:

```text
answers/r4.2-1/r4.2-1-AAM0658.csv
answers/r4.2-2/<one incident>.csv
answers/r4.2-3/r4.2-3-BBS0039.csv
```

Tests must preserve the original rows and assert:

- Scenario 1 completes a UC1 leak motif.
- Scenario 2 completes an intent/USB-spike UC1 motif after adding that user’s real
  pre-incident baseline rows from the main CSV.
- Scenario 3 completes a UC2 multi-identity motif.
- A matched real control fixture does not exceed the corresponding alert gate.

- [ ] **Step 3: Run real-incident tests**

Run:

```powershell
python -m unittest tests.test_real_incidents -v
```

Expected: all three incident smoke tests and the negative control pass.

- [ ] **Step 4: Replace obsolete query files**

Delete:

```text
cert_queries.cypher
show_logon_usb_copy_secret.cypher
```

Ensure all supported queries exist under `queries/`.

- [ ] **Step 5: Commit**

```powershell
git add queries tests/test_real_incidents.py tests/test_graph_repository_integration.py
git rm cert_queries.cypher show_logon_usb_copy_secret.cypher
git commit -m "test(detection): verify real CERT incidents"
```

---

### Task 11: Document and exercise the end-to-end demo

**Files:**
- Replace: `README.md`
- Modify: `docker-compose.yml`
- Create: `scripts/run_demo.ps1`
- Create: `scripts/run_evaluation.ps1`

- [ ] **Step 1: Write README acceptance checklist**

The README must document:

```text
real-data-only guarantee
70 incident count and control policy
resource requirements for 8 GB RAM
all extraction/replay/evaluation commands
temporal graph schema
UC1 formula and A/U/F/D/C1 definitions
UC2 formula and M/K/E/R/C2 definitions
threshold calibration
rule baseline
Memgraph Lab visualization queries
known limitation: CERT has no removable-device ID
known limitation: source files are replayed rather than received from Kafka
```

- [ ] **Step 2: Add reproducible PowerShell workflows**

`scripts/run_demo.ps1`:

```powershell
$ErrorActionPreference = "Stop"
docker compose up -d
python 1_prepare_cert_data.py
python 2_stream_cert.py --reset
python evaluation.py
```

`scripts/run_evaluation.ps1` adds timing and writes:

```text
artifacts/graph_metrics.json
artifacts/rule_metrics.json
artifacts/comparison.json
```

`docker-compose.yml` must cap Memgraph memory conservatively and retain the existing
ports. Use Memgraph configuration supported by the selected image; verify the exact
flag with `docker compose config` before committing.

- [ ] **Step 3: Run static and unit verification**

Run:

```powershell
python -m compileall .
python -m unittest discover -s tests -v
docker compose config
```

Expected:

- Compile succeeds.
- All unit tests pass.
- Compose configuration is valid.

- [ ] **Step 4: Run Memgraph integration verification**

Run:

```powershell
docker compose up -d
python -m unittest tests.test_graph_repository_integration -v
```

Expected: integration tests pass.

- [ ] **Step 5: Run bounded end-to-end smoke**

Run:

```powershell
python 1_prepare_cert_data.py --controls-per-insider 1 --run-size 10000
python 2_stream_cert.py --reset --limit 5000 --delay 0
python evaluation.py
```

Expected:

- No synthetic identities or sources.
- Events are ordered.
- At least one detector candidate is scored during replay.
- Replay summary contains throughput and peak RSS.
- Evaluation emits graph and rule reports even if the 5,000-event limit precedes
  the first full incident.

- [ ] **Step 6: Run full evaluation cohort**

Run without `--limit`:

```powershell
python 2_stream_cert.py --reset --delay 0
python evaluation.py
```

Record:

```text
event count
elapsed time
events/second
peak Python RSS
Memgraph memory
UC1/UC2 precision, recall, F1
rule precision, recall, F1
median incident time-to-detect
median processing latency
```

If peak combined memory exceeds 8 GB, reduce `controls-per-insider` from 2 to 1
before changing detector logic, rerun extraction and repeat the measurement.

- [ ] **Step 7: Commit**

```powershell
git add README.md docker-compose.yml scripts
git commit -m "docs: add streaming graph demo workflow"
```

---

### Task 12: Final requirements audit

**Files:**
- Review all modified files
- Update: `docs/superpowers/specs/2026-06-24-streaming-graph-analytics-design.md` only if implementation required an approved clarification

- [ ] **Step 1: Search for prohibited synthetic remnants**

Run:

```powershell
rg -n "THIEF_U101|SNOOP_U102|synthetic-theft|synthetic-snoop|create_synthetic" .
```

Expected: zero matches outside historical git data.

- [ ] **Step 2: Verify formulas and alert components**

Run:

```powershell
rg -n "0\\.20.*A|0\\.25.*U|0\\.25.*F|0\\.15.*D|0\\.15.*C1|0\\.25.*M|0\\.25.*K|0\\.20.*E|0\\.15.*R|0\\.15.*C2" baselines.py graph_detectors.py README.md
```

Expected: approved formulas appear in implementation and documentation.

- [ ] **Step 3: Run the complete verification suite**

Run:

```powershell
python -m compileall .
python -m unittest discover -s tests -v
docker compose config
python -m unittest tests.test_graph_repository_integration -v
git status --short
```

Expected:

- Compilation succeeds.
- All tests pass with zero failures/errors.
- Compose validates.
- Integration tests pass.
- Only intentional generated artifacts remain ignored.

- [ ] **Step 4: Review graph-vs-rule evidence**

Confirm the final report contains:

```text
same cohort
same event order
same evaluation intervals
graph metrics
rule metrics
evidence-path examples
resource measurements
limitations
```

- [ ] **Step 5: Commit final corrections**

```powershell
git add -A
git commit -m "chore: complete streaming graph audit"
```

