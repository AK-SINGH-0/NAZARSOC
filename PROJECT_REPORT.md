# NazarSOC — Project Report

**Course:** B.Tech Cybersecurity / Computer Science  
**Project Type:** Individual Portfolio — Mini Security Operations Center  
**Data:** Fully synthetic — no real users, IPs, or attack logs  

---

## Table of Contents

1. [Abstract](#1-abstract)
2. [System Architecture](#2-system-architecture)
3. [Module Descriptions](#3-module-descriptions)
4. [Detection Algorithms](#4-detection-algorithms)
5. [Data Model](#5-data-model)
6. [Evaluation Methodology and Results](#6-evaluation-methodology-and-results)
7. [Threat Model and Security Considerations](#7-threat-model-and-security-considerations)
8. [Known Limitations](#8-known-limitations)
9. [Glossary](#9-glossary)


---

## 1. Abstract

NazarSOC is a local-first, explainable Mini Security Operations Center built entirely in Python.  
It ingests synthetic authentication logs in JSON or CSV format, normalizes events to a consistent schema, applies three rule-based detection algorithms that map to MITRE ATT&CK techniques, persists findings in a local SQLite database, and presents them through a Streamlit web dashboard.

The project demonstrates core SOC analyst competencies — log normalization, sliding-window correlation, incident triage, metrics evaluation, and report generation — without requiring cloud services, Docker, machine learning libraries, or paid APIs. All events, IP addresses, and usernames are fabricated; the system is intended for learning and portfolio demonstration only, not production security monitoring.

The test suite contains **246 unit tests** covering normalization, boundary conditions, all three detection rules, duplicate suppression, database persistence, and reporting exports. All tests pass under both normal and `-O` (assertion-stripped) execution modes.

---

## 2. System Architecture

### 2.1 Layer Diagram

```
┌─────────────────────────────────────────┐
│  Presentation Layer                     │
│  app.py — Streamlit dashboard (5 pages) │
└────────────────┬────────────────────────┘
                 │ calls
┌────────────────▼────────────────────────┐
│  Persistence Layer                      │
│  database.py — SQLite (5 tables)        │
└────────────────┬────────────────────────┘
                 │ calls
┌────────────────▼────────────────────────┐
│  Detection Layer                        │
│  engine.py — parse · normalize · detect │
└────────────────┬────────────────────────┘
                 │ reads
┌────────────────▼────────────────────────┐
│  Input                                  │
│  demo_events.json / user CSV upload     │
└─────────────────────────────────────────┘

┌─────────────────────────────────────────┐
│  Reporting Layer (independent)          │
│  reporting.py — metrics · export        │
└─────────────────────────────────────────┘
```

### 2.2 Design Decisions

| Decision | Rationale |
|---|---|
| `engine.py` has no Streamlit or DB import | Allows direct unit testing without a running app |
| SQLite over PostgreSQL | Zero-dependency local persistence; sufficient for single-analyst portfolio use |
| Deterministic detection IDs | Prevents duplicate incidents from overlapping sliding windows |
| Configurable thresholds as keyword args | Avoids hidden magic numbers; easy to explain and adjust |
| `INSERT OR IGNORE` for deduplication | Database-level safety net complementing engine-level dedup |

---

## 3. Module Descriptions

### 3.1 `engine.py`

Responsibilities: input parsing, field normalization, timestamp validation, detection rule execution.

**Key public functions:**

| Function | Description |
|---|---|
| `normalize_event(raw)` | Validates required fields, normalizes types, returns `(NormalizedEvent, None)` or `(None, ParseError)` |
| `parse_json_events(text)` | Parses a JSON string or list of records into normalized events and parse errors |
| `parse_csv_events(text)` | Parses a CSV string into normalized events and parse errors |
| `detect_brute_force(events, ...)` | Rule A — repeated failures per IP+username |
| `detect_password_spray(events, ...)` | Rule B — failures across many usernames from one IP |
| `detect_failures_then_success(events, ...)` | Rule C — failure sequence ending in success |
| `run_all_detections(events, ...)` | Convenience wrapper — runs all three rules and deduplicates |

**Internal helpers:**

| Function | Description |
|---|---|
| `_parse_timestamp(raw)` | Parses ISO 8601 string to UTC-aware `datetime`; rejects ambiguous or invalid values |
| `_normalize_string(value)` | Strips and lowercases; enforces max-length limit |
| `_make_detection_id(...)` | Builds a SHA-256 hex identifier from rule + IP + usernames + window start |
| `_sliding_window(events, window_secs)` | Yields consecutive event slices that fit within `window_secs` |
| `_auth_failures(events)` | Filters to `outcome == "failure"` |
| `_auth_successes(events)` | Filters to `outcome == "success"` |

### 3.2 `database.py`

Responsibilities: SQLite schema management, event persistence, incident lifecycle, batch tracking.

**Constants:** `DEFAULT_DB_PATH = nazarsoc.db`, `SCHEMA_VERSION = 1`, `MAX_IMPORT_RECORDS = 10000`, `MAX_IMPORT_BYTES = 52_428_800` (50 MB), `MAX_ANALYST_NOTE_LEN = 4096`.

**Key public functions:**

| Function | Description |
|---|---|
| `init_db(db_path)` | Creates all tables and sets `PRAGMA journal_mode=WAL` |
| `create_import_batch(...)` | Opens a named import batch; returns `batch_id` |
| `update_import_batch(...)` | Records final counts and status on batch close |
| `save_event(conn, evt)` | Inserts one normalized event; deduplicates on `event_id` |
| `save_events_batch(db_path, events, batch_id)` | Bulk insert with deduplication |
| `save_incident(conn, detection)` | Persists a detection as an incident; links evidence event IDs |
| `save_detections(db_path, detections)` | Bulk incident save with `INSERT OR IGNORE` |
| `get_events(conn, ...)` | Paginated event query with optional filters |
| `list_incidents(conn, ...)` | Paginated incident query with status/severity filters |
| `update_incident_status(conn, incident_id, status)` | Moves incident through `open → investigating → closed` |
| `update_incident_disposition(conn, incident_id, disposition)` | Records `true_positive`, `false_positive`, or `benign` |
| `add_analyst_note(conn, incident_id, note)` | Appends a timestamped note (max 4 096 chars) |
| `run_detection_pipeline(db_path, events)` | End-to-end: saves events, runs detections, saves incidents |

### 3.3 `reporting.py`

Responsibilities: scenario-level evaluation, JSON/CSV/HTML export.

**Key public functions:**

| Function | Description |
|---|---|
| `build_labelled_dataset()` | Returns the 8 built-in synthetic `EvalScenario` objects with ground-truth labels |
| `evaluate_scenarios(scenarios)` | Runs detections, compares to labels, returns `EvalMetrics` dataclass |
| `export_incidents_json(incidents)` | Serializes incident list to JSON string |
| `export_incidents_csv(incidents)` | Serializes to CSV with CSV-injection sanitization |
| `export_metrics_json(metrics)` | Serializes `EvalMetrics` to JSON |
| `export_metrics_csv(metrics)` | Serializes `EvalMetrics` to CSV |
| `generate_html_report(incidents, metrics)` | Produces a self-contained HTML report |
| `generate_incident_report(conn, incident_id)` | Fetches full incident detail from DB for reporting |

### 3.4 `app.py`

A Streamlit application with five pages selected from a sidebar radio button.

| Page | Key actions |
|---|---|
| Overview | KPI tiles: event count, incident count, open/closed split |
| Events | Import demo data; upload JSON/CSV; paginated event table with filters |
| Incidents | Filterable incident list; detail drill-down; status/disposition update; analyst notes |
| Quality Lab | Run `evaluate_scenarios`; display TP/FP/FN/TN and precision/recall/F1/accuracy |
| Reports | Download incidents (JSON, CSV, HTML) and metrics (JSON, CSV) |

The module-level Streamlit call is guarded by `_is_streamlit_runtime()` so `import app` in tests does not crash.

---

## 4. Detection Algorithms

### 4.1 Sliding Window

All three rules share a common `_sliding_window` generator.  
Events are sorted by timestamp ascending, then the generator yields every contiguous subsequence where `last_event.timestamp − first_event.timestamp ≤ window_secs`.  
The window advances one event at a time from the left, so every possible starting position is examined.

```
events sorted by time: e1 e2 e3 e4 e5 e6
window = [e1 e2 e3]  → check rule
window = [e2 e3 e4]  → check rule
window = [e3 e4 e5]  → check rule
...
```

**Boundary condition:** an event at exactly `window_secs` offset is included (`≤`, not `<`).

### 4.2 Rule A — Brute Force (`detect_brute_force`)

```
for each (source_ip, username) group:
    sort failures by timestamp
    for each sliding window of width ≤ 5 min:
        if len(window) >= 5:
            emit detection
            advance past last consumed event (avoid re-alerting same cluster)
```

Deduplication: after emitting a detection the inner `while` loop advances the left pointer past the last event of the consumed cluster, preventing the same sequence from triggering a second alert.

### 4.3 Rule B — Password Spraying (`detect_password_spray`)

```
for each source_ip group:
    sort failures by timestamp
    for each sliding window of width ≤ 10 min:
        distinct_users = set of usernames in window
        if len(window) >= 10 and len(distinct_users) >= 5:
            emit detection
```

The detection title uses "possible password spraying" to avoid asserting confirmed malicious intent.

### 4.4 Rule C — Failures Followed by Success (`detect_failures_then_success`)

```
for each (source_ip, username) group:
    sort all events (failures + successes) by timestamp
    for each success event:
        collect prior_fails = failures that occurred before this success
                              and within 10 min of this success
        if len(prior_fails) >= 3:
            emit detection using first failure + success as window boundaries
```

The phrase "warrants investigation" is used rather than "account compromised" to reflect appropriate confidence.

### 4.5 Duplicate Suppression

`_make_detection_id` computes:

```python
key = f"{rule_id}|{source_ip}|{','.join(sorted(usernames))}|{window_start_minute}"
detection_id = sha256(key.encode()).hexdigest()
```

`window_start_minute` is the timestamp truncated to whole minutes.  
Detections with the same logical key produce the same ID and are silently deduplicated at the database level by `INSERT OR IGNORE`.

---

## 5. Data Model

### 5.1 SQLite Tables

```
events
  id TEXT PRIMARY KEY          -- event_id from source
  batch_id TEXT                -- FK → import_batches
  timestamp TEXT               -- ISO 8601 UTC
  source_type TEXT
  source_ip TEXT
  username TEXT
  event_type TEXT
  outcome TEXT
  hostname TEXT
  source_reference TEXT
  content_hash TEXT            -- SHA-256 of normalized content
  created_at TEXT

incidents
  incident_id TEXT PRIMARY KEY  -- deterministic detection_id
  rule_id TEXT
  title TEXT
  explanation TEXT
  source_ip TEXT
  usernames TEXT               -- JSON array
  first_seen TEXT
  last_seen TEXT
  severity TEXT
  confidence TEXT
  recommendation TEXT
  mitre_technique TEXT
  status TEXT                  -- open | investigating | closed
  disposition TEXT             -- true_positive | false_positive | benign | null
  analyst_note TEXT
  event_count INTEGER
  created_at TEXT
  updated_at TEXT

evidence
  id INTEGER PRIMARY KEY AUTOINCREMENT
  incident_id TEXT             -- FK → incidents
  event_id TEXT                -- FK → events
  created_at TEXT

import_batches
  batch_id TEXT PRIMARY KEY
  name TEXT
  status TEXT                  -- pending | complete | failed
  events_attempted INTEGER
  events_saved INTEGER
  events_skipped INTEGER
  created_at TEXT
  completed_at TEXT

schema_meta
  key TEXT PRIMARY KEY
  value TEXT
```

### 5.2 NormalizedEvent (engine.py dataclass)

Fields: `event_id`, `timestamp` (UTC `datetime`), `source_type`, `source_ip`, `username`, `event_type`, `outcome`, `hostname`, `source_reference`, `import_batch`.

---

## 6. Evaluation Methodology and Results

> ⚠️ **All figures below are computed on a built-in synthetic dataset.  
> They do not reflect real-world detection accuracy.**

### 6.1 Approach

The `build_labelled_dataset()` function in `reporting.py` constructs 8 `EvalScenario` objects.  
Each scenario is a list of fabricated events with a ground-truth label (`should_fire: bool`) and the expected `rule_id`.  
`evaluate_scenarios()` runs `run_all_detections` on each scenario and compares whether at least one matching detection fired.

### 6.2 Scenario Table

| # | Description | Expected | Rule |
|---|---|---|---|
| 1 | 6 failures, same IP+user, within 5 min | Fire | Rule A |
| 2 | 4 failures, same IP+user (below threshold) | No fire | Rule A |
| 3 | 12 failures across 6 users, same IP | Fire | Rule B |
| 4 | 9 failures across 6 users (below count threshold) | No fire | Rule B |
| 5 | 4 failures + success, same IP+user, within 10 min | Fire | Rule C |
| 6 | 2 failures + success (below failure threshold) | No fire | Rule C |
| 7 | Normal successful logins only | No fire | — |
| 8 | Isolated failures from different IPs | No fire | — |

### 6.3 Metrics (Synthetic)

| Metric | Value |
|---|---|
| True Positives | 3 |
| False Positives | 0 |
| False Negatives | 0 |
| True Negatives | 5 |
| **Precision** | **1.0** |
| **Recall** | **1.0** |
| **F1 Score** | **1.0** |
| **Accuracy** | **1.0** |

These results reflect that the rules were designed and the test data was constructed together.  
They cannot be generalized to unseen or real log data.

---

## 7. Threat Model and Security Considerations

### 7.1 Scope

NazarSOC is a single-user local tool. The only network interface exposed is the Streamlit server bound to `127.0.0.1:8501`. No external connections are made at runtime.

### 7.2 Input Handling

| Risk | Mitigation |
|---|---|
| Malicious JSON/CSV content | Imported data is parsed as data only; `eval` and `exec` are never used |
| CSV injection (formula injection) | `_sanitize_csv_cell` prefixes dangerous characters (`=`, `+`, `-`, `@`, `\t`, `\r`) with a single quote in all exported cells |
| Excessively large imports | `MAX_IMPORT_RECORDS = 10000` and `MAX_IMPORT_BYTES = 50 MB` enforced before parsing |
| Long string fields | `_normalize_string` enforces a 256-character limit on `event_id`, `username`, etc. |
| Invalid IP addresses | `ipaddress.ip_address()` validates `source_ip`; non-strings are rejected |
| SQL injection | All database queries use parameterized statements (`?` placeholders); no string interpolation |
| Path traversal on DB path | `DEFAULT_DB_PATH` resolves to the current working directory; no user-controlled path components reach the DB open call |

### 7.3 What This Tool Does Not Protect Against

- A local attacker with filesystem access can read or delete `nazarsoc.db` directly.
- No authentication is provided; anyone who can reach `127.0.0.1:8501` can use the dashboard.
- The detection rules cover only authentication events; other attack categories (lateral movement, data exfiltration, etc.) are out of scope.

---

## 8. Known Limitations

1. **Synthetic evaluation only.** All precision/recall/F1 figures are computed on fabricated scenarios crafted to match the rules. Real-world accuracy is unknown.
2. **Authentication events only.** No support for network flow, process creation, file integrity, or other log sources.
3. **No real-time streaming.** Events must be imported manually; there is no live log tail or syslog listener.
4. **Single-user SQLite.** Not suitable for concurrent multi-analyst use. A production deployment would require PostgreSQL and an authentication layer.
5. **Windows `run.bat` only.** Linux and macOS users must activate the virtual environment and launch Streamlit manually.
6. **No TLS.** The Streamlit server runs over plain HTTP on loopback only.
7. **Threshold sensitivity.** The default thresholds (Rule A: 5 failures / 5 min; Rule B: 10 failures + 5 users / 10 min; Rule C: 3 failures + 1 success / 10 min) were chosen for demo clarity. A real deployment would require tuning against baseline data to control false-positive rates.
8. **No enrichment.** There is no GeoIP lookup, threat intelligence feed, or asset inventory integration.

---

## 9. Glossary

| Term | Definition |
|---|---|
| **SOC** | Security Operations Center — a team or facility responsible for monitoring, detecting, and responding to cybersecurity incidents |
| **SIEM** | Security Information and Event Management — a platform that aggregates and correlates log data from many sources |
| **Detection Rule** | A defined condition applied to event data that, when matched, generates an alert or incident |
| **Sliding Window** | A technique that moves a fixed-time-width frame across a sorted event sequence to find bursts of activity |
| **Normalization** | Converting raw, heterogeneous log fields into a consistent schema (lowercase usernames, UTC timestamps, etc.) |
| **Brute Force** | Repeatedly attempting credentials to gain unauthorized access (MITRE T1110) |
| **Password Spraying** | Testing one common password against many accounts to avoid lockout policies (MITRE T1110.003) |
| **True Positive (TP)** | A detection that correctly fired on a real (or, here, synthetically labelled) attack |
| **False Positive (FP)** | A detection that fired when no attack was present |
| **False Negative (FN)** | A real attack that the detection engine missed |
| **True Negative (TN)** | Correctly producing no detection on benign activity |
| **Precision** | TP / (TP + FP) — fraction of detections that were correct |
| **Recall** | TP / (TP + FN) — fraction of attacks that were detected |
| **F1 Score** | Harmonic mean of Precision and Recall |
| **MITRE ATT&CK** | A globally accessible knowledge base of adversary tactics and techniques based on real-world observations |
| **T1110.001** | MITRE technique: Brute Force — Password Guessing |
| **T1110.003** | MITRE technique: Brute Force — Password Spraying |
| **RFC 5737** | Defines three IPv4 address ranges reserved for documentation and examples: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 |
| **WAL** | Write-Ahead Logging — a SQLite journal mode that improves concurrency and reduces corruption risk |
| **SHA-256** | A cryptographic hash function used here to generate deterministic detection identifiers |
| **Incident** | A persisted detection record with lifecycle fields (status, disposition, analyst notes) |
| **Disposition** | An analyst's verdict on an incident: `true_positive`, `false_positive`, or `benign` |
| **CSV Injection** | An attack where a CSV cell beginning with `=`, `+`, `-`, or `@` is interpreted as a formula by spreadsheet software |
| **Parameterized Query** | A database query that passes user data as bound parameters rather than string-interpolated SQL, preventing SQL injection |
