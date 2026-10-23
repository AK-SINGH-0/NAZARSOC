"""
database.py — NazarSOC Persistence Layer (Phase 2)

Responsibilities
----------------
- Initialize and migrate the SQLite schema.
- Persist validated events and import-batch metadata.
- Persist detections as incidents with evidence links.
- Provide read/update functions for analyst workflow.

Design decisions
----------------
- Every query that touches data uses parameterized SQL (never f-strings or
  % formatting with user-supplied values).
- Foreign keys are enabled on every connection via PRAGMA foreign_keys = ON.
- Timestamps are stored as ISO-8601 strings in UTC (e.g. "2024-01-15T10:00:00Z")
  and documented here so all callers agree on the format.
- Schema versioning is handled by the schema_version table; the current version
  is SCHEMA_VERSION.  Future migrations append to _MIGRATIONS.
- The database file is created in the directory specified by DB_PATH (default:
  the current working directory, configurable at runtime).
- All insert/update operations use explicit transactions; a failed write is
  rolled back cleanly.
- This module is independent of Streamlit. It can be imported and tested from
  the CLI or unittest.

Duplicate-event policy
----------------------
An event is uniquely identified by the combination of (event_id, content_hash).
- Re-importing an identical event (same event_id AND same content) is skipped
  silently and counted as a duplicate in the batch stats — it does not inflate
  authentication counts or incident counts.
- Importing an event with an existing event_id but different content is rejected
  with a CONFLICT status in the batch stats.  The original evidence is preserved.
- If two genuinely different source systems emit the same event_id string, each
  record is differentiated by its content_hash.  Phase 2 does not auto-merge
  them; the analyst can investigate via the import batch records.

Incident correlation policy
----------------------------
An incident's stable identity is its detection_id, which is produced by
engine._make_detection_id and incorporates (rule_id, source_ip, usernames,
5-minute-bucket timestamp).  Two runs of run_all_detections on the same event
set will produce the same detection_id for the same qualifying cluster.

A temporally distinct cluster (same rule + IP + user but a different 5-minute
bucket) produces a different detection_id and therefore a separate incident.

Reprocessing an existing detection_id updates the incident's first_seen,
last_seen, and evidence set if they change, but never resets analyst status,
disposition, or notes.

This module does not store sensitive secrets, credentials, or raw file contents.
Imported event text is stored as data and is never executed.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple

from engine import Detection, NormalizedEvent


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

#: Default path for the SQLite database file.
#: Override by passing db_path= to init_db() or any function that accepts it.
DEFAULT_DB_PATH: Path = Path("nazarsoc.db")

#: Current schema version.  Increment when _MIGRATIONS grows.
SCHEMA_VERSION: int = 1

#: Import size limits.  Conservative defaults for a local demo tool.
#: MAX_IMPORT_RECORDS: hard cap on records per parse_json_events / parse_csv_events call.
MAX_IMPORT_RECORDS: int = 10_000
#: MAX_IMPORT_BYTES: hard cap on raw JSON/CSV string size fed to parsers.
MAX_IMPORT_BYTES: int = 50 * 1024 * 1024  # 50 MB

#: Analyst note maximum length.
MAX_ANALYST_NOTE_LEN: int = 4096

#: Allowed incident status values.
INCIDENT_STATUSES: Tuple[str, ...] = ("New", "Investigating", "Resolved")

#: Allowed incident disposition values.
INCIDENT_DISPOSITIONS: Tuple[str, ...] = (
    "Undetermined",
    "True Positive",
    "False Positive",
)

# ---------------------------------------------------------------------------
# UTC timestamp helpers
# ---------------------------------------------------------------------------

TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def _now_utc() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(tz=timezone.utc).strftime(TS_FORMAT)


def _dt_to_str(dt: datetime) -> str:
    """Convert a UTC-aware datetime to the canonical storage string."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime(TS_FORMAT)


def _str_to_dt(s: str) -> datetime:
    """Parse a stored UTC timestamp string back to a UTC-aware datetime."""
    return datetime.strptime(s, TS_FORMAT).replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Content fingerprint
# ---------------------------------------------------------------------------

def _event_content_hash(evt: NormalizedEvent) -> str:
    """
    Produce a deterministic SHA-256 fingerprint of a NormalizedEvent's content.

    Used to detect whether two records with the same event_id are genuinely
    identical or represent conflicting imports.  Only forensically significant
    fields are hashed; storage metadata (import_batch, imported_at) is excluded.
    """
    parts = "|".join([
        evt.event_id,
        _dt_to_str(evt.timestamp),
        evt.source_ip,
        evt.username,
        evt.event_type,
        evt.outcome,
        evt.hostname or "",
        evt.source_type or "",
        evt.source_reference or "",
    ])
    return hashlib.sha256(parts.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Schema migrations
# ---------------------------------------------------------------------------

# Each entry is (version_number, sql_statements_list).
# Migrations run in order during init_db.  Add new tuples to extend the schema.
_MIGRATIONS: List[Tuple[int, List[str]]] = [
    (
        1,
        [
            # Track applied schema versions.
            """
            CREATE TABLE IF NOT EXISTS schema_version (
                version     INTEGER PRIMARY KEY,
                applied_at  TEXT NOT NULL
            )
            """,

            # Import batches: metadata about each import run.
            # source_name is a safe display label (never raw file path contents).
            """
            CREATE TABLE IF NOT EXISTS import_batches (
                batch_id    TEXT    PRIMARY KEY,
                source_name TEXT    NOT NULL,
                imported_at TEXT    NOT NULL,
                total       INTEGER NOT NULL DEFAULT 0,
                accepted    INTEGER NOT NULL DEFAULT 0,
                rejected    INTEGER NOT NULL DEFAULT 0,
                duplicates  INTEGER NOT NULL DEFAULT 0,
                conflicts   INTEGER NOT NULL DEFAULT 0,
                status      TEXT    NOT NULL DEFAULT 'completed'
                            CHECK(status IN ('completed', 'partial', 'failed'))
            )
            """,

            # Normalized events persisted from the detection engine.
            # content_hash differentiates genuine duplicates from ID collisions.
            """
            CREATE TABLE IF NOT EXISTS events (
                row_id          INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id        TEXT    NOT NULL,
                content_hash    TEXT    NOT NULL,
                source_ip       TEXT    NOT NULL,
                username        TEXT    NOT NULL,
                event_type      TEXT    NOT NULL,
                outcome         TEXT    NOT NULL,
                timestamp       TEXT    NOT NULL,
                hostname        TEXT,
                source_type     TEXT,
                source_reference TEXT,
                import_batch_id TEXT    REFERENCES import_batches(batch_id)
                                        ON DELETE SET NULL,
                imported_at     TEXT    NOT NULL,
                UNIQUE(event_id, content_hash)
            )
            """,

            # Index for the most common detection query: fetch events by IP and type.
            "CREATE INDEX IF NOT EXISTS idx_events_ip ON events(source_ip)",
            "CREATE INDEX IF NOT EXISTS idx_events_username ON events(username)",
            "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_events_batch ON events(import_batch_id)",

            # Incidents produced by the detection engine.
            # affected_usernames is stored as a JSON array string.
            # analyst_notes is plain text; treated as data, not executed.
            """
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id         TEXT    PRIMARY KEY,
                detection_id        TEXT    NOT NULL UNIQUE,
                rule_id             TEXT    NOT NULL,
                title               TEXT    NOT NULL,
                explanation         TEXT    NOT NULL,
                severity            TEXT    NOT NULL
                                    CHECK(severity IN ('Low','Medium','High','Critical')),
                confidence          TEXT    NOT NULL
                                    CHECK(confidence IN ('Low','Medium','High')),
                source_ip           TEXT    NOT NULL,
                affected_usernames  TEXT    NOT NULL,
                mitre_technique     TEXT,
                first_seen          TEXT    NOT NULL,
                last_seen           TEXT    NOT NULL,
                status              TEXT    NOT NULL DEFAULT 'New'
                                    CHECK(status IN ('New','Investigating','Resolved')),
                disposition         TEXT    NOT NULL DEFAULT 'Undetermined'
                                    CHECK(disposition IN ('Undetermined','True Positive','False Positive')),
                analyst_notes       TEXT    NOT NULL DEFAULT '',
                recommended_action  TEXT    NOT NULL DEFAULT '',
                created_at          TEXT    NOT NULL,
                updated_at          TEXT    NOT NULL
            )
            """,

            "CREATE INDEX IF NOT EXISTS idx_incidents_rule ON incidents(rule_id)",
            "CREATE INDEX IF NOT EXISTS idx_incidents_ip ON incidents(source_ip)",
            "CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)",

            # Many-to-many: which events support which incidents.
            # A single event can support multiple incidents (spray + brute-force).
            """
            CREATE TABLE IF NOT EXISTS incident_evidence (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT    NOT NULL REFERENCES incidents(incident_id)
                                    ON DELETE CASCADE,
                event_id    TEXT    NOT NULL,
                added_at    TEXT    NOT NULL,
                UNIQUE(incident_id, event_id)
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_evidence_incident ON incident_evidence(incident_id)",
            "CREATE INDEX IF NOT EXISTS idx_evidence_event ON incident_evidence(event_id)",
        ],
    ),
]


# ---------------------------------------------------------------------------
# Connection management
# ---------------------------------------------------------------------------

def _get_connection(db_path: Path) -> sqlite3.Connection:
    """
    Open a SQLite connection with foreign-key enforcement and row-factory set.

    Always enable foreign keys on each new connection — SQLite resets this
    pragma per connection and does NOT inherit it from previous sessions.
    """
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")   # safer concurrent reads
    return conn


@contextmanager
def _transaction(conn: sqlite3.Connection) -> Generator[sqlite3.Connection, None, None]:
    """
    Context manager that commits on success and rolls back on any exception.

    Usage::
        with _transaction(conn) as c:
            c.execute(...)
    """
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


# ---------------------------------------------------------------------------
# Initialization / migration
# ---------------------------------------------------------------------------

def init_db(db_path: Path = DEFAULT_DB_PATH) -> None:
    """
    Create the database file and apply any pending schema migrations.

    Safe to call multiple times — migrations are idempotent and only apply
    versions greater than the current recorded version.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = _get_connection(db_path)
    try:
        # Bootstrap: ensure schema_version table exists before querying it.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS schema_version (
                version    INTEGER PRIMARY KEY,
                applied_at TEXT    NOT NULL
            )
        """)
        conn.commit()

        current = conn.execute(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version"
        ).fetchone()[0]

        for version, statements in _MIGRATIONS:
            if version <= current:
                continue
            with _transaction(conn) as c:
                for sql in statements:
                    c.execute(sql)
                c.execute(
                    "INSERT OR IGNORE INTO schema_version(version, applied_at) VALUES (?,?)",
                    (version, _now_utc()),
                )
    finally:
        conn.close()


def get_schema_version(db_path: Path = DEFAULT_DB_PATH) -> int:
    """Return the highest applied schema version, or 0 if none."""
    conn = _get_connection(db_path)
    try:
        row = conn.execute(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version"
        ).fetchone()
        return int(row[0])
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Import-batch management
# ---------------------------------------------------------------------------

def create_import_batch(
    batch_id: str,
    source_name: str,
    db_path: Path = DEFAULT_DB_PATH,
) -> None:
    """
    Register a new import batch record with zero counts.

    batch_id should be a stable, externally generated ID (e.g. a UUID or
    a hash of the source file content).  source_name is a display label
    such as a filename; never store raw path contents here.
    """
    conn = _get_connection(db_path)
    try:
        with _transaction(conn) as c:
            c.execute(
                """
                INSERT INTO import_batches
                    (batch_id, source_name, imported_at, total, accepted,
                     rejected, duplicates, conflicts, status)
                VALUES (?,?,?,0,0,0,0,0,'completed')
                """,
                (batch_id, source_name, _now_utc()),
            )
    finally:
        conn.close()


def update_import_batch(
    batch_id: str,
    total: int,
    accepted: int,
    rejected: int,
    duplicates: int,
    conflicts: int,
    status: str = "completed",
    db_path: Path = DEFAULT_DB_PATH,
) -> None:
    """Update counts and final status for an existing import batch."""
    if status not in ("completed", "partial", "failed"):
        raise ValueError(f"Invalid batch status: {status!r}")
    conn = _get_connection(db_path)
    try:
        with _transaction(conn) as c:
            c.execute(
                """
                UPDATE import_batches
                   SET total=?, accepted=?, rejected=?, duplicates=?,
                       conflicts=?, status=?
                 WHERE batch_id=?
                """,
                (total, accepted, rejected, duplicates, conflicts, status, batch_id),
            )
    finally:
        conn.close()


def get_import_batch(
    batch_id: str,
    db_path: Path = DEFAULT_DB_PATH,
) -> Optional[Dict[str, Any]]:
    """Return batch metadata as a dict, or None if not found."""
    conn = _get_connection(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM import_batches WHERE batch_id=?", (batch_id,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Event persistence
# ---------------------------------------------------------------------------

class EventSaveResult:
    """Result of a single save_event call."""

    __slots__ = ("status", "event_id", "content_hash", "reason")

    def __init__(
        self,
        status: str,
        event_id: str,
        content_hash: str,
        reason: str = "",
    ) -> None:
        #: "accepted" | "duplicate" | "conflict"
        self.status = status
        self.event_id = event_id
        self.content_hash = content_hash
        #: Human-readable explanation for non-accepted results.
        self.reason = reason


def save_event(
    evt: NormalizedEvent,
    batch_id: Optional[str] = None,
    db_path: Path = DEFAULT_DB_PATH,
) -> EventSaveResult:
    """
    Persist a single NormalizedEvent.

    Duplicate policy:
    - Same event_id + same content_hash → "duplicate" (skipped, not an error).
    - Same event_id + different content_hash → "conflict" (rejected, original kept).
    - New event_id → "accepted".

    Returns an EventSaveResult describing the outcome.
    """
    h = _event_content_hash(evt)
    conn = _get_connection(db_path)
    try:
        existing = conn.execute(
            "SELECT content_hash FROM events WHERE event_id=?",
            (evt.event_id,),
        ).fetchone()

        if existing is not None:
            stored_hash = existing["content_hash"]
            if stored_hash == h:
                return EventSaveResult("duplicate", evt.event_id, h)
            else:
                return EventSaveResult(
                    "conflict",
                    evt.event_id,
                    h,
                    reason=(
                        f"event_id {evt.event_id!r} already exists with a different "
                        f"content hash.  Original evidence preserved."
                    ),
                )

        with _transaction(conn) as c:
            c.execute(
                """
                INSERT INTO events
                    (event_id, content_hash, source_ip, username, event_type,
                     outcome, timestamp, hostname, source_type, source_reference,
                     import_batch_id, imported_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    evt.event_id,
                    h,
                    evt.source_ip,
                    evt.username,
                    evt.event_type,
                    evt.outcome,
                    _dt_to_str(evt.timestamp),
                    evt.hostname,
                    evt.source_type,
                    evt.source_reference,
                    batch_id,
                    _now_utc(),
                ),
            )
        return EventSaveResult("accepted", evt.event_id, h)
    finally:
        conn.close()


def save_events_batch(
    events: List[NormalizedEvent],
    batch_id: Optional[str] = None,
    db_path: Path = DEFAULT_DB_PATH,
) -> Dict[str, int]:
    """
    Persist a list of NormalizedEvents in a single transaction.

    Returns a dict with keys: accepted, duplicate, conflict.
    On any unexpected error, the entire batch is rolled back and the exception
    is re-raised.
    """
    counts: Dict[str, int] = {"accepted": 0, "duplicate": 0, "conflict": 0}
    conn = _get_connection(db_path)
    try:
        with _transaction(conn) as c:
            for evt in events:
                h = _event_content_hash(evt)
                existing = c.execute(
                    "SELECT content_hash FROM events WHERE event_id=?",
                    (evt.event_id,),
                ).fetchone()

                if existing is not None:
                    stored_hash = existing["content_hash"]
                    if stored_hash == h:
                        counts["duplicate"] += 1
                    else:
                        counts["conflict"] += 1
                    continue

                c.execute(
                    """
                    INSERT INTO events
                        (event_id, content_hash, source_ip, username, event_type,
                         outcome, timestamp, hostname, source_type, source_reference,
                         import_batch_id, imported_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        evt.event_id,
                        h,
                        evt.source_ip,
                        evt.username,
                        evt.event_type,
                        evt.outcome,
                        _dt_to_str(evt.timestamp),
                        evt.hostname,
                        evt.source_type,
                        evt.source_reference,
                        batch_id,
                        _now_utc(),
                    ),
                )
                counts["accepted"] += 1
    finally:
        conn.close()

    return counts


def get_event(
    event_id: str,
    db_path: Path = DEFAULT_DB_PATH,
) -> Optional[Dict[str, Any]]:
    """Return a single event by event_id, or None if not found."""
    conn = _get_connection(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM events WHERE event_id=?", (event_id,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_events(
    limit: int = 100,
    offset: int = 0,
    source_ip: Optional[str] = None,
    username: Optional[str] = None,
    db_path: Path = DEFAULT_DB_PATH,
) -> List[Dict[str, Any]]:
    """
    Return a bounded, paginated list of events, optionally filtered.

    limit is capped at 1000 to prevent accidental full-table scans in the UI.
    """
    limit = min(limit, 1000)
    params: List[Any] = []
    where_clauses: List[str] = []

    if source_ip is not None:
        where_clauses.append("source_ip = ?")
        params.append(source_ip)
    if username is not None:
        where_clauses.append("username = ?")
        params.append(username)

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
    sql = f"SELECT * FROM events {where_sql} ORDER BY timestamp ASC LIMIT ? OFFSET ?"
    params += [limit, offset]

    conn = _get_connection(db_path)
    try:
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Incident persistence
# ---------------------------------------------------------------------------

def _incident_id_from_detection_id(detection_id: str) -> str:
    """
    Derive a stable incident_id from a detection_id.

    A short SHA-256 prefix ensures the incident_id is always a fixed-length
    string regardless of the detection_id format.
    """
    return "INC-" + hashlib.sha256(detection_id.encode()).hexdigest()[:12]


def save_incident(
    detection: Detection,
    db_path: Path = DEFAULT_DB_PATH,
) -> Tuple[str, str]:
    """
    Persist a Detection as an Incident.

    Returns (incident_id, action) where action is "created" or "updated".

    Reprocessing policy:
    - If no incident exists for this detection_id → create it.
    - If an incident already exists → update first_seen, last_seen and evidence
      only.  Status, disposition, and analyst_notes are left untouched.
    - Evidence links (incident_evidence rows) are appended; existing links are
      never deleted.
    """
    incident_id = _incident_id_from_detection_id(detection.detection_id)
    now = _now_utc()
    first_seen_s = _dt_to_str(detection.first_seen)
    last_seen_s = _dt_to_str(detection.last_seen)
    affected_json = json.dumps(sorted(detection.affected_usernames))

    conn = _get_connection(db_path)
    try:
        existing = conn.execute(
            "SELECT incident_id FROM incidents WHERE detection_id=?",
            (detection.detection_id,),
        ).fetchone()

        with _transaction(conn) as c:
            if existing is None:
                c.execute(
                    """
                    INSERT INTO incidents (
                        incident_id, detection_id, rule_id, title, explanation,
                        severity, confidence, source_ip, affected_usernames,
                        mitre_technique, first_seen, last_seen, status, disposition,
                        analyst_notes, recommended_action, created_at, updated_at
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,'New','Undetermined','',?,?,?)
                    """,
                    (
                        incident_id,
                        detection.detection_id,
                        detection.rule_id,
                        detection.title,
                        detection.explanation,
                        detection.severity,
                        detection.confidence,
                        detection.source_ip,
                        affected_json,
                        detection.mitre_technique,
                        first_seen_s,
                        last_seen_s,
                        detection.recommended_action,
                        now,
                        now,
                    ),
                )
                action = "created"
            else:
                # Update timestamps if the new detection covers a wider window.
                c.execute(
                    """
                    UPDATE incidents
                       SET first_seen  = MIN(first_seen, ?),
                           last_seen   = MAX(last_seen, ?),
                           updated_at  = ?
                     WHERE detection_id = ?
                    """,
                    (first_seen_s, last_seen_s, now, detection.detection_id),
                )
                action = "updated"

            # Upsert evidence links — IGNORE silently skips existing (inc_id, event_id) pairs.
            for eid in detection.event_ids:
                c.execute(
                    """
                    INSERT OR IGNORE INTO incident_evidence
                        (incident_id, event_id, added_at)
                    VALUES (?,?,?)
                    """,
                    (incident_id, eid, now),
                )

        return incident_id, action
    finally:
        conn.close()


def save_detections(
    detections: List[Detection],
    db_path: Path = DEFAULT_DB_PATH,
) -> Dict[str, int]:
    """
    Persist a list of Detection objects transactionally.

    Returns counts: {"created": N, "updated": N, "errors": N}.
    Each detection is saved individually so that one failure does not roll
    back the entire batch.
    """
    counts: Dict[str, int] = {"created": 0, "updated": 0, "errors": 0}
    for det in detections:
        try:
            _, action = save_incident(det, db_path=db_path)
            counts[action] += 1
        except Exception:
            counts["errors"] += 1
    return counts


def get_incident(
    incident_id: str,
    db_path: Path = DEFAULT_DB_PATH,
) -> Optional[Dict[str, Any]]:
    """Return an incident and its evidence event IDs, or None if not found."""
    conn = _get_connection(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM incidents WHERE incident_id=?", (incident_id,)
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        evidence_rows = conn.execute(
            "SELECT event_id FROM incident_evidence WHERE incident_id=? ORDER BY added_at",
            (incident_id,),
        ).fetchall()
        result["evidence_event_ids"] = [r["event_id"] for r in evidence_rows]
        result["affected_usernames"] = json.loads(result["affected_usernames"])
        return result
    finally:
        conn.close()


def list_incidents(
    limit: int = 50,
    offset: int = 0,
    status: Optional[str] = None,
    db_path: Path = DEFAULT_DB_PATH,
) -> List[Dict[str, Any]]:
    """
    Return a paginated list of incidents, optionally filtered by status.

    limit is capped at 500.
    """
    limit = min(limit, 500)
    params: List[Any] = []
    where = ""
    if status is not None:
        if status not in INCIDENT_STATUSES:
            raise ValueError(f"Invalid status: {status!r}. Must be one of {INCIDENT_STATUSES}")
        where = "WHERE status = ?"
        params.append(status)
    params += [limit, offset]

    conn = _get_connection(db_path)
    try:
        rows = conn.execute(
            f"SELECT * FROM incidents {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params,
        ).fetchall()
        results = []
        for row in rows:
            d = dict(row)
            d["affected_usernames"] = json.loads(d["affected_usernames"])
            results.append(d)
        return results
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Analyst workflow
# ---------------------------------------------------------------------------

def update_incident_status(
    incident_id: str,
    status: str,
    db_path: Path = DEFAULT_DB_PATH,
) -> None:
    """
    Change an incident's status.

    Raises ValueError for unsupported status values or unknown incident IDs.
    """
    if status not in INCIDENT_STATUSES:
        raise ValueError(
            f"Invalid status: {status!r}. Supported: {INCIDENT_STATUSES}"
        )
    conn = _get_connection(db_path)
    try:
        row = conn.execute(
            "SELECT incident_id FROM incidents WHERE incident_id=?", (incident_id,)
        ).fetchone()
        if row is None:
            raise ValueError(f"Incident not found: {incident_id!r}")
        with _transaction(conn) as c:
            c.execute(
                "UPDATE incidents SET status=?, updated_at=? WHERE incident_id=?",
                (status, _now_utc(), incident_id),
            )
    finally:
        conn.close()


def update_incident_disposition(
    incident_id: str,
    disposition: str,
    db_path: Path = DEFAULT_DB_PATH,
) -> None:
    """
    Set an incident's disposition.

    Raises ValueError for unsupported disposition values or unknown incident IDs.
    """
    if disposition not in INCIDENT_DISPOSITIONS:
        raise ValueError(
            f"Invalid disposition: {disposition!r}. Supported: {INCIDENT_DISPOSITIONS}"
        )
    conn = _get_connection(db_path)
    try:
        row = conn.execute(
            "SELECT incident_id FROM incidents WHERE incident_id=?", (incident_id,)
        ).fetchone()
        if row is None:
            raise ValueError(f"Incident not found: {incident_id!r}")
        with _transaction(conn) as c:
            c.execute(
                "UPDATE incidents SET disposition=?, updated_at=? WHERE incident_id=?",
                (disposition, _now_utc(), incident_id),
            )
    finally:
        conn.close()


def add_analyst_note(
    incident_id: str,
    note: str,
    db_path: Path = DEFAULT_DB_PATH,
) -> None:
    """
    Append a timestamped note to an incident's analyst_notes field.

    Notes are stored as plain text.  They are never executed.
    Maximum cumulative length per incident is MAX_ANALYST_NOTE_LEN * 10
    (to allow many notes while preventing unbounded growth).
    The individual note is capped at MAX_ANALYST_NOTE_LEN characters.

    Raises ValueError for oversized notes or unknown incident IDs.
    """
    if not isinstance(note, str):
        raise ValueError("Note must be a string.")
    if len(note) > MAX_ANALYST_NOTE_LEN:
        raise ValueError(
            f"Note exceeds maximum length of {MAX_ANALYST_NOTE_LEN} characters."
        )

    conn = _get_connection(db_path)
    try:
        row = conn.execute(
            "SELECT analyst_notes FROM incidents WHERE incident_id=?",
            (incident_id,),
        ).fetchone()
        if row is None:
            raise ValueError(f"Incident not found: {incident_id!r}")

        existing = row["analyst_notes"] or ""
        entry = f"[{_now_utc()}] {note}"
        separator = "\n" if existing else ""
        new_notes = existing + separator + entry

        # Guard against unbounded accumulation
        if len(new_notes) > MAX_ANALYST_NOTE_LEN * 10:
            raise ValueError(
                "Analyst notes have reached the maximum cumulative length for this incident."
            )

        with _transaction(conn) as c:
            c.execute(
                "UPDATE incidents SET analyst_notes=?, updated_at=? WHERE incident_id=?",
                (new_notes, _now_utc(), incident_id),
            )
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Load stored events for re-detection
# ---------------------------------------------------------------------------

def load_all_events_for_detection(
    db_path: Path = DEFAULT_DB_PATH,
) -> List[NormalizedEvent]:
    """
    Reconstruct NormalizedEvent objects for every row in the events table.

    This lets the detection pipeline be run against the full stored dataset —
    useful when the caller wants to re-detect on all events, not just a
    freshly parsed batch (e.g. after a duplicate-only import, or when the
    user clicks "Run Detection" explicitly).

    The list is sorted by timestamp ascending so sliding-window rules work
    correctly without re-sorting.
    """
    conn = _get_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM events ORDER BY timestamp ASC"
        ).fetchall()
    finally:
        conn.close()

    events: List[NormalizedEvent] = []
    for row in rows:
        r = dict(row)
        try:
            evt = NormalizedEvent(
                event_id=r["event_id"],
                timestamp=_str_to_dt(r["timestamp"]),
                source_ip=r["source_ip"],
                username=r["username"],
                event_type=r["event_type"],
                outcome=r["outcome"],
                hostname=r.get("hostname"),
                source_type=r.get("source_type"),
                source_reference=r.get("source_reference"),
                import_batch=r.get("import_batch_id"),
            )
            events.append(evt)
        except Exception:
            # Skip rows that cannot be reconstructed (should not happen with a
            # well-maintained DB, but we must not abort the whole load).
            continue
    return events


# ---------------------------------------------------------------------------
# Detection-engine integration
# ---------------------------------------------------------------------------

def run_detection_pipeline(
    events: List[NormalizedEvent],
    db_path: Path = DEFAULT_DB_PATH,
    thresholds=None,
) -> Dict[str, int]:
    """
    Run the full detection pipeline and persist results.

    Steps:
    1. Run run_all_detections on the provided NormalizedEvent list.
    2. Save each Detection as an Incident (create or update).
    3. Return counts: new_incidents, updated_incidents, detection_errors.

    The function does NOT save events itself — call save_events_batch first so
    the caller controls batch metadata and duplicate handling.
    """
    from engine import run_all_detections

    detections = run_all_detections(events, thresholds=thresholds)
    counts = save_detections(detections, db_path=db_path)
    return {
        "new_incidents": counts.get("created", 0),
        "updated_incidents": counts.get("updated", 0),
        "detection_errors": counts.get("errors", 0),
        "total_detections": len(detections),
    }
