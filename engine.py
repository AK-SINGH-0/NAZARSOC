"""
engine.py — NazarSOC Detection Engine (Phase 1)

Responsibilities
----------------
- Parse and validate events from JSON dicts or CSV rows.
- Normalize field values to a canonical form.
- Detect three authentication-abuse patterns.
- Return structured, explainable detections.

This module is intentionally independent of Streamlit and SQLite so that
it can be imported and tested directly from the CLI or unittest.

MITRE ATT&CK references
-----------------------
T1110.001  Brute Force: Password Guessing
T1110.003  Brute Force: Password Spraying
"""

from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Field-length limits
# Documented maximums for free-text fields.  Chosen to be generous enough for
# real identifiers while preventing unbounded memory from adversarial input.
# ---------------------------------------------------------------------------

MAX_EVENT_ID_LEN: int = 256
MAX_USERNAME_LEN: int = 256
MAX_HOSTNAME_LEN: int = 253      # RFC 1035 DNS name limit
MAX_SOURCE_REF_LEN: int = 512
MAX_SOURCE_TYPE_LEN: int = 128
MAX_IMPORT_BATCH_LEN: int = 128
MAX_IP_LEN: int = 45             # longest IPv6 with zone ID


# ---------------------------------------------------------------------------
# Schema constants
# ---------------------------------------------------------------------------

#: Fields that must be present and non-empty for detection rules to run.
REQUIRED_FIELDS: Tuple[str, ...] = (
    "event_id",
    "timestamp",
    "source_ip",
    "username",
    "event_type",
    "outcome",
)

#: All recognised event types (lower-cased).
SUPPORTED_EVENT_TYPES: Tuple[str, ...] = (
    "authentication",
    "logon",
    "logoff",
    "account_lockout",
    "password_change",
)

#: All recognised outcome values (lower-cased).
SUPPORTED_OUTCOMES: Tuple[str, ...] = (
    "success",
    "failure",
    "unknown",
)

#: Optional fields included in the normalised schema; None is the default.
OPTIONAL_FIELDS: Tuple[str, ...] = (
    "hostname",
    "source_type",
    "source_reference",
    "import_batch",
)


# ---------------------------------------------------------------------------
# Detection thresholds (configurable — override before calling detect_*)
# ---------------------------------------------------------------------------

class Thresholds:
    """Central place to tune detection thresholds without touching rule logic."""

    # Rule A — Repeated authentication failures (brute-force per account)
    BRUTE_FORCE_MIN_FAILURES: int = 5
    BRUTE_FORCE_WINDOW_SECONDS: int = 5 * 60   # 5 minutes

    # Rule B — Password spraying (many accounts, one source IP)
    SPRAY_MIN_FAILURES: int = 10
    SPRAY_MIN_DISTINCT_USERS: int = 5
    SPRAY_WINDOW_SECONDS: int = 10 * 60         # 10 minutes

    # Rule C — Failures followed by success (possible successful brute-force)
    FFS_MIN_FAILURES: int = 3
    FFS_WINDOW_SECONDS: int = 10 * 60           # 10 minutes


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class NormalizedEvent:
    """A validated, normalised representation of a single log event."""

    event_id: str
    timestamp: datetime          # always UTC-aware
    source_ip: str
    username: str                # lower-cased
    event_type: str              # lower-cased, validated
    outcome: str                 # lower-cased, validated
    hostname: Optional[str] = None
    source_type: Optional[str] = None
    source_reference: Optional[str] = None
    import_batch: Optional[str] = None


@dataclass
class ParseError:
    """Describes why a raw record could not be parsed or normalised."""

    raw: Dict[str, Any]
    reason: str


@dataclass
class Detection:
    """
    A single detection produced by the engine.

    Severity rationale
    ------------------
    - High  : Patterns with strong forensic signal (brute-force success, spray)
    - Medium: Moderate signal requiring analyst review (brute-force failures only)
    - Low   : Weak or noisy patterns

    Confidence rationale
    --------------------
    - High  : Threshold significantly exceeded; low chance of false positive
    - Medium: Threshold met but not greatly exceeded; analyst should verify
    - Low   : At or near threshold; may be benign

    Note: severity and confidence are independent.  A high-severity pattern
    (e.g. failures-then-success) may still carry medium confidence because the
    evidence could reflect a legitimate user who forgot their password.
    """

    rule_id: str                    # e.g. "RULE_A"
    detection_id: str               # deterministic hash for deduplication
    title: str
    explanation: str
    severity: str                   # "Low" | "Medium" | "High" | "Critical"
    confidence: str                 # "Low" | "Medium" | "High"
    source_ip: str
    affected_usernames: List[str]
    first_seen: datetime
    last_seen: datetime
    event_ids: List[str]
    recommended_action: str
    mitre_technique: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _parse_timestamp(raw: str) -> datetime:
    """
    Parse an ISO-8601 timestamp string and return a UTC-aware datetime.

    Accepts:
        - "2024-01-15T10:00:00Z"
        - "2024-01-15T10:00:00+00:00"
        - "2024-01-15T10:00:00" (assumed UTC — no offset information)

    Raises:
        ValueError: if the string cannot be interpreted as a valid timestamp.
    """
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("Timestamp must be a non-empty string.")

    ts = raw.strip()

    # Replace trailing 'Z' with '+00:00' for fromisoformat compatibility
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        raise ValueError(f"Invalid ISO-8601 timestamp: {raw!r}")

    # If no timezone info was provided, treat as UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        # Normalise any offset to UTC
        dt = dt.astimezone(timezone.utc)

    return dt


def _normalize_string(value: Any) -> str:
    """Strip and lower-case a string field."""
    if not isinstance(value, str):
        raise ValueError(f"Expected a string, got {type(value).__name__}: {value!r}")
    return value.strip().lower()


def normalize_event(raw: Dict[str, Any]) -> Tuple[Optional[NormalizedEvent], Optional[ParseError]]:
    """
    Validate and normalise a raw event dict.

    Returns (NormalizedEvent, None) on success, (None, ParseError) on failure.
    Original field values are preserved in ParseError.raw so that forensic
    context is never destroyed by normalisation.
    """
    # --- Check required fields are present and non-empty ---
    for f in REQUIRED_FIELDS:
        val = raw.get(f)
        if val is None or (isinstance(val, str) and not val.strip()):
            return None, ParseError(raw=raw, reason=f"Missing required field: '{f}'")

    # --- Validate event_type ---
    try:
        event_type = _normalize_string(raw["event_type"])
    except ValueError as exc:
        return None, ParseError(raw=raw, reason=str(exc))

    if event_type not in SUPPORTED_EVENT_TYPES:
        return None, ParseError(
            raw=raw,
            reason=(
                f"Unsupported event_type: {raw['event_type']!r}. "
                f"Supported: {SUPPORTED_EVENT_TYPES}"
            ),
        )

    # --- Validate outcome ---
    try:
        outcome = _normalize_string(raw["outcome"])
    except ValueError as exc:
        return None, ParseError(raw=raw, reason=str(exc))

    if outcome not in SUPPORTED_OUTCOMES:
        return None, ParseError(
            raw=raw,
            reason=(
                f"Unsupported outcome: {raw['outcome']!r}. "
                f"Supported: {SUPPORTED_OUTCOMES}"
            ),
        )

    # --- Parse timestamp ---
    try:
        timestamp = _parse_timestamp(str(raw["timestamp"]))
    except ValueError as exc:
        return None, ParseError(raw=raw, reason=str(exc))

    # --- Normalise remaining required fields ---

    # event_id: must be a string (not silently coerced from dict/list/int).
    if not isinstance(raw["event_id"], str):
        return None, ParseError(
            raw=raw,
            reason=(
                f"event_id must be a string, got {type(raw['event_id']).__name__}: "
                f"{raw['event_id']!r}"
            ),
        )
    event_id = raw["event_id"].strip()
    if not event_id:
        return None, ParseError(raw=raw, reason="Missing required field: 'event_id'")
    if len(event_id) > MAX_EVENT_ID_LEN:
        return None, ParseError(
            raw=raw,
            reason=f"event_id exceeds maximum length of {MAX_EVENT_ID_LEN} characters.",
        )

    # source_ip: must be a string and a valid IPv4 or IPv6 address.
    if not isinstance(raw["source_ip"], str):
        return None, ParseError(
            raw=raw,
            reason=(
                f"source_ip must be a string, got {type(raw['source_ip']).__name__}: "
                f"{raw['source_ip']!r}"
            ),
        )
    source_ip = raw["source_ip"].strip()
    if not source_ip:
        return None, ParseError(raw=raw, reason="Missing required field: 'source_ip'")
    try:
        ipaddress.ip_address(source_ip)
    except ValueError:
        return None, ParseError(
            raw=raw,
            reason=f"source_ip is not a valid IPv4 or IPv6 address: {source_ip!r}",
        )

    # username: wrap in try/except so a non-string value (int, list, …) returns a
    # ParseError instead of raising an unhandled ValueError to the caller.
    try:
        username = _normalize_string(raw["username"])
    except ValueError as exc:
        return None, ParseError(raw=raw, reason=str(exc))
    if len(username) > MAX_USERNAME_LEN:
        return None, ParseError(
            raw=raw,
            reason=f"username exceeds maximum length of {MAX_USERNAME_LEN} characters.",
        )

    # --- Optional fields (None if absent or empty, length-capped) ---
    _OPTIONAL_LIMITS = {
        "hostname": MAX_HOSTNAME_LEN,
        "source_type": MAX_SOURCE_TYPE_LEN,
        "source_reference": MAX_SOURCE_REF_LEN,
        "import_batch": MAX_IMPORT_BATCH_LEN,
    }

    def _optional(key: str) -> Optional[str]:
        v = raw.get(key)
        if v is None:
            return None
        s = str(v).strip()
        if not s:
            return None
        limit = _OPTIONAL_LIMITS.get(key)
        if limit and len(s) > limit:
            # Reject rather than silently truncate — truncation would destroy
            # forensic meaning (e.g. a partial hostname is misleading).
            raise ValueError(
                f"Field '{key}' exceeds maximum length of {limit} characters."
            )
        return s

    try:
        hostname = _optional("hostname")
        source_type = _optional("source_type")
        source_reference = _optional("source_reference")
        import_batch_field = _optional("import_batch")
    except ValueError as exc:
        return None, ParseError(raw=raw, reason=str(exc))

    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        source_ip=source_ip,
        username=username,
        event_type=event_type,
        outcome=outcome,
        hostname=hostname,
        source_type=source_type,
        source_reference=source_reference,
        import_batch=import_batch_field,
    ), None


# ---------------------------------------------------------------------------
# Bulk parsers — JSON and CSV
# ---------------------------------------------------------------------------

def parse_json_events(
    data: str | List[Dict[str, Any]],
) -> Tuple[List[NormalizedEvent], List[ParseError]]:
    """
    Parse events from a JSON string or a pre-decoded list of dicts.

    Returns a tuple of (good_events, errors).
    """
    if isinstance(data, str):
        try:
            records = json.loads(data)
        except json.JSONDecodeError as exc:
            return [], [ParseError(raw={}, reason=f"JSON decode error: {exc}")]
        if not isinstance(records, list):
            return [], [ParseError(raw={}, reason="JSON root must be a list of event objects.")]
    else:
        records = data

    good: List[NormalizedEvent] = []
    errors: List[ParseError] = []

    for record in records:
        if not isinstance(record, dict):
            errors.append(ParseError(raw={"value": record}, reason="Each event must be a JSON object."))
            continue
        evt, err = normalize_event(record)
        if evt is not None:
            good.append(evt)
        else:
            errors.append(err)  # type: ignore[arg-type]

    return good, errors


def parse_csv_events(
    data: str,
) -> Tuple[List[NormalizedEvent], List[ParseError]]:
    """
    Parse events from a CSV string.

    The first row must be a header that includes at least the required fields.
    Extra columns are silently ignored.
    """
    good: List[NormalizedEvent] = []
    errors: List[ParseError] = []

    reader = csv.DictReader(io.StringIO(data))

    if reader.fieldnames is None:
        return [], [ParseError(raw={}, reason="CSV input has no header row.")]

    for i, row in enumerate(reader, start=2):  # line 1 is the header
        raw = dict(row)
        # Strip whitespace from all values produced by the CSV reader
        raw = {k: (v.strip() if v else v) for k, v in raw.items()}
        evt, err = normalize_event(raw)
        if evt is not None:
            good.append(evt)
        else:
            # err is guaranteed non-None when evt is None (normalize_event contract),
            # but we guard explicitly to avoid a silent assert strip under -O.
            if err is not None:
                err.raw["_csv_line"] = i
                errors.append(err)

    return good, errors


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

def _make_detection_id(rule_id: str, source_ip: str, usernames: List[str], window_start: datetime) -> str:
    """
    Produce a deterministic, stable detection ID by hashing the key attributes
    that define a unique detection context.

    Two detections for the same rule, IP, user set, and 5-minute bucket will
    produce the same ID, preventing duplicate rows when events are re-processed.
    """
    # Bucket the window_start to the nearest 5-minute boundary so that slight
    # timing differences between re-imports don't generate new IDs.
    bucket = window_start.replace(
        minute=(window_start.minute // 5) * 5,
        second=0,
        microsecond=0,
    )
    key = f"{rule_id}|{source_ip}|{','.join(sorted(usernames))}|{bucket.isoformat()}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _auth_failures(events: List[NormalizedEvent]) -> List[NormalizedEvent]:
    """Return only authentication/logon failure events."""
    return [
        e for e in events
        if e.event_type in ("authentication", "logon") and e.outcome == "failure"
    ]


def _auth_successes(events: List[NormalizedEvent]) -> List[NormalizedEvent]:
    """Return only authentication/logon success events."""
    return [
        e for e in events
        if e.event_type in ("authentication", "logon") and e.outcome == "success"
    ]


def _sliding_window(
    events: List[NormalizedEvent],
    window_seconds: int,
) -> List[Tuple[datetime, datetime, List[NormalizedEvent]]]:
    """
    Yield all maximal contiguous groups of events that fit within a sliding
    window of `window_seconds`.

    Algorithm: sort events by timestamp; for each event i, expand forward
    while the next event is within the window.  Return each group only once
    (starting from every possible leading event) so the caller can inspect
    the tightest windows.

    Returns a list of (window_start, window_end, events_in_window) tuples.
    """
    if not events:
        return []

    sorted_evts = sorted(events, key=lambda e: e.timestamp)
    window = timedelta(seconds=window_seconds)
    results = []
    n = len(sorted_evts)

    for i in range(n):
        group = [sorted_evts[i]]
        for j in range(i + 1, n):
            if sorted_evts[j].timestamp - sorted_evts[i].timestamp <= window:
                group.append(sorted_evts[j])
            else:
                break
        if len(group) > 1 or i == 0:
            results.append((
                sorted_evts[i].timestamp,
                group[-1].timestamp,
                group,
            ))

    return results


# ---------------------------------------------------------------------------
# Rule A — Repeated authentication failures (brute-force per account)
# ---------------------------------------------------------------------------

def detect_brute_force(
    events: List[NormalizedEvent],
    min_failures: int = Thresholds.BRUTE_FORCE_MIN_FAILURES,
    window_seconds: int = Thresholds.BRUTE_FORCE_WINDOW_SECONDS,
) -> List[Detection]:
    """
    Rule A — Repeated Authentication Failures

    Groups failure events by (source_ip, username) and searches for any
    time window of `window_seconds` containing at least `min_failures` events.

    One detection is emitted per qualifying window.  After a qualifying window
    is found, the scan advances past ALL events in that window so that
    overlapping windows do not emit duplicates, while a later, temporally
    distinct cluster (outside the current window) CAN still produce a separate
    detection.  The seen_ids set provides a final deduplication guard for
    the 5-minute bucketing used by _make_detection_id.

    Severity: Medium  — failures alone don't confirm compromise
    Confidence: Medium — may be legitimate user with forgotten password
    MITRE: T1110.001 (Brute Force: Password Guessing)
    """
    failures = _auth_failures(events)

    # Group by (ip, username)
    groups: Dict[Tuple[str, str], List[NormalizedEvent]] = {}
    for e in failures:
        key = (e.source_ip, e.username)
        groups.setdefault(key, []).append(e)

    detections: List[Detection] = []
    seen_ids: set = set()

    for (ip, username), group_events in groups.items():
        sorted_evts = sorted(group_events, key=lambda e: e.timestamp)

        n = len(sorted_evts)
        window = timedelta(seconds=window_seconds)
        i = 0
        while i < n:
            window_events = [sorted_evts[i]]
            for j in range(i + 1, n):
                if sorted_evts[j].timestamp - sorted_evts[i].timestamp <= window:
                    window_events.append(sorted_evts[j])
                else:
                    break

            if len(window_events) >= min_failures:
                det_id = _make_detection_id("RULE_A", ip, [username], sorted_evts[i].timestamp)
                if det_id not in seen_ids:
                    seen_ids.add(det_id)
                    first = window_events[0].timestamp
                    last = window_events[-1].timestamp
                    evt_ids = [e.event_id for e in window_events]
                    detections.append(Detection(
                        rule_id="RULE_A",
                        detection_id=det_id,
                        title="Repeated Authentication Failures — Possible Brute Force",
                        explanation=(
                            f"{len(window_events)} authentication failures for user '{username}' "
                            f"from {ip} within "
                            f"{int((last - first).total_seconds())} seconds. "
                            f"This volume of failures may indicate an automated password-guessing "
                            f"attack (T1110.001), but could also reflect a legitimate user who has "
                            f"forgotten their credentials. Analyst review is recommended."
                        ),
                        severity="Medium",
                        confidence="Medium",
                        source_ip=ip,
                        affected_usernames=[username],
                        first_seen=first,
                        last_seen=last,
                        event_ids=evt_ids,
                        recommended_action=(
                            "Verify with the account owner whether the failures are expected. "
                            "Consider temporarily locking the account if failures continue. "
                            "Check whether the source IP is known or associated with a VPN."
                        ),
                        mitre_technique="T1110.001",
                        extra={"failure_count": len(window_events), "window_seconds": window_seconds},
                    ))
                # Advance past all events consumed by this window to avoid
                # overlapping-window duplicates for the same cluster.
                i += len(window_events)
            else:
                i += 1

    return detections


# ---------------------------------------------------------------------------
# Rule B — Password spraying
# ---------------------------------------------------------------------------

def detect_password_spray(
    events: List[NormalizedEvent],
    min_failures: int = Thresholds.SPRAY_MIN_FAILURES,
    min_distinct_users: int = Thresholds.SPRAY_MIN_DISTINCT_USERS,
    window_seconds: int = Thresholds.SPRAY_WINDOW_SECONDS,
) -> List[Detection]:
    """
    Rule B — Possible Password Spraying

    Groups failure events by source_ip and searches for a time window of
    `window_seconds` that contains at least `min_failures` failures spread
    across at least `min_distinct_users` distinct usernames.

    Password spraying tries one common password against many accounts to
    avoid per-account lockout thresholds.  A high count of distinct target
    usernames from a single source IP is the distinguishing signal.

    Severity: High   — spraying specifically attempts to evade lockout controls
    Confidence: Medium — a single IP serving many users (e.g. NAT/proxy) could
                         produce similar patterns legitimately
    MITRE: T1110.003 (Brute Force: Password Spraying)
    """
    failures = _auth_failures(events)

    # Group by source_ip
    by_ip: Dict[str, List[NormalizedEvent]] = {}
    for e in failures:
        by_ip.setdefault(e.source_ip, []).append(e)

    detections: List[Detection] = []
    seen_ids: set = set()

    for ip, ip_events in by_ip.items():
        sorted_evts = sorted(ip_events, key=lambda e: e.timestamp)
        n = len(sorted_evts)
        window = timedelta(seconds=window_seconds)
        i = 0
        while i < n:
            window_events: List[NormalizedEvent] = [sorted_evts[i]]
            for j in range(i + 1, n):
                if sorted_evts[j].timestamp - sorted_evts[i].timestamp <= window:
                    window_events.append(sorted_evts[j])
                else:
                    break

            distinct_users = {e.username for e in window_events}

            if len(window_events) >= min_failures and len(distinct_users) >= min_distinct_users:
                det_id = _make_detection_id("RULE_B", ip, list(distinct_users), sorted_evts[i].timestamp)
                if det_id not in seen_ids:
                    seen_ids.add(det_id)
                    first = window_events[0].timestamp
                    last = window_events[-1].timestamp
                    evt_ids = [e.event_id for e in window_events]
                    usernames = sorted(distinct_users)
                    detections.append(Detection(
                        rule_id="RULE_B",
                        detection_id=det_id,
                        title="Possible Password Spraying — Multiple Accounts Targeted",
                        explanation=(
                            f"{len(window_events)} authentication failures from {ip} targeting "
                            f"{len(distinct_users)} distinct accounts "
                            f"({', '.join(usernames[:5])}{'...' if len(usernames) > 5 else ''}) "
                            f"within {int((last - first).total_seconds())} seconds. "
                            f"This pattern is consistent with a password-spraying technique "
                            f"(T1110.003), which attempts one password per account to avoid "
                            f"triggering per-account lockout policies. This activity warrants "
                            f"investigation, but a shared NAT gateway or proxy could produce "
                            f"similar signals from legitimate users."
                        ),
                        severity="High",
                        confidence="Medium",
                        source_ip=ip,
                        affected_usernames=usernames,
                        first_seen=first,
                        last_seen=last,
                        event_ids=evt_ids,
                        recommended_action=(
                            "Correlate the source IP against threat-intelligence feeds. "
                            "Check whether the IP belongs to a known proxy or VPN exit node. "
                            "Review account activity for any of the targeted users. "
                            "Consider blocking the source IP at the perimeter if spraying is confirmed."
                        ),
                        mitre_technique="T1110.003",
                        extra={
                            "failure_count": len(window_events),
                            "distinct_user_count": len(distinct_users),
                            "window_seconds": window_seconds,
                        },
                    ))
                i += len(window_events)
            else:
                i += 1

    return detections


# ---------------------------------------------------------------------------
# Rule C — Failures followed by success
# ---------------------------------------------------------------------------

def detect_failures_then_success(
    events: List[NormalizedEvent],
    min_failures: int = Thresholds.FFS_MIN_FAILURES,
    window_seconds: int = Thresholds.FFS_WINDOW_SECONDS,
) -> List[Detection]:
    """
    Rule C — Repeated Failures Followed by Successful Login

    For each (source_ip, username) pair, checks whether there are at least
    `min_failures` failures followed by a success within `window_seconds`.

    The success event must occur *after* the failures within the window.
    This sequence warrants investigation because it may indicate that an
    automated attack eventually guessed the correct password. However, it
    could equally reflect a legitimate user who mistyped their password
    several times before succeeding.

    Severity: High   — successful login after repeated failures may mean
                       an attacker gained access
    Confidence: Medium — the success may belong to the legitimate account owner
    MITRE: T1110.001 (Brute Force: Password Guessing, culminating in success)
    """
    # Index failures and successes by (ip, username)
    failures_by_key: Dict[Tuple[str, str], List[NormalizedEvent]] = {}
    successes_by_key: Dict[Tuple[str, str], List[NormalizedEvent]] = {}

    for e in events:
        if e.event_type not in ("authentication", "logon"):
            continue
        key = (e.source_ip, e.username)
        if e.outcome == "failure":
            failures_by_key.setdefault(key, []).append(e)
        elif e.outcome == "success":
            successes_by_key.setdefault(key, []).append(e)

    detections: List[Detection] = []
    seen_ids: set = set()

    for key, fail_events in failures_by_key.items():
        ip, username = key
        success_events = successes_by_key.get(key, [])
        if not success_events:
            continue

        sorted_fails = sorted(fail_events, key=lambda e: e.timestamp)
        sorted_successes = sorted(success_events, key=lambda e: e.timestamp)
        window = timedelta(seconds=window_seconds)

        # For each failure window starting point, look for a success within range.
        # After a qualifying window fires, skip forward past all events in that
        # window so that a later distinct cluster can still trigger separately.
        n = len(sorted_fails)
        i = 0
        while i < n:
            # Collect failures within the window starting at sorted_fails[i]
            window_fails: List[NormalizedEvent] = [sorted_fails[i]]
            for j in range(i + 1, n):
                if sorted_fails[j].timestamp - sorted_fails[i].timestamp <= window:
                    window_fails.append(sorted_fails[j])
                else:
                    break

            if len(window_fails) < min_failures:
                i += 1
                continue

            window_start = sorted_fails[i].timestamp
            window_end = window_start + window

            # Count only the failures that precede the candidate success.
            # A success that occurs before min_failures of the window's failures
            # does not represent a brute-force that "finally succeeded".
            qualifying_success = None
            for s in sorted_successes:
                if s.timestamp < window_start or s.timestamp > window_end:
                    continue
                prior_fails = [f for f in window_fails if f.timestamp <= s.timestamp]
                if len(prior_fails) >= min_failures:
                    qualifying_success = s
                    window_fails = prior_fails
                    break

            if qualifying_success is None:
                i += 1
                continue

            det_id = _make_detection_id("RULE_C", ip, [username], sorted_fails[i].timestamp)
            if det_id not in seen_ids:
                seen_ids.add(det_id)
                all_evidence = window_fails + [qualifying_success]
                first = min(e.timestamp for e in all_evidence)
                last = max(e.timestamp for e in all_evidence)
                evt_ids = [e.event_id for e in window_fails] + [qualifying_success.event_id]
                detections.append(Detection(
                    rule_id="RULE_C",
                    detection_id=det_id,
                    title="Repeated Failures Followed by Successful Login — Possible Credential Compromise",
                    explanation=(
                        f"{len(window_fails)} authentication failures for user '{username}' from {ip} "
                        f"followed by a successful login (event {qualifying_success.event_id}) "
                        f"within {int((last - first).total_seconds())} seconds. "
                        f"This sequence may indicate that a brute-force or credential-stuffing "
                        f"attempt (T1110.001) ultimately succeeded. It could also represent a "
                        f"legitimate user who recovered access after multiple failed attempts. "
                        f"Analyst review is recommended before concluding that the account was compromised."
                    ),
                    severity="High",
                    confidence="Medium",
                    source_ip=ip,
                    affected_usernames=[username],
                    first_seen=first,
                    last_seen=last,
                    event_ids=evt_ids,
                    recommended_action=(
                        "Contact the account owner to confirm whether they performed the login. "
                        "Review the post-login session for unusual activity. "
                        "If the owner did not log in, treat this as a potential account compromise: "
                        "reset credentials and revoke active sessions."
                    ),
                    mitre_technique="T1110.001",
                    extra={
                        "failure_count": len(window_fails),
                        "success_event_id": qualifying_success.event_id,
                        "window_seconds": window_seconds,
                    },
                ))
            i += len(window_fails)

    return detections


# ---------------------------------------------------------------------------
# Public API — run all rules at once
# ---------------------------------------------------------------------------

def run_all_detections(
    events: List[NormalizedEvent],
    thresholds: Optional[Thresholds] = None,
) -> List[Detection]:
    """
    Run all three detection rules against the provided event list.

    Pass a custom `Thresholds` instance to override default values.
    Returns a combined, deduplicated list of Detection objects suitable
    for persistence or display.
    """
    t = thresholds or Thresholds()

    all_detections: List[Detection] = []

    all_detections.extend(detect_brute_force(
        events,
        min_failures=t.BRUTE_FORCE_MIN_FAILURES,
        window_seconds=t.BRUTE_FORCE_WINDOW_SECONDS,
    ))
    all_detections.extend(detect_password_spray(
        events,
        min_failures=t.SPRAY_MIN_FAILURES,
        min_distinct_users=t.SPRAY_MIN_DISTINCT_USERS,
        window_seconds=t.SPRAY_WINDOW_SECONDS,
    ))
    all_detections.extend(detect_failures_then_success(
        events,
        min_failures=t.FFS_MIN_FAILURES,
        window_seconds=t.FFS_WINDOW_SECONDS,
    ))

    return all_detections
