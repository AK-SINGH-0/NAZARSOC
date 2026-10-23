"""
test_project.py — NazarSOC Phase 1 Test Suite

Tests are grouped into:
  - TestNormalization   : event parsing, field validation, timestamp handling
  - TestParsers         : JSON and CSV bulk parsers
  - TestRuleA           : Brute-force (repeated failures per account)
  - TestRuleB           : Password spraying (many accounts, one IP)
  - TestRuleC           : Failures then success
  - TestDeduplication   : stable detection IDs, overlapping windows
  - TestDemoEvents      : integration test against demo_events.json

All timestamps are deterministic UTC values.  No live network activity or
external services are used.
"""

import json
import textwrap
import unittest
from datetime import datetime, timezone, timedelta
from typing import List

from engine import (
    NormalizedEvent,
    ParseError,
    Detection,
    Thresholds,
    normalize_event,
    parse_json_events,
    parse_csv_events,
    detect_brute_force,
    detect_password_spray,
    detect_failures_then_success,
    run_all_detections,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts(offset_minutes: int = 0) -> str:
    """Return a deterministic UTC ISO timestamp offset from a fixed base."""
    base = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    dt = base + timedelta(minutes=offset_minutes)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _make_event(
    event_id: str = "E1",
    ts_offset: int = 0,
    source_ip: str = "192.0.2.1",
    username: str = "alice",
    event_type: str = "authentication",
    outcome: str = "success",
    **kwargs,
) -> dict:
    """Build a minimal valid raw event dict."""
    d = {
        "event_id": event_id,
        "timestamp": _ts(ts_offset),
        "source_ip": source_ip,
        "username": username,
        "event_type": event_type,
        "outcome": outcome,
    }
    d.update(kwargs)
    return d


def _norm(
    event_id: str = "E1",
    ts_offset: int = 0,
    source_ip: str = "192.0.2.1",
    username: str = "alice",
    event_type: str = "authentication",
    outcome: str = "success",
    **kwargs,
) -> NormalizedEvent:
    """Build a NormalizedEvent directly (bypasses parse pipeline)."""
    base = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    return NormalizedEvent(
        event_id=event_id,
        timestamp=base + timedelta(minutes=ts_offset),
        source_ip=source_ip,
        username=username,
        event_type=event_type,
        outcome=outcome,
        **kwargs,
    )


def _failures(
    source_ip: str,
    username: str,
    count: int,
    start_offset: int = 0,
    spacing_seconds: int = 60,
    event_type: str = "authentication",
) -> List[NormalizedEvent]:
    """Generate `count` failure NormalizedEvents spaced `spacing_seconds` apart."""
    base = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc) + timedelta(minutes=start_offset)
    return [
        NormalizedEvent(
            event_id=f"F-{source_ip}-{username}-{i}",
            timestamp=base + timedelta(seconds=i * spacing_seconds),
            source_ip=source_ip,
            username=username,
            event_type=event_type,
            outcome="failure",
        )
        for i in range(count)
    ]


def _success(
    source_ip: str,
    username: str,
    ts_offset_minutes: int,
    event_id: str = "S1",
    event_type: str = "authentication",
) -> NormalizedEvent:
    """Create a single success NormalizedEvent."""
    base = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    return NormalizedEvent(
        event_id=event_id,
        timestamp=base + timedelta(minutes=ts_offset_minutes),
        source_ip=source_ip,
        username=username,
        event_type=event_type,
        outcome="success",
    )


# ---------------------------------------------------------------------------
# TestNormalization
# ---------------------------------------------------------------------------

class TestNormalization(unittest.TestCase):

    # --- Valid events ---

    def test_valid_event_all_fields(self):
        raw = {
            "event_id": "E1",
            "timestamp": "2024-01-15T10:00:00Z",
            "source_ip": "192.0.2.1",
            "username": "Alice",
            "event_type": "Authentication",
            "outcome": "Success",
            "hostname": "web-01",
            "source_type": "linux_auth",
            "source_reference": "syslog",
            "import_batch": "batch-01",
        }
        evt, err = normalize_event(raw)
        self.assertIsNone(err)
        self.assertIsNotNone(evt)
        # Normalisation: username, event_type, outcome must be lower-cased
        self.assertEqual(evt.username, "alice")
        self.assertEqual(evt.event_type, "authentication")
        self.assertEqual(evt.outcome, "success")
        # Optional fields preserved
        self.assertEqual(evt.hostname, "web-01")
        self.assertEqual(evt.source_type, "linux_auth")

    def test_valid_event_minimal_required_fields(self):
        raw = _make_event()
        evt, err = normalize_event(raw)
        self.assertIsNone(err)
        self.assertIsNotNone(evt)
        self.assertEqual(evt.event_id, "E1")

    def test_optional_fields_default_to_none(self):
        raw = _make_event()
        evt, err = normalize_event(raw)
        self.assertIsNone(err)
        self.assertIsNone(evt.hostname)
        self.assertIsNone(evt.source_type)
        self.assertIsNone(evt.source_reference)
        self.assertIsNone(evt.import_batch)

    def test_logon_event_type_accepted(self):
        raw = _make_event(event_type="logon")
        evt, err = normalize_event(raw)
        self.assertIsNone(err)
        self.assertEqual(evt.event_type, "logon")

    def test_whitespace_trimmed_from_string_fields(self):
        raw = _make_event(username="  Alice  ", event_type="  authentication  ")
        evt, err = normalize_event(raw)
        self.assertIsNone(err)
        self.assertEqual(evt.username, "alice")
        self.assertEqual(evt.event_type, "authentication")

    # --- Missing required fields ---

    def test_missing_event_id(self):
        raw = _make_event()
        del raw["event_id"]
        evt, err = normalize_event(raw)
        self.assertIsNone(evt)
        self.assertIn("event_id", err.reason)

    def test_missing_timestamp(self):
        raw = _make_event()
        del raw["timestamp"]
        evt, err = normalize_event(raw)
        self.assertIsNone(evt)
        self.assertIn("timestamp", err.reason)

    def test_missing_source_ip(self):
        raw = _make_event()
        del raw["source_ip"]
        evt, err = normalize_event(raw)
        self.assertIsNone(evt)
        self.assertIn("source_ip", err.reason)

    def test_missing_username(self):
        raw = _make_event()
        del raw["username"]
        evt, err = normalize_event(raw)
        self.assertIsNone(evt)
        self.assertIn("username", err.reason)

    def test_missing_event_type(self):
        raw = _make_event()
        del raw["event_type"]
        evt, err = normalize_event(raw)
        self.assertIsNone(evt)
        self.assertIn("event_type", err.reason)

    def test_missing_outcome(self):
        raw = _make_event()
        del raw["outcome"]
        evt, err = normalize_event(raw)
        self.assertIsNone(evt)
        self.assertIn("outcome", err.reason)

    def test_empty_string_required_field(self):
        raw = _make_event(username="   ")
        evt, err = normalize_event(raw)
        self.assertIsNone(evt)
        self.assertIn("username", err.reason)

    def test_none_required_field(self):
        raw = _make_event()
        raw["username"] = None
        evt, err = normalize_event(raw)
        self.assertIsNone(evt)
        self.assertIn("username", err.reason)

    # --- Invalid timestamps ---

    def test_invalid_timestamp_text(self):
        raw = _make_event()
        raw["timestamp"] = "not-a-date"
        evt, err = normalize_event(raw)
        self.assertIsNone(evt)
        self.assertIn("timestamp", err.reason.lower())

    def test_invalid_timestamp_empty(self):
        raw = _make_event()
        raw["timestamp"] = ""
        evt, err = normalize_event(raw)
        self.assertIsNone(evt)

    def test_timestamp_z_suffix_parsed_as_utc(self):
        raw = _make_event()
        raw["timestamp"] = "2024-01-15T10:00:00Z"
        evt, err = normalize_event(raw)
        self.assertIsNone(err)
        self.assertEqual(evt.timestamp.tzinfo, timezone.utc)
        self.assertEqual(evt.timestamp.hour, 10)

    def test_timestamp_offset_converted_to_utc(self):
        """A +02:00 timestamp should be normalised to UTC (08:00)."""
        raw = _make_event()
        raw["timestamp"] = "2024-01-15T10:00:00+02:00"
        evt, err = normalize_event(raw)
        self.assertIsNone(err)
        self.assertEqual(evt.timestamp.tzinfo, timezone.utc)
        self.assertEqual(evt.timestamp.hour, 8)

    def test_timestamp_naive_assumed_utc(self):
        raw = _make_event()
        raw["timestamp"] = "2024-01-15T10:00:00"
        evt, err = normalize_event(raw)
        self.assertIsNone(err)
        self.assertEqual(evt.timestamp.tzinfo, timezone.utc)

    # --- Invalid event types and outcomes ---

    def test_unsupported_event_type(self):
        raw = _make_event(event_type="network_scan")
        evt, err = normalize_event(raw)
        self.assertIsNone(evt)
        self.assertIn("event_type", err.reason)

    def test_unsupported_outcome(self):
        raw = _make_event(outcome="partial")
        evt, err = normalize_event(raw)
        self.assertIsNone(evt)
        self.assertIn("outcome", err.reason)

    def test_raw_preserved_in_parse_error(self):
        """Original source data must survive in ParseError.raw for forensic purposes."""
        raw = _make_event(event_type="INJECTION_ATTEMPT")
        evt, err = normalize_event(raw)
        self.assertIsNone(evt)
        self.assertEqual(err.raw["event_type"], "INJECTION_ATTEMPT")


# ---------------------------------------------------------------------------
# TestParsers
# ---------------------------------------------------------------------------

class TestParsers(unittest.TestCase):

    def test_parse_json_string(self):
        records = [_make_event("J1"), _make_event("J2", ts_offset=1)]
        data = json.dumps(records)
        good, errors = parse_json_events(data)
        self.assertEqual(len(good), 2)
        self.assertEqual(len(errors), 0)
        self.assertEqual({e.event_id for e in good}, {"J1", "J2"})

    def test_parse_json_list_of_dicts(self):
        records = [_make_event("J3")]
        good, errors = parse_json_events(records)
        self.assertEqual(len(good), 1)
        self.assertEqual(len(errors), 0)

    def test_parse_json_invalid_json_string(self):
        good, errors = parse_json_events("{ not valid json }")
        self.assertEqual(len(good), 0)
        self.assertGreater(len(errors), 0)

    def test_parse_json_non_list_root(self):
        good, errors = parse_json_events('{"event_id": "X"}')
        self.assertEqual(len(good), 0)
        self.assertGreater(len(errors), 0)

    def test_parse_json_mixed_valid_invalid(self):
        records = [
            _make_event("GOOD1"),
            {"event_id": "BAD1", "timestamp": "2024-01-15T10:00:00Z"},  # missing fields
            _make_event("GOOD2", ts_offset=2),
        ]
        data = json.dumps(records)
        good, errors = parse_json_events(data)
        self.assertEqual(len(good), 2)
        self.assertEqual(len(errors), 1)

    def test_parse_json_empty_list(self):
        good, errors = parse_json_events("[]")
        self.assertEqual(len(good), 0)
        self.assertEqual(len(errors), 0)

    def test_parse_json_non_object_element(self):
        good, errors = parse_json_events('["not", "objects"]')
        self.assertEqual(len(good), 0)
        self.assertEqual(len(errors), 2)

    def test_parse_csv_valid(self):
        csv_data = textwrap.dedent("""\
            event_id,timestamp,source_ip,username,event_type,outcome,hostname
            C1,2024-01-15T10:00:00Z,192.0.2.1,alice,authentication,success,web-01
            C2,2024-01-15T10:01:00Z,192.0.2.2,bob,authentication,failure,web-02
        """)
        good, errors = parse_csv_events(csv_data)
        self.assertEqual(len(good), 2)
        self.assertEqual(len(errors), 0)
        self.assertEqual(good[0].event_id, "C1")
        self.assertEqual(good[1].outcome, "failure")

    def test_parse_csv_missing_required_column_value(self):
        csv_data = textwrap.dedent("""\
            event_id,timestamp,source_ip,username,event_type,outcome
            ,2024-01-15T10:00:00Z,192.0.2.1,alice,authentication,success
        """)
        good, errors = parse_csv_events(csv_data)
        self.assertEqual(len(good), 0)
        self.assertEqual(len(errors), 1)

    def test_parse_csv_invalid_timestamp(self):
        csv_data = textwrap.dedent("""\
            event_id,timestamp,source_ip,username,event_type,outcome
            C3,not-a-date,192.0.2.1,alice,authentication,success
        """)
        good, errors = parse_csv_events(csv_data)
        self.assertEqual(len(good), 0)
        self.assertEqual(len(errors), 1)

    def test_parse_csv_empty_input(self):
        good, errors = parse_csv_events("")
        # Empty string produces no rows but also no crash
        self.assertEqual(len(good), 0)

    def test_parse_csv_header_only(self):
        csv_data = "event_id,timestamp,source_ip,username,event_type,outcome\n"
        good, errors = parse_csv_events(csv_data)
        self.assertEqual(len(good), 0)
        self.assertEqual(len(errors), 0)


# ---------------------------------------------------------------------------
# TestRuleA — Brute-force (repeated failures per account)
# ---------------------------------------------------------------------------

class TestRuleA(unittest.TestCase):

    def test_exactly_threshold_triggers(self):
        """Exactly 5 failures within 5 minutes → detection."""
        events = _failures("192.0.2.1", "alice", count=5, spacing_seconds=60)
        dets = detect_brute_force(events, min_failures=5, window_seconds=300)
        self.assertEqual(len(dets), 1)
        self.assertEqual(dets[0].rule_id, "RULE_A")
        self.assertEqual(dets[0].source_ip, "192.0.2.1")
        self.assertEqual(dets[0].affected_usernames, ["alice"])
        self.assertEqual(len(dets[0].event_ids), 5)

    def test_below_threshold_no_detection(self):
        """4 failures — should not trigger (threshold is 5)."""
        events = _failures("192.0.2.1", "alice", count=4, spacing_seconds=60)
        dets = detect_brute_force(events, min_failures=5, window_seconds=300)
        self.assertEqual(len(dets), 0)

    def test_above_threshold_triggers(self):
        """10 failures within 5 minutes → 1 detection (not 10)."""
        events = _failures("192.0.2.1", "alice", count=10, spacing_seconds=20)
        dets = detect_brute_force(events, min_failures=5, window_seconds=300)
        self.assertEqual(len(dets), 1)
        self.assertGreaterEqual(len(dets[0].event_ids), 5)

    def test_failures_outside_window_no_detection(self):
        """5 failures but spaced > 5 minutes apart → no detection."""
        events = _failures("192.0.2.1", "alice", count=5, spacing_seconds=90)
        # Window is 300 s; events span 4*90 = 360 s → should NOT trigger
        dets = detect_brute_force(events, min_failures=5, window_seconds=300)
        self.assertEqual(len(dets), 0)

    def test_failures_exactly_on_window_boundary_triggers(self):
        """5 failures; last event exactly at window boundary (t=300) → triggers."""
        events = _failures("192.0.2.1", "alice", count=5, spacing_seconds=75)
        # Span = 4*75 = 300 s which equals the window
        dets = detect_brute_force(events, min_failures=5, window_seconds=300)
        self.assertEqual(len(dets), 1)

    def test_different_users_same_ip_separate_detections(self):
        """Failures for two different users from the same IP → 2 detections."""
        evts_alice = _failures("192.0.2.1", "alice", count=5, spacing_seconds=60)
        evts_bob = _failures("192.0.2.1", "bob", count=5, spacing_seconds=60)
        dets = detect_brute_force(evts_alice + evts_bob, min_failures=5, window_seconds=300)
        self.assertEqual(len(dets), 2)
        user_set = {d.affected_usernames[0] for d in dets}
        self.assertEqual(user_set, {"alice", "bob"})

    def test_different_ips_same_user_separate_detections(self):
        """Failures for the same user from two different IPs → 2 detections."""
        evts_1 = _failures("192.0.2.1", "alice", count=5, spacing_seconds=60)
        evts_2 = _failures("192.0.2.2", "alice", count=5, spacing_seconds=60)
        dets = detect_brute_force(evts_1 + evts_2, min_failures=5, window_seconds=300)
        self.assertEqual(len(dets), 2)
        ip_set = {d.source_ip for d in dets}
        self.assertEqual(ip_set, {"192.0.2.1", "192.0.2.2"})

    def test_no_false_positive_with_success_events_mixed_in(self):
        """Success events interleaved with 4 failures → no detection (successes ignored)."""
        events = _failures("192.0.2.1", "alice", count=4, spacing_seconds=60)
        events.append(_success("192.0.2.1", "alice", ts_offset_minutes=3))
        dets = detect_brute_force(events, min_failures=5, window_seconds=300)
        self.assertEqual(len(dets), 0)

    def test_evidence_ids_match_input_events(self):
        """All event_ids in the detection must come from the input."""
        events = _failures("192.0.2.1", "alice", count=5, spacing_seconds=60)
        input_ids = {e.event_id for e in events}
        dets = detect_brute_force(events, min_failures=5, window_seconds=300)
        self.assertEqual(len(dets), 1)
        for eid in dets[0].event_ids:
            self.assertIn(eid, input_ids, f"event_id {eid} not in input events")

    def test_empty_input(self):
        dets = detect_brute_force([], min_failures=5, window_seconds=300)
        self.assertEqual(len(dets), 0)

    def test_only_success_events_no_detection(self):
        events = [_success("192.0.2.1", "alice", ts_offset_minutes=i, event_id=f"S{i}") for i in range(10)]
        dets = detect_brute_force(events, min_failures=5, window_seconds=300)
        self.assertEqual(len(dets), 0)

    def test_detection_severity_is_medium(self):
        events = _failures("192.0.2.1", "alice", count=5, spacing_seconds=60)
        dets = detect_brute_force(events, min_failures=5, window_seconds=300)
        self.assertEqual(dets[0].severity, "Medium")

    def test_detection_mitre_technique(self):
        events = _failures("192.0.2.1", "alice", count=5, spacing_seconds=60)
        dets = detect_brute_force(events, min_failures=5, window_seconds=300)
        self.assertEqual(dets[0].mitre_technique, "T1110.001")

    def test_input_ordering_irrelevant(self):
        """Detection should fire regardless of whether input is sorted by time."""
        events = _failures("192.0.2.1", "alice", count=5, spacing_seconds=60)
        events_reversed = list(reversed(events))
        dets_forward = detect_brute_force(events, min_failures=5, window_seconds=300)
        dets_reverse = detect_brute_force(events_reversed, min_failures=5, window_seconds=300)
        self.assertEqual(len(dets_forward), 1)
        self.assertEqual(len(dets_reverse), 1)

    def test_logon_event_type_also_triggers(self):
        """Rule A should also trigger on event_type='logon'."""
        events = _failures("192.0.2.1", "alice", count=5, spacing_seconds=60, event_type="logon")
        dets = detect_brute_force(events, min_failures=5, window_seconds=300)
        self.assertEqual(len(dets), 1)


# ---------------------------------------------------------------------------
# TestRuleB — Password spraying
# ---------------------------------------------------------------------------

class TestRuleB(unittest.TestCase):

    def _spray_events(
        self,
        source_ip: str = "203.0.113.1",
        num_users: int = 10,
        failures_per_user: int = 1,
        spacing_seconds: int = 60,
        start_offset_minutes: int = 0,
    ) -> List[NormalizedEvent]:
        """Create spray-like failures: `failures_per_user` per user, `num_users` users."""
        base = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc) + timedelta(minutes=start_offset_minutes)
        events = []
        seq = 0
        for u in range(num_users):
            for f in range(failures_per_user):
                events.append(NormalizedEvent(
                    event_id=f"SP-{source_ip}-u{u}-f{f}",
                    timestamp=base + timedelta(seconds=seq * spacing_seconds),
                    source_ip=source_ip,
                    username=f"user{u:02d}",
                    event_type="authentication",
                    outcome="failure",
                ))
                seq += 1
        return events

    def test_exact_threshold_triggers(self):
        """10 failures across 5 users within 10 min → detection."""
        events = self._spray_events(num_users=5, failures_per_user=2, spacing_seconds=60)
        dets = detect_password_spray(
            events, min_failures=10, min_distinct_users=5, window_seconds=600
        )
        self.assertEqual(len(dets), 1)
        self.assertEqual(dets[0].rule_id, "RULE_B")

    def test_too_few_failures_no_detection(self):
        """9 failures across 5 users → no detection (threshold 10)."""
        events = self._spray_events(num_users=5, failures_per_user=1, spacing_seconds=60)
        events = events[:9]
        dets = detect_password_spray(
            events, min_failures=10, min_distinct_users=5, window_seconds=600
        )
        self.assertEqual(len(dets), 0)

    def test_too_few_distinct_users_no_detection(self):
        """10 failures but only 4 distinct users → no detection (threshold 5)."""
        events = self._spray_events(num_users=4, failures_per_user=3, spacing_seconds=30)[:10]
        dets = detect_password_spray(
            events, min_failures=10, min_distinct_users=5, window_seconds=600
        )
        self.assertEqual(len(dets), 0)

    def test_failures_outside_window_no_detection(self):
        """10 failures across 10 users but spanning > 10 minutes → no detection."""
        events = self._spray_events(num_users=10, failures_per_user=1, spacing_seconds=70)
        # 9 * 70 = 630 s > 600 s window
        dets = detect_password_spray(
            events, min_failures=10, min_distinct_users=5, window_seconds=600
        )
        self.assertEqual(len(dets), 0)

    def test_affected_usernames_in_detection(self):
        events = self._spray_events(num_users=10, failures_per_user=1, spacing_seconds=50)
        dets = detect_password_spray(
            events, min_failures=10, min_distinct_users=5, window_seconds=600
        )
        self.assertEqual(len(dets), 1)
        self.assertEqual(len(dets[0].affected_usernames), 10)

    def test_different_ips_independent_detections(self):
        """Spray from two different IPs → 2 detections."""
        evts_1 = self._spray_events(source_ip="203.0.113.1", num_users=10, spacing_seconds=50)
        evts_2 = self._spray_events(source_ip="203.0.113.2", num_users=10, spacing_seconds=50)
        dets = detect_password_spray(
            evts_1 + evts_2, min_failures=10, min_distinct_users=5, window_seconds=600
        )
        self.assertEqual(len(dets), 2)
        ip_set = {d.source_ip for d in dets}
        self.assertEqual(ip_set, {"203.0.113.1", "203.0.113.2"})

    def test_detection_severity_is_high(self):
        events = self._spray_events(num_users=10, failures_per_user=1, spacing_seconds=50)
        dets = detect_password_spray(
            events, min_failures=10, min_distinct_users=5, window_seconds=600
        )
        self.assertEqual(dets[0].severity, "High")

    def test_detection_mitre_technique(self):
        events = self._spray_events(num_users=10, failures_per_user=1, spacing_seconds=50)
        dets = detect_password_spray(
            events, min_failures=10, min_distinct_users=5, window_seconds=600
        )
        self.assertEqual(dets[0].mitre_technique, "T1110.003")

    def test_evidence_ids_match_input(self):
        events = self._spray_events(num_users=10, failures_per_user=1, spacing_seconds=50)
        input_ids = {e.event_id for e in events}
        dets = detect_password_spray(
            events, min_failures=10, min_distinct_users=5, window_seconds=600
        )
        for eid in dets[0].event_ids:
            self.assertIn(eid, input_ids)

    def test_empty_input(self):
        dets = detect_password_spray([], min_failures=10, min_distinct_users=5, window_seconds=600)
        self.assertEqual(len(dets), 0)


# ---------------------------------------------------------------------------
# TestRuleC — Failures then success
# ---------------------------------------------------------------------------

class TestRuleC(unittest.TestCase):

    def _make_ffs(
        self,
        source_ip: str = "198.51.100.1",
        username: str = "alice",
        failure_count: int = 3,
        failure_spacing_seconds: int = 60,
        success_offset_minutes: int = 5,
    ) -> List[NormalizedEvent]:
        """Build a failures-then-success scenario."""
        events = _failures(source_ip, username, count=failure_count, spacing_seconds=failure_spacing_seconds)
        events.append(_success(source_ip, username, ts_offset_minutes=success_offset_minutes, event_id="S-FFS"))
        return events

    def test_exact_threshold_triggers(self):
        """3 failures followed by a success within 10 min → detection."""
        events = self._make_ffs(failure_count=3, success_offset_minutes=5)
        dets = detect_failures_then_success(events, min_failures=3, window_seconds=600)
        self.assertEqual(len(dets), 1)
        self.assertEqual(dets[0].rule_id, "RULE_C")

    def test_below_threshold_no_detection(self):
        """2 failures then success → no detection (threshold 3)."""
        events = self._make_ffs(failure_count=2, success_offset_minutes=5)
        dets = detect_failures_then_success(events, min_failures=3, window_seconds=600)
        self.assertEqual(len(dets), 0)

    def test_success_outside_window_no_detection(self):
        """3 failures but success at 11 min → outside 10 min window → no detection."""
        events = _failures("198.51.100.1", "alice", count=3, spacing_seconds=60)
        events.append(_success("198.51.100.1", "alice", ts_offset_minutes=11, event_id="S-LATE"))
        dets = detect_failures_then_success(events, min_failures=3, window_seconds=600)
        self.assertEqual(len(dets), 0)

    def test_success_exactly_at_window_boundary_triggers(self):
        """Success at exactly t+600s (window boundary) should trigger."""
        base = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        events = [
            NormalizedEvent(
                event_id=f"F{i}", timestamp=base + timedelta(seconds=i * 60),
                source_ip="198.51.100.1", username="alice",
                event_type="authentication", outcome="failure",
            )
            for i in range(3)
        ]
        events.append(NormalizedEvent(
            event_id="S-BOUNDARY",
            timestamp=base + timedelta(seconds=600),   # exactly at boundary
            source_ip="198.51.100.1", username="alice",
            event_type="authentication", outcome="success",
        ))
        dets = detect_failures_then_success(events, min_failures=3, window_seconds=600)
        self.assertEqual(len(dets), 1)

    def test_no_success_no_detection(self):
        """Failures with no matching success → no detection."""
        events = _failures("198.51.100.1", "alice", count=5, spacing_seconds=60)
        dets = detect_failures_then_success(events, min_failures=3, window_seconds=600)
        self.assertEqual(len(dets), 0)

    def test_success_only_no_detection(self):
        events = [_success("198.51.100.1", "alice", ts_offset_minutes=0)]
        dets = detect_failures_then_success(events, min_failures=3, window_seconds=600)
        self.assertEqual(len(dets), 0)

    def test_detection_includes_success_event_id(self):
        events = self._make_ffs(failure_count=3, success_offset_minutes=5)
        dets = detect_failures_then_success(events, min_failures=3, window_seconds=600)
        self.assertIn("S-FFS", dets[0].event_ids)

    def test_evidence_ids_match_input(self):
        events = self._make_ffs(failure_count=3, success_offset_minutes=5)
        input_ids = {e.event_id for e in events}
        dets = detect_failures_then_success(events, min_failures=3, window_seconds=600)
        for eid in dets[0].event_ids:
            self.assertIn(eid, input_ids)

    def test_detection_severity_is_high(self):
        events = self._make_ffs(failure_count=3, success_offset_minutes=5)
        dets = detect_failures_then_success(events, min_failures=3, window_seconds=600)
        self.assertEqual(dets[0].severity, "High")

    def test_detection_confidence_is_medium(self):
        """Rule C is High severity but Medium confidence — not a confirmed compromise."""
        events = self._make_ffs(failure_count=3, success_offset_minutes=5)
        dets = detect_failures_then_success(events, min_failures=3, window_seconds=600)
        self.assertEqual(dets[0].confidence, "Medium")

    def test_different_users_same_ip(self):
        """Two users from same IP both trigger separately."""
        evts_alice = self._make_ffs("198.51.100.1", "alice", 3, 60, 5)
        evts_bob = [
            *_failures("198.51.100.1", "bob", count=3, spacing_seconds=60),
            _success("198.51.100.1", "bob", ts_offset_minutes=5, event_id="S-BOB"),
        ]
        dets = detect_failures_then_success(evts_alice + evts_bob, min_failures=3, window_seconds=600)
        self.assertEqual(len(dets), 2)
        users = {d.affected_usernames[0] for d in dets}
        self.assertEqual(users, {"alice", "bob"})

    def test_mitre_technique(self):
        events = self._make_ffs(failure_count=3, success_offset_minutes=5)
        dets = detect_failures_then_success(events, min_failures=3, window_seconds=600)
        self.assertEqual(dets[0].mitre_technique, "T1110.001")

    def test_empty_input(self):
        dets = detect_failures_then_success([], min_failures=3, window_seconds=600)
        self.assertEqual(len(dets), 0)


# ---------------------------------------------------------------------------
# TestDeduplication — stable IDs, overlapping windows
# ---------------------------------------------------------------------------

class TestDeduplication(unittest.TestCase):

    def test_rule_a_single_detection_for_many_overlapping_windows(self):
        """10 tight failures → only 1 detection, not 10."""
        events = _failures("192.0.2.1", "alice", count=10, spacing_seconds=20)
        dets = detect_brute_force(events, min_failures=5, window_seconds=300)
        self.assertEqual(len(dets), 1)

    def test_rule_b_single_detection_per_ip(self):
        """Spray with many more failures than threshold → still 1 detection per IP."""
        base = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        events = [
            NormalizedEvent(
                event_id=f"SP{i}",
                timestamp=base + timedelta(seconds=i * 30),
                source_ip="203.0.113.1",
                username=f"user{i:02d}",
                event_type="authentication",
                outcome="failure",
            )
            for i in range(20)
        ]
        dets = detect_password_spray(events, min_failures=10, min_distinct_users=5, window_seconds=600)
        self.assertEqual(len(dets), 1)

    def test_rule_a_stable_detection_id_on_reprocessing(self):
        """Same events processed twice must produce the same detection_id."""
        events = _failures("192.0.2.1", "alice", count=5, spacing_seconds=60)
        dets1 = detect_brute_force(events, min_failures=5, window_seconds=300)
        dets2 = detect_brute_force(events, min_failures=5, window_seconds=300)
        self.assertEqual(len(dets1), 1)
        self.assertEqual(len(dets2), 1)
        self.assertEqual(dets1[0].detection_id, dets2[0].detection_id)

    def test_rule_b_stable_detection_id_on_reprocessing(self):
        base = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        events = [
            NormalizedEvent(
                event_id=f"SP{i}",
                timestamp=base + timedelta(seconds=i * 50),
                source_ip="203.0.113.5",
                username=f"user{i:02d}",
                event_type="authentication",
                outcome="failure",
            )
            for i in range(10)
        ]
        dets1 = detect_password_spray(events, min_failures=10, min_distinct_users=5, window_seconds=600)
        dets2 = detect_password_spray(events, min_failures=10, min_distinct_users=5, window_seconds=600)
        self.assertEqual(dets1[0].detection_id, dets2[0].detection_id)

    def test_rule_c_stable_detection_id(self):
        base = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        fails = _failures("198.51.100.1", "alice", count=3, spacing_seconds=60)
        success = NormalizedEvent(
            event_id="S1",
            timestamp=base + timedelta(minutes=5),
            source_ip="198.51.100.1",
            username="alice",
            event_type="authentication",
            outcome="success",
        )
        events = fails + [success]
        dets1 = detect_failures_then_success(events, min_failures=3, window_seconds=600)
        dets2 = detect_failures_then_success(events, min_failures=3, window_seconds=600)
        self.assertEqual(dets1[0].detection_id, dets2[0].detection_id)

    def test_distinct_ips_produce_distinct_detection_ids(self):
        """Different source IPs must not collide to the same detection_id."""
        evts1 = _failures("192.0.2.1", "alice", count=5, spacing_seconds=60)
        evts2 = _failures("192.0.2.2", "alice", count=5, spacing_seconds=60)
        dets1 = detect_brute_force(evts1, min_failures=5, window_seconds=300)
        dets2 = detect_brute_force(evts2, min_failures=5, window_seconds=300)
        self.assertNotEqual(dets1[0].detection_id, dets2[0].detection_id)

    def test_run_all_returns_all_three_rules(self):
        """run_all_detections should trigger all three rules on the right input."""
        # Brute-force input (Rule A)
        bf_events = _failures("192.0.2.1", "alpha", count=5, spacing_seconds=60)

        # Spray input (Rule B)
        base = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        spray_events = [
            NormalizedEvent(
                event_id=f"SPR{i}",
                timestamp=base + timedelta(seconds=i * 50),
                source_ip="203.0.113.9",
                username=f"sprayed{i:02d}",
                event_type="authentication",
                outcome="failure",
            )
            for i in range(10)
        ]

        # FFS input (Rule C)
        ffs_failures = _failures("198.51.100.2", "omega", count=3, spacing_seconds=60)
        ffs_success = NormalizedEvent(
            event_id="FFS-S1",
            timestamp=base + timedelta(minutes=5),
            source_ip="198.51.100.2",
            username="omega",
            event_type="authentication",
            outcome="success",
        )

        all_events = bf_events + spray_events + ffs_failures + [ffs_success]
        dets = run_all_detections(all_events)
        rule_ids = {d.rule_id for d in dets}
        self.assertIn("RULE_A", rule_ids)
        self.assertIn("RULE_B", rule_ids)
        self.assertIn("RULE_C", rule_ids)


# ---------------------------------------------------------------------------
# TestDemoEvents — integration against demo_events.json
# ---------------------------------------------------------------------------

class TestDemoEvents(unittest.TestCase):
    """
    Load demo_events.json and verify the expected detection outcomes.

    Expected (based on documented synthetic data):
    - Rule A fires for 'dave' from 198.51.100.50 (5 failures, EVT-100 … EVT-104)
    - Rule B fires for spray from 203.0.113.77 (10 failures, 10 users, EVT-200 … EVT-209)
    - Rule C fires for 'eve' from 198.51.100.99 (3 failures + success, EVT-300 … EVT-303)
    - Isolated failures (EVT-010 … EVT-013) should NOT trigger Rule A
    - Normal successes (EVT-001 … EVT-003) should NOT trigger any rule
    - Boundary events (EVT-400, EVT-401) with > 5 min gap must NOT trigger Rule A
    """

    def setUp(self):
        with open("demo_events.json", "r", encoding="utf-8") as fh:
            raw_list = json.load(fh)

        # Filter out comment/section marker dicts (no event_id)
        data = [r for r in raw_list if "event_id" in r]
        self.events, self.errors = parse_json_events(data)
        self.detections = run_all_detections(self.events)

    def test_demo_events_load_without_errors(self):
        self.assertEqual(len(self.errors), 0, f"Parse errors: {self.errors}")

    def test_rule_a_fires_for_dave(self):
        rule_a = [d for d in self.detections if d.rule_id == "RULE_A"]
        self.assertGreater(len(rule_a), 0)
        dave_dets = [d for d in rule_a if "dave" in d.affected_usernames]
        self.assertEqual(len(dave_dets), 1)
        self.assertEqual(dave_dets[0].source_ip, "198.51.100.50")

    def test_rule_b_fires_for_spray(self):
        rule_b = [d for d in self.detections if d.rule_id == "RULE_B"]
        self.assertGreater(len(rule_b), 0)
        spray_det = [d for d in rule_b if d.source_ip == "203.0.113.77"]
        self.assertEqual(len(spray_det), 1)
        self.assertGreaterEqual(len(spray_det[0].affected_usernames), 5)

    def test_rule_c_fires_for_eve(self):
        rule_c = [d for d in self.detections if d.rule_id == "RULE_C"]
        self.assertGreater(len(rule_c), 0)
        eve_dets = [d for d in rule_c if "eve" in d.affected_usernames]
        self.assertEqual(len(eve_dets), 1)
        self.assertIn("EVT-303", eve_dets[0].event_ids)  # success event

    def test_isolated_failures_no_alert(self):
        """4 failures for alice from 192.0.2.20 must not trigger Rule A."""
        rule_a = [d for d in self.detections if d.rule_id == "RULE_A"]
        alice_from_20 = [
            d for d in rule_a
            if "alice" in d.affected_usernames and d.source_ip == "192.0.2.20"
        ]
        self.assertEqual(len(alice_from_20), 0)

    def test_boundary_events_no_alert(self):
        """frank's 2 failures >5 min apart must not trigger Rule A."""
        rule_a = [d for d in self.detections if d.rule_id == "RULE_A"]
        frank_dets = [d for d in rule_a if "frank" in d.affected_usernames]
        self.assertEqual(len(frank_dets), 0)

    def test_rule_b_evidence_ids_from_spray_batch(self):
        """Spray detection event IDs must all start with 'EVT-2'."""
        rule_b = [d for d in self.detections if d.rule_id == "RULE_B" and d.source_ip == "203.0.113.77"]
        self.assertEqual(len(rule_b), 1)
        for eid in rule_b[0].event_ids:
            self.assertTrue(eid.startswith("EVT-2"), f"Unexpected event_id: {eid}")

    def test_rule_c_failure_evidence_ids_from_ffs_batch(self):
        """FFS detection failure evidence must include EVT-300, EVT-301, EVT-302."""
        rule_c = [d for d in self.detections if d.rule_id == "RULE_C"]
        eve_dets = [d for d in rule_c if "eve" in d.affected_usernames]
        eid_set = set(eve_dets[0].event_ids)
        for expected in ("EVT-300", "EVT-301", "EVT-302"):
            self.assertIn(expected, eid_set)


# ---------------------------------------------------------------------------
# TestAuditRegressions — regression tests for every confirmed defect
# ---------------------------------------------------------------------------

class TestAuditRegressions(unittest.TestCase):
    """
    Regression tests added during the Phase 1 security audit.

    DEF-1: normalize_event raised an unhandled ValueError when a required
           string field (username) was given a non-string value (e.g. int).
           Fix: the _normalize_string call for username is now wrapped in
           try/except and returns a ParseError.

    DEF-2: detect_failures_then_success (Rule C) fired when fewer than
           min_failures failures preceded the success event.  The window
           collected all failures from an anchor point then found the first
           success ANYWHERE in the window — including before the bulk of the
           failures.  Fix: only the failures that occurred at or before the
           candidate success timestamp count toward the min_failures threshold.

    DEF-3: parse_csv_events used `assert err is not None` which Python strips
           with `-O`, causing an AttributeError.
           Fix: replaced with an explicit `if err is not None` guard.
    """

    # --- DEF-1 regressions: non-string typed fields ---

    def test_def1_int_username_returns_parse_error(self):
        """Non-string username must return ParseError, not raise ValueError."""
        raw = _make_event()
        raw["username"] = 42
        evt, err = normalize_event(raw)
        self.assertIsNone(evt)
        self.assertIsNotNone(err)
        self.assertIsInstance(err, ParseError)
        self.assertIn("int", err.reason)

    def test_def1_list_username_returns_parse_error(self):
        """List username must return ParseError, not crash."""
        raw = _make_event()
        raw["username"] = ["alice", "bob"]
        evt, err = normalize_event(raw)
        self.assertIsNone(evt)
        self.assertIsNotNone(err)

    def test_def1_dict_username_returns_parse_error(self):
        """Dict username must return ParseError, not crash."""
        raw = _make_event()
        raw["username"] = {"name": "alice"}
        evt, err = normalize_event(raw)
        self.assertIsNone(evt)
        self.assertIsNotNone(err)

    def test_def1_float_username_returns_parse_error(self):
        """Float username must return ParseError, not crash."""
        raw = _make_event()
        raw["username"] = 3.14
        evt, err = normalize_event(raw)
        self.assertIsNone(evt)
        self.assertIsNotNone(err)

    def test_def1_non_string_does_not_crash_parse_json(self):
        """A JSON record with a non-string username should produce an error entry,
        not crash parse_json_events, and valid records in the same batch still parse."""
        records = [
            _make_event("GOOD"),
            {
                "event_id": "BAD", "timestamp": "2024-01-15T10:00:00Z",
                "source_ip": "192.0.2.1", "username": 99,
                "event_type": "authentication", "outcome": "failure",
            },
        ]
        import json as _json
        good, errors = parse_json_events(_json.dumps(records))
        self.assertEqual(len(good), 1, "Valid record should still parse")
        self.assertEqual(good[0].event_id, "GOOD")
        self.assertEqual(len(errors), 1, "Non-string username should produce one error")

    # --- DEF-2 regressions: Rule C success-ordering ---

    def test_def2_success_between_failures_only_2_before_not_trigger(self):
        """
        2 failures, then success, then 3 more failures.
        Only 2 failures precede the success → must NOT trigger with min_failures=3.
        Previously fired incorrectly because the engine found 5 failures in the
        window and a success anywhere in that window.
        """
        base = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        events = [
            NormalizedEvent("F1", base, "192.0.2.1", "alice", "authentication", "failure"),
            NormalizedEvent("F2", base + timedelta(minutes=1), "192.0.2.1", "alice", "authentication", "failure"),
            NormalizedEvent("S1", base + timedelta(minutes=2), "192.0.2.1", "alice", "authentication", "success"),
            NormalizedEvent("F3", base + timedelta(minutes=3), "192.0.2.1", "alice", "authentication", "failure"),
            NormalizedEvent("F4", base + timedelta(minutes=4), "192.0.2.1", "alice", "authentication", "failure"),
            NormalizedEvent("F5", base + timedelta(minutes=5), "192.0.2.1", "alice", "authentication", "failure"),
        ]
        dets = detect_failures_then_success(events, min_failures=3, window_seconds=600)
        self.assertEqual(len(dets), 0,
            "Only 2 failures preceded the success; 3 post-success failures must not count")

    def test_def2_exactly_3_before_success_triggers(self):
        """3 failures strictly before the success → must trigger with min_failures=3."""
        base = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        events = [
            NormalizedEvent("F1", base, "192.0.2.1", "alice", "authentication", "failure"),
            NormalizedEvent("F2", base + timedelta(minutes=1), "192.0.2.1", "alice", "authentication", "failure"),
            NormalizedEvent("F3", base + timedelta(minutes=2), "192.0.2.1", "alice", "authentication", "failure"),
            NormalizedEvent("S1", base + timedelta(minutes=5), "192.0.2.1", "alice", "authentication", "success"),
        ]
        dets = detect_failures_then_success(events, min_failures=3, window_seconds=600)
        self.assertEqual(len(dets), 1)

    def test_def2_evidence_only_contains_pre_success_failures(self):
        """Evidence event IDs must only include failures that occurred before the success."""
        base = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        events = [
            NormalizedEvent("F1", base, "192.0.2.1", "alice", "authentication", "failure"),
            NormalizedEvent("F2", base + timedelta(minutes=1), "192.0.2.1", "alice", "authentication", "failure"),
            NormalizedEvent("F3", base + timedelta(minutes=2), "192.0.2.1", "alice", "authentication", "failure"),
            NormalizedEvent("S1", base + timedelta(minutes=5), "192.0.2.1", "alice", "authentication", "success"),
            NormalizedEvent("F4", base + timedelta(minutes=6), "192.0.2.1", "alice", "authentication", "failure"),
        ]
        dets = detect_failures_then_success(events, min_failures=3, window_seconds=600)
        self.assertEqual(len(dets), 1)
        # F4 occurred after S1 and must not appear in evidence
        self.assertNotIn("F4", dets[0].event_ids)
        self.assertIn("S1", dets[0].event_ids)

    def test_def2_success_same_timestamp_as_failure_counts(self):
        """
        When success timestamp equals the last of the min_failures failures,
        the prior_fails check uses <=, so all three failures (including the
        concurrent one) count and the detection fires.
        """
        base = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        ts = base + timedelta(minutes=5)
        events = [
            NormalizedEvent("F1", base + timedelta(minutes=3), "192.0.2.1", "alice", "authentication", "failure"),
            NormalizedEvent("F2", base + timedelta(minutes=4), "192.0.2.1", "alice", "authentication", "failure"),
            NormalizedEvent("F3", ts, "192.0.2.1", "alice", "authentication", "failure"),
            NormalizedEvent("S1", ts, "192.0.2.1", "alice", "authentication", "success"),
        ]
        dets = detect_failures_then_success(events, min_failures=3, window_seconds=600)
        self.assertEqual(len(dets), 1)

    # --- DEF-3 regression: assert replaced with if-guard in parse_csv_events ---

    def test_def3_csv_bad_record_produces_error_not_crash(self):
        """
        A malformed CSV row must produce a ParseError entry.
        Under `python -O` the original `assert err is not None` was silently
        stripped, causing an AttributeError.  Now guarded with an explicit if.
        """
        import textwrap
        csv_data = textwrap.dedent("""\
            event_id,timestamp,source_ip,username,event_type,outcome
            ,2024-01-15T10:00:00Z,192.0.2.1,alice,authentication,success
        """)
        good, errors = parse_csv_events(csv_data)
        self.assertEqual(len(good), 0)
        self.assertEqual(len(errors), 1)
        # Error must carry the CSV line number annotation
        self.assertIn("_csv_line", errors[0].raw)

    def test_def3_csv_mixed_good_bad_rows(self):
        """Good rows parse normally even when a bad row follows them."""
        import textwrap
        csv_data = textwrap.dedent("""\
            event_id,timestamp,source_ip,username,event_type,outcome
            GOOD1,2024-01-15T10:00:00Z,192.0.2.1,alice,authentication,success
            ,2024-01-15T10:01:00Z,192.0.2.1,bob,authentication,failure
            GOOD2,2024-01-15T10:02:00Z,192.0.2.2,charlie,authentication,success
        """)
        good, errors = parse_csv_events(csv_data)
        self.assertEqual(len(good), 2)
        self.assertEqual(len(errors), 1)
        self.assertEqual({e.event_id for e in good}, {"GOOD1", "GOOD2"})


# ---------------------------------------------------------------------------
# Phase 2 engine.py validation regression tests
# (RISK-1 fixes: event_id / source_ip type enforcement + field-length limits)
# ---------------------------------------------------------------------------

class TestEngineValidationPhase2(unittest.TestCase):
    """Tests for the stricter field validation added in Phase 2."""

    def test_int_event_id_returns_parse_error(self):
        raw = _make_event()
        raw["event_id"] = 42
        evt, err = normalize_event(raw)
        self.assertIsNone(evt)
        self.assertIsNotNone(err)
        self.assertIn("event_id", err.reason)

    def test_list_event_id_returns_parse_error(self):
        raw = _make_event()
        raw["event_id"] = ["a", "b"]
        evt, err = normalize_event(raw)
        self.assertIsNone(evt)
        self.assertIsNotNone(err)

    def test_dict_event_id_returns_parse_error(self):
        raw = _make_event()
        raw["event_id"] = {"id": "x"}
        evt, err = normalize_event(raw)
        self.assertIsNone(evt)
        self.assertIsNotNone(err)

    def test_int_source_ip_returns_parse_error(self):
        raw = _make_event()
        raw["source_ip"] = 3232235521   # numeric IP
        evt, err = normalize_event(raw)
        self.assertIsNone(evt)
        self.assertIsNotNone(err)
        self.assertIn("source_ip", err.reason)

    def test_dict_source_ip_returns_parse_error(self):
        raw = _make_event()
        raw["source_ip"] = {"ip": "192.0.2.1"}
        evt, err = normalize_event(raw)
        self.assertIsNone(evt)
        self.assertIsNotNone(err)

    def test_invalid_ip_string_returns_parse_error(self):
        raw = _make_event()
        raw["source_ip"] = "999.999.999.999"
        evt, err = normalize_event(raw)
        self.assertIsNone(evt)
        self.assertIsNotNone(err)
        self.assertIn("source_ip", err.reason)

    def test_malformed_ip_hostname_returns_parse_error(self):
        raw = _make_event()
        raw["source_ip"] = "not-an-ip"
        evt, err = normalize_event(raw)
        self.assertIsNone(evt)
        self.assertIsNotNone(err)

    def test_valid_private_ip_accepted(self):
        """Private RFC 1918 addresses must be accepted (used in synthetic test data)."""
        raw = _make_event()
        raw["source_ip"] = "10.0.0.1"
        evt, err = normalize_event(raw)
        self.assertIsNone(err)
        self.assertEqual(evt.source_ip, "10.0.0.1")

    def test_valid_documentation_ip_accepted(self):
        """RFC 5737 documentation range must be accepted."""
        raw = _make_event()
        raw["source_ip"] = "192.0.2.1"
        evt, err = normalize_event(raw)
        self.assertIsNone(err)

    def test_valid_ipv6_accepted(self):
        """A valid IPv6 address must be accepted."""
        raw = _make_event()
        raw["source_ip"] = "2001:db8::1"
        evt, err = normalize_event(raw)
        self.assertIsNone(err)
        self.assertEqual(evt.source_ip, "2001:db8::1")

    def test_event_id_too_long_returns_parse_error(self):
        from engine import MAX_EVENT_ID_LEN
        raw = _make_event()
        raw["event_id"] = "X" * (MAX_EVENT_ID_LEN + 1)
        evt, err = normalize_event(raw)
        self.assertIsNone(evt)
        self.assertIsNotNone(err)
        self.assertIn("event_id", err.reason)

    def test_event_id_at_max_length_accepted(self):
        from engine import MAX_EVENT_ID_LEN
        raw = _make_event()
        raw["event_id"] = "X" * MAX_EVENT_ID_LEN
        evt, err = normalize_event(raw)
        self.assertIsNone(err)
        self.assertIsNotNone(evt)

    def test_username_too_long_returns_parse_error(self):
        from engine import MAX_USERNAME_LEN
        raw = _make_event()
        raw["username"] = "a" * (MAX_USERNAME_LEN + 1)
        evt, err = normalize_event(raw)
        self.assertIsNone(evt)
        self.assertIsNotNone(err)
        self.assertIn("username", err.reason)

    def test_hostname_too_long_returns_parse_error(self):
        from engine import MAX_HOSTNAME_LEN
        raw = _make_event()
        raw["hostname"] = "h" * (MAX_HOSTNAME_LEN + 1)
        evt, err = normalize_event(raw)
        self.assertIsNone(evt)
        self.assertIsNotNone(err)
        self.assertIn("hostname", err.reason)

    def test_source_reference_too_long_returns_parse_error(self):
        from engine import MAX_SOURCE_REF_LEN
        raw = _make_event()
        raw["source_reference"] = "r" * (MAX_SOURCE_REF_LEN + 1)
        evt, err = normalize_event(raw)
        self.assertIsNone(evt)
        self.assertIsNotNone(err)


# ---------------------------------------------------------------------------
# Phase 2 database tests — helpers
# ---------------------------------------------------------------------------

import pathlib
import tempfile

from database import (
    DEFAULT_DB_PATH,
    INCIDENT_DISPOSITIONS,
    INCIDENT_STATUSES,
    MAX_ANALYST_NOTE_LEN,
    EventSaveResult,
    add_analyst_note,
    create_import_batch,
    get_event,
    get_events,
    get_import_batch,
    get_incident,
    get_schema_version,
    init_db,
    list_incidents,
    load_all_events_for_detection,
    run_detection_pipeline,
    save_detections,
    save_event,
    save_events_batch,
    save_incident,
    update_import_batch,
    update_incident_disposition,
    update_incident_status,
)


def _make_db() -> pathlib.Path:
    """Create a temp dir + initialized database, returning the db Path."""
    tmp = tempfile.mkdtemp()
    p = pathlib.Path(tmp) / "test.db"
    init_db(p)
    return p


def _make_batch(db_path: pathlib.Path, batch_id: str = "B1") -> None:
    create_import_batch(batch_id, "test.json", db_path=db_path)


def _evt(
    event_id: str = "E1",
    ts_offset_min: int = 0,
    source_ip: str = "192.0.2.1",
    username: str = "alice",
    event_type: str = "authentication",
    outcome: str = "failure",
) -> NormalizedEvent:
    base = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    return NormalizedEvent(
        event_id=event_id,
        timestamp=base + timedelta(minutes=ts_offset_min),
        source_ip=source_ip,
        username=username,
        event_type=event_type,
        outcome=outcome,
    )


def _brute_force_events(
    ip: str = "192.0.2.1",
    username: str = "alice",
    count: int = 5,
    start_min: int = 0,
) -> List[NormalizedEvent]:
    """5+ failures within 5 minutes — enough to trigger RULE_A."""
    return [
        _evt(f"BF-{ip}-{username}-{i}", ts_offset_min=start_min + i, source_ip=ip, username=username)
        for i in range(count)
    ]


# ---------------------------------------------------------------------------
# TestDatabaseInit
# ---------------------------------------------------------------------------

class TestDatabaseInit(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = pathlib.Path(self.tmp) / "test.db"

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_init_creates_database_file(self):
        self.assertFalse(self.db.exists())
        init_db(self.db)
        self.assertTrue(self.db.exists())

    def test_init_sets_schema_version_1(self):
        init_db(self.db)
        self.assertEqual(get_schema_version(self.db), 1)

    def test_init_is_idempotent(self):
        """Calling init_db twice must not raise and must not change the version."""
        init_db(self.db)
        init_db(self.db)
        self.assertEqual(get_schema_version(self.db), 1)

    def test_init_creates_expected_tables(self):
        import sqlite3
        init_db(self.db)
        conn = sqlite3.connect(str(self.db))
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        conn.close()
        for expected in ("schema_version", "import_batches", "events",
                         "incidents", "incident_evidence"):
            self.assertIn(expected, tables)

    def test_foreign_keys_enforced(self):
        """Inserting an event with a non-existent batch_id must fail."""
        import sqlite3
        init_db(self.db)
        evt = _evt()
        with self.assertRaises(Exception):
            save_event(evt, batch_id="nonexistent-batch", db_path=self.db)


# ---------------------------------------------------------------------------
# TestImportBatch
# ---------------------------------------------------------------------------

class TestImportBatch(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = pathlib.Path(self.tmp) / "test.db"
        init_db(self.db)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_create_and_retrieve_batch(self):
        create_import_batch("B1", "events.json", db_path=self.db)
        b = get_import_batch("B1", db_path=self.db)
        self.assertIsNotNone(b)
        self.assertEqual(b["batch_id"], "B1")
        self.assertEqual(b["source_name"], "events.json")
        self.assertEqual(b["status"], "completed")
        self.assertEqual(b["total"], 0)

    def test_update_batch_counts(self):
        create_import_batch("B2", "f.csv", db_path=self.db)
        update_import_batch("B2", total=20, accepted=18, rejected=1,
                            duplicates=1, conflicts=0, db_path=self.db)
        b = get_import_batch("B2", db_path=self.db)
        self.assertEqual(b["accepted"], 18)
        self.assertEqual(b["rejected"], 1)
        self.assertEqual(b["duplicates"], 1)

    def test_invalid_batch_status_rejected(self):
        create_import_batch("B3", "x.json", db_path=self.db)
        with self.assertRaises(ValueError):
            update_import_batch("B3", 0, 0, 0, 0, 0, status="unknown",
                                db_path=self.db)

    def test_get_nonexistent_batch_returns_none(self):
        self.assertIsNone(get_import_batch("no-such-batch", db_path=self.db))


# ---------------------------------------------------------------------------
# TestEventPersistence
# ---------------------------------------------------------------------------

class TestEventPersistence(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = pathlib.Path(self.tmp) / "test.db"
        init_db(self.db)
        create_import_batch("B1", "test.json", db_path=self.db)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_save_and_retrieve_event(self):
        evt = _evt("E1")
        result = save_event(evt, batch_id="B1", db_path=self.db)
        self.assertEqual(result.status, "accepted")
        stored = get_event("E1", db_path=self.db)
        self.assertIsNotNone(stored)
        self.assertEqual(stored["event_id"], "E1")
        self.assertEqual(stored["source_ip"], "192.0.2.1")
        self.assertEqual(stored["username"], "alice")

    def test_timestamp_stored_as_utc_string(self):
        evt = _evt("E2")
        save_event(evt, db_path=self.db)
        stored = get_event("E2", db_path=self.db)
        # Must end with Z
        self.assertTrue(stored["timestamp"].endswith("Z"),
                        f"timestamp {stored['timestamp']!r} not UTC")

    def test_duplicate_event_returns_duplicate_status(self):
        evt = _evt("E3")
        r1 = save_event(evt, db_path=self.db)
        r2 = save_event(evt, db_path=self.db)
        self.assertEqual(r1.status, "accepted")
        self.assertEqual(r2.status, "duplicate")

    def test_duplicate_does_not_create_second_row(self):
        evt = _evt("E4")
        save_event(evt, db_path=self.db)
        save_event(evt, db_path=self.db)
        rows = get_events(db_path=self.db)
        ids = [r["event_id"] for r in rows if r["event_id"] == "E4"]
        self.assertEqual(len(ids), 1)

    def test_conflicting_event_id_returns_conflict_status(self):
        """Same event_id but different content → conflict, original preserved."""
        evt1 = _evt("E5", source_ip="192.0.2.1")
        evt2 = _evt("E5", source_ip="192.0.2.99")  # different IP = different content
        save_event(evt1, db_path=self.db)
        r2 = save_event(evt2, db_path=self.db)
        self.assertEqual(r2.status, "conflict")
        # Original must be preserved
        stored = get_event("E5", db_path=self.db)
        self.assertEqual(stored["source_ip"], "192.0.2.1")

    def test_save_events_batch_counts(self):
        evts = [_evt(f"B{i}") for i in range(5)]
        counts = save_events_batch(evts, batch_id="B1", db_path=self.db)
        self.assertEqual(counts["accepted"], 5)
        self.assertEqual(counts["duplicate"], 0)
        self.assertEqual(counts["conflict"], 0)

    def test_save_events_batch_idempotent(self):
        evts = [_evt(f"C{i}") for i in range(3)]
        save_events_batch(evts, batch_id="B1", db_path=self.db)
        counts2 = save_events_batch(evts, batch_id="B1", db_path=self.db)
        self.assertEqual(counts2["accepted"], 0)
        self.assertEqual(counts2["duplicate"], 3)

    def test_get_events_pagination(self):
        evts = [_evt(f"P{i}", ts_offset_min=i) for i in range(10)]
        save_events_batch(evts, db_path=self.db)
        page1 = get_events(limit=3, offset=0, db_path=self.db)
        page2 = get_events(limit=3, offset=3, db_path=self.db)
        self.assertEqual(len(page1), 3)
        self.assertEqual(len(page2), 3)
        ids1 = {r["event_id"] for r in page1}
        ids2 = {r["event_id"] for r in page2}
        self.assertEqual(len(ids1 & ids2), 0, "Pages must not overlap")

    def test_get_events_filter_by_ip(self):
        save_event(_evt("IP1", source_ip="192.0.2.1"), db_path=self.db)
        save_event(_evt("IP2", source_ip="192.0.2.2"), db_path=self.db)
        rows = get_events(source_ip="192.0.2.1", db_path=self.db)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event_id"], "IP1")

    def test_get_events_limit_cap(self):
        """Requests for > 1000 records are silently capped at 1000."""
        rows = get_events(limit=99999, db_path=self.db)
        # Just check no crash and type is list
        self.assertIsInstance(rows, list)

    def test_save_event_no_batch_accepted(self):
        """Saving with batch_id=None must work (batch FK is nullable)."""
        evt = _evt("NB1")
        r = save_event(evt, batch_id=None, db_path=self.db)
        self.assertEqual(r.status, "accepted")

    def test_unicode_username_preserved(self):
        """Unicode characters in username must be stored and retrieved intact."""
        raw = _make_event(event_id="UNI1", username="用户名")
        raw["source_ip"] = "192.0.2.1"
        from engine import normalize_event
        evt, err = normalize_event(raw)
        self.assertIsNone(err)
        save_event(evt, db_path=self.db)
        stored = get_event("UNI1", db_path=self.db)
        self.assertEqual(stored["username"], "用户名")

    def test_control_char_in_hostname_stored_as_data(self):
        """Control characters in hostname are stored as data, not executed."""
        raw = _make_event(event_id="CTL1")
        raw["hostname"] = "host\x01name"
        raw["source_ip"] = "192.0.2.1"
        from engine import normalize_event
        evt, err = normalize_event(raw)
        if err:
            # If engine rejects control chars, that's fine
            return
        save_event(evt, db_path=self.db)
        stored = get_event("CTL1", db_path=self.db)
        self.assertIsNotNone(stored)


# ---------------------------------------------------------------------------
# TestIncidentPersistence
# ---------------------------------------------------------------------------

class TestIncidentPersistence(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = pathlib.Path(self.tmp) / "test.db"
        init_db(self.db)
        create_import_batch("B1", "test.json", db_path=self.db)
        self.bf_events = _brute_force_events()
        save_events_batch(self.bf_events, batch_id="B1", db_path=self.db)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_detection_pipeline_creates_incident(self):
        result = run_detection_pipeline(self.bf_events, db_path=self.db)
        self.assertGreater(result["new_incidents"], 0)
        self.assertEqual(result["detection_errors"], 0)

    def test_incident_has_correct_rule_id(self):
        run_detection_pipeline(self.bf_events, db_path=self.db)
        incs = list_incidents(db_path=self.db)
        rule_ids = {i["rule_id"] for i in incs}
        self.assertIn("RULE_A", rule_ids)

    def test_incident_initial_status_is_new(self):
        run_detection_pipeline(self.bf_events, db_path=self.db)
        incs = list_incidents(db_path=self.db)
        self.assertTrue(all(i["status"] == "New" for i in incs))

    def test_incident_initial_disposition_is_undetermined(self):
        run_detection_pipeline(self.bf_events, db_path=self.db)
        incs = list_incidents(db_path=self.db)
        self.assertTrue(all(i["disposition"] == "Undetermined" for i in incs))

    def test_incident_evidence_links_created(self):
        run_detection_pipeline(self.bf_events, db_path=self.db)
        incs = list_incidents(db_path=self.db)
        inc = get_incident(incs[0]["incident_id"], db_path=self.db)
        self.assertGreater(len(inc["evidence_event_ids"]), 0)

    def test_evidence_ids_match_input_events(self):
        run_detection_pipeline(self.bf_events, db_path=self.db)
        input_ids = {e.event_id for e in self.bf_events}
        incs = list_incidents(db_path=self.db)
        inc = get_incident(incs[0]["incident_id"], db_path=self.db)
        for eid in inc["evidence_event_ids"]:
            self.assertIn(eid, input_ids)

    def test_reprocessing_does_not_create_duplicate_incidents(self):
        run_detection_pipeline(self.bf_events, db_path=self.db)
        run_detection_pipeline(self.bf_events, db_path=self.db)
        incs = list_incidents(db_path=self.db)
        self.assertEqual(len(incs), 1)

    def test_reprocessing_preserves_analyst_status(self):
        run_detection_pipeline(self.bf_events, db_path=self.db)
        incs = list_incidents(db_path=self.db)
        iid = incs[0]["incident_id"]
        update_incident_status(iid, "Investigating", db_path=self.db)
        run_detection_pipeline(self.bf_events, db_path=self.db)
        inc2 = get_incident(iid, db_path=self.db)
        self.assertEqual(inc2["status"], "Investigating")

    def test_reprocessing_preserves_analyst_notes(self):
        run_detection_pipeline(self.bf_events, db_path=self.db)
        incs = list_incidents(db_path=self.db)
        iid = incs[0]["incident_id"]
        add_analyst_note(iid, "Confirmed source", db_path=self.db)
        run_detection_pipeline(self.bf_events, db_path=self.db)
        inc2 = get_incident(iid, db_path=self.db)
        self.assertIn("Confirmed source", inc2["analyst_notes"])

    def test_reprocessing_preserves_disposition(self):
        run_detection_pipeline(self.bf_events, db_path=self.db)
        incs = list_incidents(db_path=self.db)
        iid = incs[0]["incident_id"]
        update_incident_disposition(iid, "False Positive", db_path=self.db)
        run_detection_pipeline(self.bf_events, db_path=self.db)
        inc2 = get_incident(iid, db_path=self.db)
        self.assertEqual(inc2["disposition"], "False Positive")

    def test_distinct_clusters_produce_separate_incidents(self):
        """Two temporally separated brute-force clusters → 2 incidents."""
        # Cluster 1: t=0..4 min
        c1 = _brute_force_events(start_min=0)
        # Cluster 2: t=60..64 min (different 5-min bucket)
        c2 = _brute_force_events(
            username="alice",
            start_min=60,
        )
        for e in c2:
            object.__setattr__(e, "event_id", "C2-" + e.event_id)

        all_events = c1 + c2
        save_events_batch(all_events, db_path=self.db)
        run_detection_pipeline(all_events, db_path=self.db)
        incs = [i for i in list_incidents(db_path=self.db) if i["rule_id"] == "RULE_A"]
        self.assertEqual(len(incs), 2,
            "Temporally distinct clusters must produce separate incidents")

    def test_all_three_rules_produce_incidents(self):
        base = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        # RULE_A: 5 failures same IP+user
        rule_a_events = [
            NormalizedEvent(f"RA{i}", base + timedelta(seconds=i*60),
                            "192.0.2.10", "ruleA", "authentication", "failure")
            for i in range(5)
        ]
        # RULE_B: 10 failures, 10 distinct users
        rule_b_events = [
            NormalizedEvent(f"RB{i}", base + timedelta(seconds=i*50),
                            "203.0.113.1", f"spray{i:02d}", "authentication", "failure")
            for i in range(10)
        ]
        # RULE_C: 3 failures + success
        rule_c_events = [
            NormalizedEvent(f"RC{i}", base + timedelta(seconds=i*60),
                            "198.51.100.1", "ruleC", "authentication", "failure")
            for i in range(3)
        ] + [
            NormalizedEvent("RC-S", base + timedelta(minutes=5),
                            "198.51.100.1", "ruleC", "authentication", "success")
        ]
        all_events = rule_a_events + rule_b_events + rule_c_events
        save_events_batch(all_events, db_path=self.db)
        run_detection_pipeline(all_events, db_path=self.db)
        incs = list_incidents(db_path=self.db)
        rule_ids = {i["rule_id"] for i in incs}
        self.assertIn("RULE_A", rule_ids)
        self.assertIn("RULE_B", rule_ids)
        self.assertIn("RULE_C", rule_ids)

    def test_duplicate_import_does_not_inflate_incident_count(self):
        """Importing the same events twice must not create additional incidents."""
        run_detection_pipeline(self.bf_events, db_path=self.db)
        run_detection_pipeline(self.bf_events, db_path=self.db)
        incs = list_incidents(db_path=self.db)
        self.assertEqual(len(incs), 1)

    def test_get_incident_includes_affected_usernames_list(self):
        run_detection_pipeline(self.bf_events, db_path=self.db)
        incs = list_incidents(db_path=self.db)
        inc = get_incident(incs[0]["incident_id"], db_path=self.db)
        self.assertIsInstance(inc["affected_usernames"], list)

    def test_get_incident_unknown_id_returns_none(self):
        self.assertIsNone(get_incident("INC-000000000000", db_path=self.db))


# ---------------------------------------------------------------------------
# TestAnalystWorkflow
# ---------------------------------------------------------------------------

class TestAnalystWorkflow(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = pathlib.Path(self.tmp) / "test.db"
        init_db(self.db)
        create_import_batch("B1", "test.json", db_path=self.db)
        evts = _brute_force_events()
        save_events_batch(evts, batch_id="B1", db_path=self.db)
        run_detection_pipeline(evts, db_path=self.db)
        self.incident_id = list_incidents(db_path=self.db)[0]["incident_id"]

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_update_status_investigating(self):
        update_incident_status(self.incident_id, "Investigating", db_path=self.db)
        inc = get_incident(self.incident_id, db_path=self.db)
        self.assertEqual(inc["status"], "Investigating")

    def test_update_status_resolved(self):
        update_incident_status(self.incident_id, "Resolved", db_path=self.db)
        inc = get_incident(self.incident_id, db_path=self.db)
        self.assertEqual(inc["status"], "Resolved")

    def test_invalid_status_raises_value_error(self):
        with self.assertRaises(ValueError):
            update_incident_status(self.incident_id, "Closed", db_path=self.db)

    def test_unknown_incident_id_status_raises(self):
        with self.assertRaises(ValueError):
            update_incident_status("INC-bad", "Resolved", db_path=self.db)

    def test_update_disposition_true_positive(self):
        update_incident_disposition(self.incident_id, "True Positive", db_path=self.db)
        inc = get_incident(self.incident_id, db_path=self.db)
        self.assertEqual(inc["disposition"], "True Positive")

    def test_update_disposition_false_positive(self):
        update_incident_disposition(self.incident_id, "False Positive", db_path=self.db)
        inc = get_incident(self.incident_id, db_path=self.db)
        self.assertEqual(inc["disposition"], "False Positive")

    def test_invalid_disposition_raises_value_error(self):
        with self.assertRaises(ValueError):
            update_incident_disposition(self.incident_id, "Benign", db_path=self.db)

    def test_unknown_incident_id_disposition_raises(self):
        with self.assertRaises(ValueError):
            update_incident_disposition("INC-bad", "True Positive", db_path=self.db)

    def test_add_note_appended(self):
        add_analyst_note(self.incident_id, "First note", db_path=self.db)
        inc = get_incident(self.incident_id, db_path=self.db)
        self.assertIn("First note", inc["analyst_notes"])

    def test_add_multiple_notes_both_present(self):
        add_analyst_note(self.incident_id, "Note A", db_path=self.db)
        add_analyst_note(self.incident_id, "Note B", db_path=self.db)
        inc = get_incident(self.incident_id, db_path=self.db)
        self.assertIn("Note A", inc["analyst_notes"])
        self.assertIn("Note B", inc["analyst_notes"])

    def test_note_too_long_raises_value_error(self):
        with self.assertRaises(ValueError):
            add_analyst_note(
                self.incident_id,
                "x" * (MAX_ANALYST_NOTE_LEN + 1),
                db_path=self.db,
            )

    def test_note_non_string_raises_value_error(self):
        with self.assertRaises(ValueError):
            add_analyst_note(self.incident_id, 12345, db_path=self.db)

    def test_note_unknown_incident_raises(self):
        with self.assertRaises(ValueError):
            add_analyst_note("INC-bad", "hello", db_path=self.db)

    def test_html_in_note_stored_as_data(self):
        """HTML-like content in notes must be stored verbatim, not rendered."""
        note = "<script>alert('xss')</script>"
        add_analyst_note(self.incident_id, note, db_path=self.db)
        inc = get_incident(self.incident_id, db_path=self.db)
        self.assertIn("<script>", inc["analyst_notes"])

    def test_updated_at_changes_after_status_update(self):
        inc_before = get_incident(self.incident_id, db_path=self.db)
        import time; time.sleep(1)  # ensure clock advances
        update_incident_status(self.incident_id, "Investigating", db_path=self.db)
        inc_after = get_incident(self.incident_id, db_path=self.db)
        self.assertGreaterEqual(inc_after["updated_at"], inc_before["updated_at"])


# ---------------------------------------------------------------------------
# TestListAndPagination
# ---------------------------------------------------------------------------

class TestListAndPagination(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = pathlib.Path(self.tmp) / "test.db"
        init_db(self.db)
        create_import_batch("B1", "test.json", db_path=self.db)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _create_n_incidents(self, n: int) -> None:
        base = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        for k in range(n):
            # Each user gets a distinct brute-force incident
            username = f"user{k:03d}"
            events = [
                NormalizedEvent(
                    f"LI-{username}-{i}",
                    base + timedelta(hours=k, seconds=i * 60),
                    f"192.0.2.{(k % 254) + 1}",
                    username,
                    "authentication",
                    "failure",
                )
                for i in range(5)
            ]
            save_events_batch(events, db_path=self.db)
            run_detection_pipeline(events, db_path=self.db)

    def test_list_incidents_default_limit(self):
        self._create_n_incidents(3)
        incs = list_incidents(db_path=self.db)
        self.assertEqual(len(incs), 3)

    def test_list_incidents_pagination(self):
        self._create_n_incidents(5)
        page1 = list_incidents(limit=2, offset=0, db_path=self.db)
        page2 = list_incidents(limit=2, offset=2, db_path=self.db)
        ids1 = {i["incident_id"] for i in page1}
        ids2 = {i["incident_id"] for i in page2}
        self.assertEqual(len(ids1 & ids2), 0, "Pages must not overlap")

    def test_list_incidents_filter_by_status(self):
        self._create_n_incidents(3)
        all_incs = list_incidents(db_path=self.db)
        # Set first to Investigating
        update_incident_status(all_incs[0]["incident_id"], "Investigating",
                               db_path=self.db)
        inv = list_incidents(status="Investigating", db_path=self.db)
        self.assertEqual(len(inv), 1)
        new_incs = list_incidents(status="New", db_path=self.db)
        self.assertEqual(len(new_incs), 2)

    def test_list_incidents_invalid_status_raises(self):
        with self.assertRaises(ValueError):
            list_incidents(status="Unknown", db_path=self.db)

    def test_list_incidents_empty_database(self):
        self.assertEqual(list_incidents(db_path=self.db), [])


# ---------------------------------------------------------------------------
# TestTransactionRollback
# ---------------------------------------------------------------------------

class TestTransactionRollback(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = pathlib.Path(self.tmp) / "test.db"
        init_db(self.db)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_batch_rollback_on_failure(self):
        """
        If a batch insert fails partway through (simulated by passing an
        invalid NormalizedEvent whose insert will violate a constraint), the
        entire batch must be rolled back — no partial writes.
        """
        import sqlite3 as _sqlite3
        from database import _get_connection, _transaction

        init_db(self.db)
        conn = _get_connection(self.db)
        # Verify table is empty before
        count_before = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        conn.close()

        # Force a mid-batch failure by passing an event that would insert fine,
        # then attempting a direct SQL error inside a transaction.
        good_evt = _evt("ROL1")
        try:
            conn2 = _get_connection(self.db)
            with _transaction(conn2) as c:
                c.execute(
                    """INSERT INTO events
                    (event_id, content_hash, source_ip, username, event_type,
                     outcome, timestamp, imported_at)
                    VALUES (?,?,?,?,?,?,?,?)""",
                    ("ROL1", "hash1", "192.0.2.1", "alice",
                     "authentication", "failure", "2024-01-15T10:00:00Z",
                     "2024-01-15T10:00:00Z"),
                )
                # Force constraint violation (duplicate PK via content_hash uniqueness)
                c.execute(
                    """INSERT INTO events
                    (event_id, content_hash, source_ip, username, event_type,
                     outcome, timestamp, imported_at)
                    VALUES (?,?,?,?,?,?,?,?)""",
                    ("ROL1", "hash1", "192.0.2.1", "alice",
                     "authentication", "failure", "2024-01-15T10:00:00Z",
                     "2024-01-15T10:00:00Z"),
                )
        except _sqlite3.IntegrityError:
            pass  # expected
        finally:
            conn2.close()

        conn3 = _get_connection(self.db)
        count_after = conn3.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        conn3.close()
        self.assertEqual(count_before, count_after,
                         "Failed transaction must leave no partial data")


# ---------------------------------------------------------------------------
# TestIntegrationFlow
# ---------------------------------------------------------------------------

class TestIntegrationFlow(unittest.TestCase):
    """
    End-to-end integration: synthetic events → parse → persist → detect → incidents.
    Mirrors what the dashboard will eventually call.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = pathlib.Path(self.tmp) / "test.db"
        init_db(self.db)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_full_flow_from_json_to_incidents(self):
        import json as _json
        from engine import parse_json_events

        # Build synthetic events that cover all three rules
        base = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        raw_events = []
        # RULE_A: 5 failures for 'alice'
        for i in range(5):
            raw_events.append({
                "event_id": f"INT-A-{i}", "source_ip": "192.0.2.1",
                "username": "alice", "event_type": "authentication",
                "outcome": "failure",
                "timestamp": (base + timedelta(seconds=i*60)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            })
        # RULE_B: 10 failures, 10 users
        for i in range(10):
            raw_events.append({
                "event_id": f"INT-B-{i}", "source_ip": "203.0.113.1",
                "username": f"spray{i:02d}", "event_type": "authentication",
                "outcome": "failure",
                "timestamp": (base + timedelta(seconds=i*50)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            })
        # RULE_C: 3 failures + success for 'bob'
        for i in range(3):
            raw_events.append({
                "event_id": f"INT-C-F{i}", "source_ip": "198.51.100.1",
                "username": "bob", "event_type": "authentication",
                "outcome": "failure",
                "timestamp": (base + timedelta(seconds=i*60)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            })
        raw_events.append({
            "event_id": "INT-C-S", "source_ip": "198.51.100.1",
            "username": "bob", "event_type": "authentication",
            "outcome": "success",
            "timestamp": (base + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        })

        # Parse
        events, errors = parse_json_events(raw_events)
        self.assertEqual(len(errors), 0)
        self.assertGreater(len(events), 0)

        # Persist events
        create_import_batch("INT-BATCH", "integration_test.json", db_path=self.db)
        save_counts = save_events_batch(events, batch_id="INT-BATCH", db_path=self.db)
        self.assertEqual(save_counts["accepted"], len(events))

        # Update batch stats
        update_import_batch(
            "INT-BATCH",
            total=len(raw_events),
            accepted=save_counts["accepted"],
            rejected=len(errors),
            duplicates=save_counts["duplicate"],
            conflicts=save_counts["conflict"],
            db_path=self.db,
        )

        # Run detection
        pipeline_result = run_detection_pipeline(events, db_path=self.db)
        self.assertGreater(pipeline_result["new_incidents"], 0)
        self.assertEqual(pipeline_result["detection_errors"], 0)

        # Check all three rules fired
        incs = list_incidents(db_path=self.db)
        rule_ids = {i["rule_id"] for i in incs}
        self.assertIn("RULE_A", rule_ids)
        self.assertIn("RULE_B", rule_ids)
        self.assertIn("RULE_C", rule_ids)

        # Analyst workflow
        first_inc = incs[0]["incident_id"]
        update_incident_status(first_inc, "Investigating", db_path=self.db)
        add_analyst_note(first_inc, "Reviewed — escalating", db_path=self.db)
        inc_detail = get_incident(first_inc, db_path=self.db)
        self.assertEqual(inc_detail["status"], "Investigating")
        self.assertIn("escalating", inc_detail["analyst_notes"])

        # Re-run: no new incidents, analyst data intact
        result2 = run_detection_pipeline(events, db_path=self.db)
        self.assertEqual(result2["new_incidents"], 0)
        inc_check = get_incident(first_inc, db_path=self.db)
        self.assertEqual(inc_check["status"], "Investigating")


# ---------------------------------------------------------------------------
# Phase 3 tests — reporting.py
# ---------------------------------------------------------------------------

from reporting import (
    EvalMetrics,
    EvalScenario,
    ScenarioResult,
    _h,
    _sanitize_csv_cell,
    build_labelled_dataset,
    evaluate_scenarios,
    export_incidents_csv,
    export_incidents_json,
    export_metrics_csv,
    export_metrics_json,
    generate_html_report,
    generate_incident_report,
    list_incident_reports,
)


class TestEvalMetrics(unittest.TestCase):
    """Unit tests for metric calculation logic."""

    def _metrics(self, tp, fp, fn, tn):
        """Helper: build minimal EvalMetrics from raw counts."""
        prec = (tp / (tp + fp)) if (tp + fp) > 0 else None
        rec  = (tp / (tp + fn)) if (tp + fn) > 0 else None
        f1   = (2 * prec * rec / (prec + rec)
                if prec is not None and rec is not None and (prec + rec) > 0
                else None)
        total = tp + fp + fn + tn
        acc = (tp + tn) / total if total > 0 else None
        return EvalMetrics(tp=tp, fp=fp, fn=fn, tn=tn,
                           precision=prec, recall=rec, f1=f1, accuracy=acc,
                           scenario_count=1)

    def test_perfect_precision_and_recall(self):
        m = self._metrics(tp=5, fp=0, fn=0, tn=10)
        self.assertAlmostEqual(m.precision, 1.0)
        self.assertAlmostEqual(m.recall, 1.0)
        self.assertAlmostEqual(m.f1, 1.0)

    def test_zero_tp_fp_precision_undefined(self):
        m = self._metrics(tp=0, fp=0, fn=3, tn=5)
        self.assertIsNone(m.precision)

    def test_zero_tp_fn_recall_undefined(self):
        m = self._metrics(tp=0, fp=2, fn=0, tn=5)
        self.assertIsNone(m.recall)

    def test_all_zeros_accuracy_undefined(self):
        m = self._metrics(tp=0, fp=0, fn=0, tn=0)
        self.assertIsNone(m.accuracy)

    def test_metrics_within_valid_range(self):
        for tp, fp, fn, tn in [(3,1,1,5), (0,2,3,8), (5,0,0,10)]:
            m = self._metrics(tp, fp, fn, tn)
            for attr in ("precision", "recall", "f1", "accuracy"):
                v = getattr(m, attr)
                if v is not None:
                    self.assertGreaterEqual(v, 0.0)
                    self.assertLessEqual(v, 1.0)

    def test_f1_undefined_when_precision_undefined(self):
        m = self._metrics(tp=0, fp=0, fn=2, tn=5)
        self.assertIsNone(m.f1)

    def test_dataset_label_contains_synthetic(self):
        m = self._metrics(tp=1, fp=0, fn=0, tn=1)
        self.assertIn("SYNTHETIC", m.dataset_label.upper())


class TestEvaluateScenarios(unittest.TestCase):
    """Tests for evaluate_scenarios() using the real detection engine."""

    def _fail_events(self, ip, user, count=5, spacing_s=55):
        base = datetime(2024, 6, 1, 9, 0, 0, tzinfo=timezone.utc)
        return [
            NormalizedEvent(f"TS-{ip}-{user}-{i}",
                            base + timedelta(seconds=i * spacing_s),
                            ip, user, "authentication", "failure")
            for i in range(count)
        ]

    def test_benign_scenario_no_detections(self):
        base = datetime(2024, 6, 1, 9, 0, 0, tzinfo=timezone.utc)
        s = EvalScenario(
            name="benign",
            events=[NormalizedEvent(f"BN{i}", base + timedelta(minutes=i),
                                    "192.0.2.1", f"u{i}",
                                    "authentication", "success")
                    for i in range(3)],
            expected_rules=set(),
        )
        results, metrics = evaluate_scenarios([s])
        self.assertEqual(metrics.tp, 0)
        self.assertEqual(metrics.fp, 0)
        self.assertEqual(metrics.fn, 0)
        self.assertEqual(metrics.tn, 3)   # 3 rules × 1 scenario not expected/fired

    def test_rule_a_scenario_tp(self):
        s = EvalScenario(
            name="rule_a",
            events=self._fail_events("192.0.2.1", "alice"),
            expected_rules={"RULE_A"},
        )
        results, metrics = evaluate_scenarios([s])
        self.assertEqual(metrics.tp, 1)
        self.assertEqual(metrics.fp, 0)
        self.assertEqual(metrics.fn, 0)

    def test_fp_when_rule_fires_unexpectedly(self):
        # Expect nothing, but feed 5 quick failures → RULE_A fires = FP
        s = EvalScenario(
            name="unexpected_rule_a",
            events=self._fail_events("192.0.2.2", "bob"),
            expected_rules=set(),   # labelled as benign — wrong label for testing
        )
        results, metrics = evaluate_scenarios([s])
        self.assertEqual(metrics.fp, 1)
        self.assertEqual(metrics.tp, 0)

    def test_fn_when_expected_rule_does_not_fire(self):
        # Expect RULE_A but give only 3 failures (below threshold) → FN
        base = datetime(2024, 6, 1, 9, 0, 0, tzinfo=timezone.utc)
        s = EvalScenario(
            name="fn_rule_a",
            events=[NormalizedEvent(f"FN{i}", base + timedelta(seconds=i*60),
                                    "192.0.2.3", "carol", "authentication", "failure")
                    for i in range(3)],
            expected_rules={"RULE_A"},
        )
        results, metrics = evaluate_scenarios([s])
        self.assertEqual(metrics.fn, 1)
        self.assertEqual(metrics.tp, 0)

    def test_empty_scenario_list(self):
        results, metrics = evaluate_scenarios([])
        self.assertEqual(len(results), 0)
        self.assertEqual(metrics.tp, 0)
        self.assertIsNone(metrics.accuracy)

    def test_consistent_results_on_repeated_calls(self):
        """Same scenarios produce identical metrics every time."""
        scenarios = build_labelled_dataset()
        _, m1 = evaluate_scenarios(scenarios)
        _, m2 = evaluate_scenarios(scenarios)
        self.assertEqual(m1.tp, m2.tp)
        self.assertEqual(m1.fp, m2.fp)
        self.assertEqual(m1.fn, m2.fn)
        self.assertEqual(m1.tn, m2.tn)

    def test_build_labelled_dataset_no_fp_no_fn(self):
        """The built-in labelled dataset must have zero FP and FN."""
        scenarios = build_labelled_dataset()
        _, metrics = evaluate_scenarios(scenarios)
        self.assertEqual(metrics.fp, 0, f"Unexpected FP in labelled dataset")
        self.assertEqual(metrics.fn, 0, f"Unexpected FN in labelled dataset")

    def test_scenario_result_properties(self):
        base = datetime(2024, 6, 1, 9, 0, 0, tzinfo=timezone.utc)
        s = EvalScenario(
            name="test",
            events=[NormalizedEvent(f"R{i}", base + timedelta(seconds=i*55),
                                    "192.0.2.5", "dave", "authentication", "failure")
                    for i in range(5)],
            expected_rules={"RULE_A"},
        )
        results, _ = evaluate_scenarios([s])
        r = results[0]
        self.assertIn("RULE_A", r.true_positives)
        self.assertEqual(len(r.false_positives), 0)
        self.assertEqual(len(r.false_negatives), 0)
        self.assertIn("RULE_B", r.true_negatives)
        self.assertIn("RULE_C", r.true_negatives)


class TestCsvSanitization(unittest.TestCase):
    """Tests for CSV formula injection prevention."""

    def test_equals_prefix_sanitized(self):
        self.assertTrue(_sanitize_csv_cell("=CMD|kill").startswith("\t"))

    def test_plus_prefix_sanitized(self):
        self.assertTrue(_sanitize_csv_cell("+1").startswith("\t"))

    def test_minus_prefix_sanitized(self):
        self.assertTrue(_sanitize_csv_cell("-1").startswith("\t"))

    def test_at_prefix_sanitized(self):
        self.assertTrue(_sanitize_csv_cell("@SUM(A1)").startswith("\t"))

    def test_leading_space_before_equals_sanitized(self):
        self.assertTrue(_sanitize_csv_cell("  =CMD").startswith("\t"))

    def test_leading_control_char_before_equals_sanitized(self):
        self.assertTrue(_sanitize_csv_cell("\x00=CMD").startswith("\t"))

    def test_normal_string_unchanged(self):
        self.assertEqual(_sanitize_csv_cell("hello"), "hello")

    def test_number_string_unchanged(self):
        self.assertEqual(_sanitize_csv_cell("12345"), "12345")

    def test_empty_string_unchanged(self):
        self.assertEqual(_sanitize_csv_cell(""), "")

    def test_hyphen_in_middle_unchanged(self):
        self.assertEqual(_sanitize_csv_cell("abc-def"), "abc-def")


class TestHtmlEscaping(unittest.TestCase):
    """Tests for HTML output escaping."""

    def test_script_tag_escaped(self):
        result = _h("<script>alert(1)</script>")
        self.assertNotIn("<script>", result)
        self.assertIn("&lt;script&gt;", result)

    def test_ampersand_escaped(self):
        self.assertIn("&amp;", _h("a & b"))

    def test_quotes_escaped(self):
        self.assertIn("&quot;", _h('"value"'))

    def test_none_becomes_empty_string(self):
        self.assertEqual(_h(None), "")   # None maps to empty string, not the string "None"

    def test_attribute_injection_escaped(self):
        payload = '" onmouseover="alert(1)"'
        result = _h(payload)
        self.assertNotIn('"', result.replace("&quot;", ""))


class TestJsonExport(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = pathlib.Path(self.tmp) / "test.db"
        init_db(self.db)
        create_import_batch("B1", "test.json", db_path=self.db)
        self._populate_one_incident()

    def _populate_one_incident(self):
        base = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        events = [
            NormalizedEvent(f"JE{i}", base + timedelta(seconds=i*60),
                            "192.0.2.1", "alice", "authentication", "failure")
            for i in range(5)
        ]
        save_events_batch(events, batch_id="B1", db_path=self.db)
        run_detection_pipeline(events, db_path=self.db)

    def tearDown(self):
        import shutil; shutil.rmtree(self.tmp, ignore_errors=True)

    def test_export_returns_valid_json(self):
        output = export_incidents_json(db_path=self.db)
        parsed = json.loads(output)
        self.assertIsInstance(parsed, list)
        self.assertEqual(len(parsed), 1)

    def test_export_contains_incident_fields(self):
        parsed = json.loads(export_incidents_json(db_path=self.db))
        inc = parsed[0]
        self.assertIn("incident_id", inc)
        self.assertIn("rule_id", inc)
        self.assertIn("evidence_event_ids", inc)

    def test_empty_db_returns_empty_list(self):
        tmp2 = tempfile.mkdtemp()
        db2 = pathlib.Path(tmp2) / "empty.db"
        init_db(db2)
        output = export_incidents_json(db_path=db2)
        self.assertEqual(json.loads(output), [])
        import shutil; shutil.rmtree(tmp2, ignore_errors=True)

    def test_invalid_limit_raises(self):
        with self.assertRaises(ValueError):
            export_incidents_json(db_path=self.db, limit=0)
        with self.assertRaises(ValueError):
            export_incidents_json(db_path=self.db, limit=99_999_999)

    def test_metrics_json_valid(self):
        _, m = evaluate_scenarios(build_labelled_dataset())
        output = export_metrics_json(m)
        parsed = json.loads(output)
        self.assertIn("tp", parsed)
        self.assertIn("dataset_label", parsed)
        self.assertIn("SYNTHETIC", parsed["dataset_label"])


class TestCsvExport(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = pathlib.Path(self.tmp) / "test.db"
        init_db(self.db)
        create_import_batch("B1", "test.json", db_path=self.db)
        base = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        events = [
            NormalizedEvent(f"CE{i}", base + timedelta(seconds=i*60),
                            "192.0.2.1", "alice", "authentication", "failure")
            for i in range(5)
        ]
        save_events_batch(events, batch_id="B1", db_path=self.db)
        run_detection_pipeline(events, db_path=self.db)

    def tearDown(self):
        import shutil; shutil.rmtree(self.tmp, ignore_errors=True)

    def test_export_returns_header_and_row(self):
        output = export_incidents_csv(db_path=self.db)
        lines = [l for l in output.strip().split("\n") if l]
        self.assertGreaterEqual(len(lines), 2)   # header + at least 1 row

    def test_header_contains_required_columns(self):
        output = export_incidents_csv(db_path=self.db)
        header = output.split("\n")[0]
        for col in ("incident_id", "rule_id", "severity", "status"):
            self.assertIn(col, header)

    def test_empty_db_returns_header_only(self):
        tmp2 = tempfile.mkdtemp()
        db2 = pathlib.Path(tmp2) / "empty.db"
        init_db(db2)
        output = export_incidents_csv(db_path=db2)
        lines = [l for l in output.strip().split("\n") if l]
        self.assertEqual(len(lines), 1)   # header only
        import shutil; shutil.rmtree(tmp2, ignore_errors=True)

    def test_invalid_limit_raises(self):
        with self.assertRaises(ValueError):
            export_incidents_csv(db_path=self.db, limit=0)

    def test_csv_formula_injection_neutralised(self):
        """A title starting with = must be tab-prefixed in the CSV output."""
        # Inject via analyst note pathway — create a Detection whose title
        # starts with a formula prefix
        from engine import Detection
        from datetime import timezone as _tz
        base = datetime(2024, 1, 15, 10, 0, 0, tzinfo=_tz.utc)
        malicious_title = "=CMD|kill"
        det = Detection(
            rule_id="RULE_A",
            detection_id="INJ-TEST-001",
            title=malicious_title,
            explanation="test",
            severity="Medium",
            confidence="Medium",
            source_ip="192.0.2.1",
            affected_usernames=["alice"],
            first_seen=base,
            last_seen=base + timedelta(minutes=4),
            event_ids=["E1"],
            recommended_action="test",
        )
        save_detections([det], db_path=self.db)
        output = export_incidents_csv(db_path=self.db)
        # The malicious title must not appear raw
        self.assertNotIn(",=CMD", output)

    def test_metrics_csv_valid(self):
        _, m = evaluate_scenarios(build_labelled_dataset())
        output = export_metrics_csv(m)
        lines = [l for l in output.strip().split("\n") if l]
        self.assertEqual(len(lines), 2)   # header + 1 data row
        self.assertIn("SYNTHETIC", output)


class TestHtmlReport(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = pathlib.Path(self.tmp) / "test.db"
        init_db(self.db)
        create_import_batch("B1", "test.json", db_path=self.db)
        base = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        events = [
            NormalizedEvent(f"HE{i}", base + timedelta(seconds=i*60),
                            "192.0.2.1", "alice", "authentication", "failure")
            for i in range(5)
        ]
        save_events_batch(events, batch_id="B1", db_path=self.db)
        run_detection_pipeline(events, db_path=self.db)

    def tearDown(self):
        import shutil; shutil.rmtree(self.tmp, ignore_errors=True)

    def test_returns_html_string(self):
        out = generate_html_report(self.db)
        self.assertIn("<!DOCTYPE html>", out)
        self.assertIn("</html>", out)

    def test_incident_appears_in_html(self):
        out = generate_html_report(self.db)
        self.assertIn("RULE_A", out)

    def test_script_injection_escaped(self):
        # Save an incident with a script-like title via Detection
        from engine import Detection
        from datetime import timezone as _tz
        base = datetime(2024, 1, 15, 10, 0, 0, tzinfo=_tz.utc)
        det = Detection(
            rule_id="RULE_A",
            detection_id="HTML-XSS-001",
            title="<script>alert('xss')</script>",
            explanation="test",
            severity="Medium",
            confidence="Medium",
            source_ip="192.0.2.1",
            affected_usernames=["alice"],
            first_seen=base,
            last_seen=base + timedelta(minutes=4),
            event_ids=["E1"],
            recommended_action="test",
        )
        save_detections([det], db_path=self.db)
        out = generate_html_report(self.db)
        self.assertNotIn("<script>alert", out)
        self.assertIn("&lt;script&gt;", out)

    def test_empty_db_no_crash(self):
        tmp2 = tempfile.mkdtemp()
        db2 = pathlib.Path(tmp2) / "empty.db"
        init_db(db2)
        out = generate_html_report(db2)
        self.assertIn("No incidents found", out)
        import shutil; shutil.rmtree(tmp2, ignore_errors=True)

    def test_invalid_limit_raises(self):
        with self.assertRaises(ValueError):
            generate_html_report(self.db, limit=0)
        with self.assertRaises(ValueError):
            generate_html_report(self.db, limit=99_999_999)

    def test_html_contains_metrics_section_when_provided(self):
        _, m = evaluate_scenarios(build_labelled_dataset())
        out = generate_html_report(self.db, metrics=m)
        self.assertIn("Detection Quality Lab", out)
        self.assertIn("SYNTHETIC", out)

    def test_attribute_injection_escaped(self):
        """Attacker-controlled IP with attribute injection must be escaped."""
        from engine import Detection
        from datetime import timezone as _tz
        base = datetime(2024, 1, 15, 10, 0, 0, tzinfo=_tz.utc)
        det = Detection(
            rule_id="RULE_B",
            detection_id="ATTR-INJ-001",
            title="Normal Title",
            explanation="test",
            severity="High",
            confidence="Medium",
            source_ip='192.0.2.1" onmouseover="alert(1)',
            affected_usernames=["alice"],
            first_seen=base,
            last_seen=base + timedelta(minutes=9),
            event_ids=["E1"],
            recommended_action="test",
        )
        save_detections([det], db_path=self.db)
        out = generate_html_report(self.db)
        # The raw attribute injection must not appear unescaped.
        # html.escape converts " to &quot;, so the injected attribute
        # becomes onmouseover=&quot;... which is harmless — the double-quote
        # delimiter is escaped and the attribute cannot be parsed by a browser.
        # Assert neither an unescaped quote variant nor a functional form appears.
        self.assertNotIn('onmouseover="alert', out)


class TestIncidentReportGeneration(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = pathlib.Path(self.tmp) / "test.db"
        init_db(self.db)
        create_import_batch("B1", "test.json", db_path=self.db)
        base = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        events = [
            NormalizedEvent(f"IR{i}", base + timedelta(seconds=i*60),
                            "192.0.2.1", "alice", "authentication", "failure")
            for i in range(5)
        ]
        save_events_batch(events, batch_id="B1", db_path=self.db)
        run_detection_pipeline(events, db_path=self.db)

    def tearDown(self):
        import shutil; shutil.rmtree(self.tmp, ignore_errors=True)

    def test_generate_report_returns_dict(self):
        incs = list_incidents(db_path=self.db)
        report = generate_incident_report(incs[0]["incident_id"], db_path=self.db)
        self.assertIsInstance(report, dict)
        self.assertIn("incident_id", report)
        self.assertIn("evidence_event_ids", report)

    def test_generate_report_unknown_id_raises(self):
        with self.assertRaises(ValueError):
            generate_incident_report("INC-does-not-exist", db_path=self.db)

    def test_list_reports_default_limit(self):
        reports = list_incident_reports(db_path=self.db)
        self.assertGreater(len(reports), 0)

    def test_list_reports_invalid_limit_raises(self):
        with self.assertRaises(ValueError):
            list_incident_reports(db_path=self.db, limit=0)
        with self.assertRaises(ValueError):
            list_incident_reports(db_path=self.db, limit=99_999_999)


# ---------------------------------------------------------------------------
# Phase 4 tests — app.py pure helper functions
# ---------------------------------------------------------------------------

from app import _fmt_metric, _safe_display_size


class TestAppHelpers(unittest.TestCase):
    """Tests for the pure helper functions in app.py."""

    # _fmt_metric
    def test_fmt_metric_none_returns_undefined(self):
        self.assertEqual(_fmt_metric(None), "Undefined")

    def test_fmt_metric_zero(self):
        self.assertEqual(_fmt_metric(0.0), "0.0000")

    def test_fmt_metric_one(self):
        self.assertEqual(_fmt_metric(1.0), "1.0000")

    def test_fmt_metric_custom_decimals(self):
        self.assertEqual(_fmt_metric(0.5, decimals=2), "0.50")

    def test_fmt_metric_partial(self):
        result = _fmt_metric(0.75)
        self.assertEqual(result, "0.7500")

    # _safe_display_size
    def test_safe_display_size_bytes(self):
        self.assertIn("B", _safe_display_size(500))
        self.assertNotIn("K", _safe_display_size(500))

    def test_safe_display_size_kb(self):
        result = _safe_display_size(2048)
        self.assertIn("KB", result)

    def test_safe_display_size_mb(self):
        result = _safe_display_size(5 * 1024 * 1024)
        self.assertIn("MB", result)

    def test_safe_display_size_zero(self):
        self.assertIn("B", _safe_display_size(0))

    def test_safe_display_size_exactly_1kb(self):
        result = _safe_display_size(1024)
        self.assertIn("KB", result)

    # Upload size / count validation behaviour (pure logic, no Streamlit)
    def test_max_import_bytes_constant_set(self):
        from database import MAX_IMPORT_BYTES
        self.assertGreater(MAX_IMPORT_BYTES, 0)

    def test_max_import_records_constant_set(self):
        from database import MAX_IMPORT_RECORDS
        self.assertGreater(MAX_IMPORT_RECORDS, 0)

    def test_utf8_decode_valid(self):
        """Valid UTF-8 bytes decode without error."""
        data = "hello world".encode("utf-8")
        self.assertEqual(data.decode("utf-8"), "hello world")

    def test_utf8_decode_invalid_raises(self):
        """Invalid UTF-8 raises UnicodeDecodeError."""
        with self.assertRaises(UnicodeDecodeError):
            b"\xff\xfe".decode("utf-8")


# ---------------------------------------------------------------------------
# Regression tests — detection-after-import bug
# ---------------------------------------------------------------------------

class TestDetectionAfterImport(unittest.TestCase):
    """
    Regression suite for the confirmed bug where:
    - Demo import never triggered the detection pipeline (no incidents created).
    - Re-running import with all-duplicate events also failed to create incidents.
    - There was no explicit "Run Detection" path against all stored events.

    Root cause: _import_demo_data() only saved events but never called
    _run_detection_on_events(). load_all_events_for_detection() did not exist,
    so the detection button could not be implemented independently of a parsed
    batch.
    """

    def setUp(self):
        import tempfile
        self.db = pathlib.Path(tempfile.mktemp(suffix=".db"))
        init_db(self.db)
        # Load and save demo events once (the "first import" scenario)
        raw = json.loads(pathlib.Path("demo_events.json").read_text(encoding="utf-8"))
        self._events, _ = parse_json_events(raw)
        bid = "reg-batch-1"
        create_import_batch(bid, "demo_events.json", db_path=self.db)
        save_events_batch(self._events, batch_id=bid, db_path=self.db)

    def tearDown(self):
        self.db.unlink(missing_ok=True)

    # ── load_all_events_for_detection ────────────────────────────────────────

    def test_load_all_returns_correct_count(self):
        """load_all_events_for_detection must return every stored event."""
        evts = load_all_events_for_detection(db_path=self.db)
        self.assertEqual(len(evts), len(self._events))

    def test_load_all_returns_normalized_event_objects(self):
        """Returned objects must be NormalizedEvent instances with UTC timestamps."""
        from engine import NormalizedEvent
        from datetime import timezone
        evts = load_all_events_for_detection(db_path=self.db)
        for e in evts:
            self.assertIsInstance(e, NormalizedEvent)
            self.assertIsNotNone(e.timestamp.tzinfo)
            self.assertEqual(e.timestamp.tzinfo, timezone.utc)

    def test_load_all_sorted_by_timestamp(self):
        """Events must be returned in ascending timestamp order."""
        evts = load_all_events_for_detection(db_path=self.db)
        timestamps = [e.timestamp for e in evts]
        self.assertEqual(timestamps, sorted(timestamps))

    def test_load_all_empty_db_returns_empty_list(self):
        """An empty database must return an empty list, not raise."""
        import tempfile
        empty_db = pathlib.Path(tempfile.mktemp(suffix=".db"))
        try:
            init_db(empty_db)
            result = load_all_events_for_detection(db_path=empty_db)
            self.assertEqual(result, [])
        finally:
            empty_db.unlink(missing_ok=True)

    # ── Detection fires after first import ───────────────────────────────────

    def test_detection_on_stored_events_produces_incidents(self):
        """
        Running the detection pipeline on load_all_events_for_detection output
        must produce at least one incident from the demo dataset.
        (This is the primary regression: demo import used to leave zero incidents.)
        """
        evts = load_all_events_for_detection(db_path=self.db)
        result = run_detection_pipeline(evts, db_path=self.db)
        self.assertGreater(result["new_incidents"], 0,
            "Expected at least one new incident from demo events")

    def test_demo_events_produce_all_three_rules(self):
        """Demo data must trigger all three detection rules."""
        evts = load_all_events_for_detection(db_path=self.db)
        run_detection_pipeline(evts, db_path=self.db)
        incidents = list_incidents(db_path=self.db)
        fired_rules = {inc["rule_id"] for inc in incidents}
        self.assertIn("RULE_A", fired_rules)
        self.assertIn("RULE_B", fired_rules)
        self.assertIn("RULE_C", fired_rules)

    # ── Detection fires when re-import is all duplicates ─────────────────────

    def test_detection_works_after_all_duplicate_import(self):
        """
        When a second import of the same events produces 0 accepted (all
        duplicates), running detection on all stored events must still produce
        incidents.  This covers the original bug where the user saw zero
        incidents after re-importing demo data.
        """
        # Second import — every event is a duplicate
        bid2 = "reg-batch-2"
        create_import_batch(bid2, "demo_events.json", db_path=self.db)
        counts = save_events_batch(self._events, batch_id=bid2, db_path=self.db)
        self.assertEqual(counts["accepted"], 0)
        self.assertEqual(counts["duplicate"], len(self._events))

        # Load all stored events (unchanged) and run detection
        evts = load_all_events_for_detection(db_path=self.db)
        result = run_detection_pipeline(evts, db_path=self.db)
        self.assertGreater(result["total_detections"], 0,
            "Detection must fire from stored events even when import was all-duplicate")

    def test_duplicate_import_does_not_double_incidents(self):
        """
        Running detection twice on the same stored events must not create
        duplicate incidents — deterministic IDs ensure idempotency.
        """
        evts = load_all_events_for_detection(db_path=self.db)
        run_detection_pipeline(evts, db_path=self.db)
        first_count = len(list_incidents(db_path=self.db))

        # Run detection again on the same stored events
        run_detection_pipeline(evts, db_path=self.db)
        second_count = len(list_incidents(db_path=self.db))

        self.assertEqual(first_count, second_count,
            "Re-running detection must not create duplicate incidents")

    # ── Evidence event IDs match stored events ────────────────────────────────

    def test_evidence_ids_present_in_events_table(self):
        """
        Every evidence event_id on every incident must correspond to an event
        that actually exists in the events table.
        """
        evts = load_all_events_for_detection(db_path=self.db)
        run_detection_pipeline(evts, db_path=self.db)
        incidents = list_incidents(db_path=self.db)
        for inc in incidents:
            full = get_incident(inc["incident_id"], db_path=self.db)
            for eid in full["evidence_event_ids"]:
                ev = get_event(eid, db_path=self.db)
                self.assertIsNotNone(ev,
                    f"Evidence event_id {eid} not found in events table")


if __name__ == "__main__":
    unittest.main(verbosity=2)
