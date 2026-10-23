"""
reporting.py — NazarSOC Metrics and Reporting (Phase 3)

Responsibilities
----------------
- Detection Quality Lab: scenario-level evaluation against the real engine.
- Incident report generation from persisted database data.
- Export of incidents and metrics to JSON, CSV and self-contained HTML.

Security notes
--------------
- All untrusted values inserted into HTML are HTML-escaped.
- CSV values that start with dangerous spreadsheet formula prefixes
  (=, +, -, @) — or whitespace/control characters preceding them — are
  prefixed with a tab character to neutralise formula injection.
- No eval, exec, or external network calls.
- Environment variables and file paths are not included in report output.

Evaluation methodology
----------------------
The evaluation unit is a *scenario* — a labelled set of NormalizedEvents
paired with the set of rule IDs expected to fire.  The real
run_all_detections() function is called on each scenario; the set of
actually-fired rule IDs is compared to the expected set.

  TP: expected rule fired and was detected.
  FP: a rule fired but was not expected for that scenario.
  FN: an expected rule did not fire.
  TN: a rule did not fire and was not expected (counted per scenario over
      the universe of all three rule IDs).

Limitations
-----------
- Scenario-level evaluation cannot distinguish which specific events within
  a scenario caused a detection; it only tests whether the rule fires.
- Because this is a rule-based detector (not a trained model), precision
  and recall measure rule firing fidelity on this synthetic dataset, not
  generalised real-world performance.
- All results are labelled SYNTHETIC and must not be cited as production SOC
  metrics.
"""

from __future__ import annotations

import csv
import html
import io
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from database import get_incident, list_incidents
from engine import NormalizedEvent, run_all_detections

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALL_RULE_IDS: Tuple[str, ...] = ("RULE_A", "RULE_B", "RULE_C")

# CSV cells starting with these characters (after stripping leading
# whitespace/control characters) can trigger formula execution in spreadsheets.
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@")

MAX_REPORT_LIMIT: int = 10_000   # guard against accidentally huge exports

# ---------------------------------------------------------------------------
# CSV injection prevention
# ---------------------------------------------------------------------------

def _sanitize_csv_cell(value: str) -> str:
    """
    Neutralise spreadsheet formula injection.

    Any cell value whose first non-whitespace, non-control character is one of
    = + - @ is prefixed with a tab so that spreadsheet applications treat it as
    text rather than a formula.
    """
    stripped = value.lstrip()
    # Strip leading control characters (ord < 32)
    stripped = stripped.lstrip("".join(chr(c) for c in range(32)))
    if stripped and stripped[0] in _CSV_FORMULA_PREFIXES:
        return "\t" + value
    return value


def _row_to_csv_safe(row: Dict[str, Any]) -> Dict[str, str]:
    """Convert a dict row to safe, string-typed CSV cells."""
    return {k: _sanitize_csv_cell(str(v) if v is not None else "") for k, v in row.items()}


# ---------------------------------------------------------------------------
# Detection Quality Lab — scenario-level evaluation
# ---------------------------------------------------------------------------

@dataclass
class EvalScenario:
    """
    A labelled evaluation scenario.

    name          : human-readable label for debugging.
    events        : NormalizedEvents to feed into run_all_detections.
    expected_rules: set of rule IDs that SHOULD fire (empty = benign scenario).
    """
    name: str
    events: List[NormalizedEvent]
    expected_rules: Set[str] = field(default_factory=set)


@dataclass
class ScenarioResult:
    """Per-scenario outcome."""
    scenario_name: str
    expected_rules: Set[str]
    fired_rules: Set[str]

    @property
    def true_positives(self) -> Set[str]:
        return self.expected_rules & self.fired_rules

    @property
    def false_positives(self) -> Set[str]:
        return self.fired_rules - self.expected_rules

    @property
    def false_negatives(self) -> Set[str]:
        return self.expected_rules - self.fired_rules

    @property
    def true_negatives(self) -> Set[str]:
        """
        Rules that were neither expected nor fired, within the full rule universe.
        """
        all_rules = set(ALL_RULE_IDS)
        return all_rules - self.expected_rules - self.fired_rules


@dataclass
class EvalMetrics:
    """
    Aggregate metrics over all evaluated scenarios.

    Counts are accumulated at the (scenario × rule_id) level:
    each (scenario, rule_id) pair contributes exactly once to one of
    TP / FP / FN / TN.  This avoids double-counting.

    All metrics are labelled SYNTHETIC.
    """
    tp: int
    fp: int
    fn: int
    tn: int
    precision: Optional[float]     # None when TP+FP == 0 (undefined)
    recall: Optional[float]        # None when TP+FN == 0 (undefined)
    f1: Optional[float]            # None when precision or recall undefined
    accuracy: Optional[float]      # None when no observations
    scenario_count: int
    dataset_label: str = "SYNTHETIC — not real-world SOC performance"


def evaluate_scenarios(
    scenarios: List[EvalScenario],
    thresholds=None,
) -> Tuple[List[ScenarioResult], EvalMetrics]:
    """
    Run the real detection engine on each scenario and compute metrics.

    Returns (per-scenario results, aggregate metrics).
    """
    results: List[ScenarioResult] = []

    for scenario in scenarios:
        detections = run_all_detections(scenario.events, thresholds=thresholds)
        fired = {d.rule_id for d in detections}
        results.append(ScenarioResult(
            scenario_name=scenario.name,
            expected_rules=set(scenario.expected_rules),
            fired_rules=fired,
        ))

    # Aggregate counts across all (scenario × rule_id) pairs
    tp = sum(len(r.true_positives) for r in results)
    fp = sum(len(r.false_positives) for r in results)
    fn = sum(len(r.false_negatives) for r in results)
    tn = sum(len(r.true_negatives) for r in results)

    precision = (tp / (tp + fp)) if (tp + fp) > 0 else None
    recall    = (tp / (tp + fn)) if (tp + fn) > 0 else None
    f1        = (
        (2 * precision * recall / (precision + recall))
        if (precision is not None and recall is not None
            and (precision + recall) > 0)
        else None
    )
    total = tp + fp + fn + tn
    accuracy = (tp + tn) / total if total > 0 else None

    metrics = EvalMetrics(
        tp=tp, fp=fp, fn=fn, tn=tn,
        precision=precision, recall=recall, f1=f1, accuracy=accuracy,
        scenario_count=len(scenarios),
    )
    return results, metrics


def build_labelled_dataset() -> List[EvalScenario]:
    """
    Return a small, deterministic labelled dataset covering:
    - Benign activity (no alerts expected).
    - RULE_A (brute-force failures per account).
    - RULE_B (password spray).
    - RULE_C (failures then success).
    - A false-positive challenge: near-threshold traffic that must NOT fire.
    - A missed-detection scenario: events spaced just outside the window.

    All data is synthetic.  IPs are from RFC 5737 documentation ranges.
    """
    from datetime import timedelta

    base = datetime(2024, 6, 1, 9, 0, 0, tzinfo=timezone.utc)

    def _f(eid, t_offset_s, ip, user, etype="authentication", outcome="failure"):
        return NormalizedEvent(
            event_id=eid,
            timestamp=base + timedelta(seconds=t_offset_s),
            source_ip=ip,
            username=user,
            event_type=etype,
            outcome=outcome,
        )

    # ── Scenario 1: purely benign logins ─────────────────────────────────
    s1 = EvalScenario(
        name="benign_logins",
        events=[
            _f("B1", 0,   "192.0.2.1", "alice", outcome="success"),
            _f("B2", 60,  "192.0.2.2", "bob",   outcome="success"),
            _f("B3", 120, "192.0.2.3", "carol", outcome="success"),
        ],
        expected_rules=set(),
    )

    # ── Scenario 2: isolated failures below threshold ─────────────────────
    s2 = EvalScenario(
        name="isolated_failures_below_threshold",
        events=[_f(f"IF{i}", i * 60, "192.0.2.10", "dave") for i in range(4)],
        expected_rules=set(),
    )

    # ── Scenario 3: RULE_A — brute force (5 failures in 5 min) ───────────
    s3 = EvalScenario(
        name="rule_a_brute_force",
        events=[_f(f"RA{i}", i * 55, "198.51.100.1", "alice") for i in range(5)],
        expected_rules={"RULE_A"},
    )

    # ── Scenario 4: RULE_B — password spray (10 failures, 10 users) ──────
    s4 = EvalScenario(
        name="rule_b_password_spray",
        events=[
            _f(f"RB{i}", i * 50, "203.0.113.1", f"spray{i:02d}")
            for i in range(10)
        ],
        expected_rules={"RULE_B"},
    )

    # ── Scenario 5: RULE_C — failures then success ───────────────────────
    s5 = EvalScenario(
        name="rule_c_failures_then_success",
        events=[
            _f(f"RC{i}", i * 60, "198.51.100.2", "eve") for i in range(3)
        ] + [
            _f("RC-S", 300, "198.51.100.2", "eve", outcome="success"),
        ],
        expected_rules={"RULE_C"},
    )

    # ── Scenario 6: false-positive challenge ─────────────────────────────
    # 4 failures for one user + 5 failures for a different user from same IP.
    # Neither account reaches threshold=5 individually — RULE_A must NOT fire.
    # (Tests that grouping is correctly per (IP, username), not just per IP.)
    s6 = EvalScenario(
        name="fp_challenge_mixed_users_below_threshold",
        events=(
            [_f(f"FP-A{i}", i * 60, "192.0.2.20", "userA") for i in range(4)] +
            [_f(f"FP-B{i}", i * 60, "192.0.2.20", "userB") for i in range(4)]
        ),
        expected_rules=set(),
    )

    # ── Scenario 7: missed-detection scenario ────────────────────────────
    # 5 failures but spaced 91 seconds apart: span = 4 × 91 = 364 s > 300 s.
    # RULE_A must NOT fire.  Demonstrates a real detection gap for slow attacks.
    s7 = EvalScenario(
        name="fn_scenario_failures_outside_window",
        events=[_f(f"MD{i}", i * 91, "192.0.2.30", "frank") for i in range(5)],
        expected_rules=set(),   # engine correctly produces no detection
    )

    # ── Scenario 8: RULE_A + RULE_C together ─────────────────────────────
    s8 = EvalScenario(
        name="rule_a_and_c_combined",
        events=(
            [_f(f"AC{i}", i * 50, "198.51.100.3", "grace") for i in range(5)] +
            [_f("AC-S", 400, "198.51.100.3", "grace", outcome="success")]
        ),
        expected_rules={"RULE_A", "RULE_C"},
    )

    return [s1, s2, s3, s4, s5, s6, s7, s8]


# ---------------------------------------------------------------------------
# Incident report generation
# ---------------------------------------------------------------------------

def generate_incident_report(
    incident_id: str,
    db_path: Path,
) -> Dict[str, Any]:
    """
    Build a structured incident report dict from persisted data.

    Returns a dict with keys: incident metadata + evidence_event_ids.
    Raises ValueError if the incident_id is not found.
    """
    inc = get_incident(incident_id, db_path=db_path)
    if inc is None:
        raise ValueError(f"Incident not found: {incident_id!r}")
    return inc   # already includes evidence_event_ids and decoded usernames


def list_incident_reports(
    db_path: Path,
    limit: int = 100,
    offset: int = 0,
    status: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Return a bounded list of incident summary dicts.

    limit is validated against MAX_REPORT_LIMIT.
    """
    if limit < 1 or limit > MAX_REPORT_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_REPORT_LIMIT}, got {limit}")
    return list_incidents(limit=limit, offset=offset, status=status, db_path=db_path)


# ---------------------------------------------------------------------------
# JSON export
# ---------------------------------------------------------------------------

def _incident_to_json_row(inc: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten an incident dict to a JSON-serialisable form."""
    row = dict(inc)
    # affected_usernames is already decoded to a list by database.get_incident
    if isinstance(row.get("affected_usernames"), list):
        row["affected_usernames"] = row["affected_usernames"]
    evidence = row.pop("evidence_event_ids", [])
    row["evidence_event_ids"] = evidence
    return row


def export_incidents_json(
    db_path: Path,
    limit: int = 1000,
    status: Optional[str] = None,
) -> str:
    """
    Export incidents (with evidence IDs) as a JSON string.

    Returns an empty JSON array string if there are no incidents.
    """
    if limit < 1 or limit > MAX_REPORT_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_REPORT_LIMIT}")
    incidents = list_incidents(limit=limit, status=status, db_path=db_path)
    rows = []
    for inc in incidents:
        full = get_incident(inc["incident_id"], db_path=db_path)
        if full:
            rows.append(_incident_to_json_row(full))
    return json.dumps(rows, indent=2, default=str)


def export_metrics_json(metrics: EvalMetrics) -> str:
    """Serialise EvalMetrics to a JSON string."""
    return json.dumps({
        "dataset_label": metrics.dataset_label,
        "scenario_count": metrics.scenario_count,
        "tp": metrics.tp,
        "fp": metrics.fp,
        "fn": metrics.fn,
        "tn": metrics.tn,
        "precision": metrics.precision,
        "recall": metrics.recall,
        "f1": metrics.f1,
        "accuracy": metrics.accuracy,
    }, indent=2)


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------

#: Stable column order for incident CSV.
_INCIDENT_CSV_COLUMNS = [
    "incident_id", "rule_id", "title", "severity", "confidence",
    "source_ip", "affected_usernames", "mitre_technique",
    "first_seen", "last_seen", "status", "disposition",
    "created_at", "updated_at", "recommended_action",
]


def export_incidents_csv(
    db_path: Path,
    limit: int = 1000,
    status: Optional[str] = None,
) -> str:
    """
    Export incidents to a UTF-8 CSV string with formula-injection prevention.

    Evidence IDs are omitted from this export (use JSON for full evidence).
    Returns a header-only CSV if there are no incidents.
    """
    if limit < 1 or limit > MAX_REPORT_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_REPORT_LIMIT}")

    incidents = list_incidents(limit=limit, status=status, db_path=db_path)

    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=_INCIDENT_CSV_COLUMNS,
        extrasaction="ignore",
        lineterminator="\n",
    )
    writer.writeheader()

    for inc in incidents:
        # Flatten list fields
        row = dict(inc)
        if isinstance(row.get("affected_usernames"), list):
            row["affected_usernames"] = "; ".join(row["affected_usernames"])
        safe = _row_to_csv_safe(row)
        # Keep only the declared columns
        writer.writerow({col: safe.get(col, "") for col in _INCIDENT_CSV_COLUMNS})

    return output.getvalue()


def export_metrics_csv(metrics: EvalMetrics) -> str:
    """Serialise EvalMetrics to a two-row CSV (header + values)."""
    columns = ["dataset_label", "scenario_count", "tp", "fp", "fn", "tn",
               "precision", "recall", "f1", "accuracy"]
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=columns, lineterminator="\n")
    writer.writeheader()
    row = {
        "dataset_label": metrics.dataset_label,
        "scenario_count": metrics.scenario_count,
        "tp": metrics.tp, "fp": metrics.fp, "fn": metrics.fn, "tn": metrics.tn,
        "precision": "" if metrics.precision is None else f"{metrics.precision:.4f}",
        "recall":    "" if metrics.recall is None    else f"{metrics.recall:.4f}",
        "f1":        "" if metrics.f1 is None        else f"{metrics.f1:.4f}",
        "accuracy":  "" if metrics.accuracy is None  else f"{metrics.accuracy:.4f}",
    }
    writer.writerow({col: _sanitize_csv_cell(str(row[col])) for col in columns})
    return output.getvalue()


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

def _h(value: Any) -> str:
    """HTML-escape a value for safe insertion into HTML. None maps to empty string."""
    if value is None:
        return ""
    return html.escape(str(value))


def _metrics_html(metrics: EvalMetrics) -> str:
    """Render EvalMetrics as an HTML section."""
    def _fmt(v):
        return f"{v:.4f}" if v is not None else "<em>undefined</em>"

    return f"""
<section>
  <h2>Detection Quality Lab</h2>
  <p class="label">{_h(metrics.dataset_label)}</p>
  <p>Scenarios evaluated: <strong>{_h(metrics.scenario_count)}</strong></p>
  <table>
    <tr><th>Metric</th><th>Value</th></tr>
    <tr><td>True Positives (TP)</td><td>{_h(metrics.tp)}</td></tr>
    <tr><td>False Positives (FP)</td><td>{_h(metrics.fp)}</td></tr>
    <tr><td>False Negatives (FN)</td><td>{_h(metrics.fn)}</td></tr>
    <tr><td>True Negatives (TN)</td><td>{_h(metrics.tn)}</td></tr>
    <tr><td>Precision</td><td>{_fmt(metrics.precision)}</td></tr>
    <tr><td>Recall</td><td>{_fmt(metrics.recall)}</td></tr>
    <tr><td>F1 Score</td><td>{_fmt(metrics.f1)}</td></tr>
    <tr><td>Accuracy</td><td>{_fmt(metrics.accuracy)}</td></tr>
  </table>
</section>
"""


def generate_html_report(
    db_path: Path,
    metrics: Optional[EvalMetrics] = None,
    limit: int = 200,
    status: Optional[str] = None,
) -> str:
    """
    Generate a self-contained, UTF-8 HTML report.

    All untrusted field values are HTML-escaped.
    No external resources are referenced.

    Parameters
    ----------
    db_path : path to the SQLite database.
    metrics : optional EvalMetrics to include a quality-lab section.
    limit   : maximum number of incidents to include.
    status  : optional status filter passed to list_incidents.
    """
    if limit < 1 or limit > MAX_REPORT_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_REPORT_LIMIT}")

    incidents = list_incidents(limit=limit, status=status, db_path=db_path)
    generated_at = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    rows_html = ""
    for inc in incidents:
        users = _h("; ".join(inc["affected_usernames"])
                   if isinstance(inc["affected_usernames"], list)
                   else inc["affected_usernames"])
        rows_html += f"""
    <tr>
      <td>{_h(inc['incident_id'])}</td>
      <td>{_h(inc['rule_id'])}</td>
      <td>{_h(inc['title'])}</td>
      <td>{_h(inc['severity'])}</td>
      <td>{_h(inc['confidence'])}</td>
      <td>{_h(inc['source_ip'])}</td>
      <td>{users}</td>
      <td>{_h(inc['status'])}</td>
      <td>{_h(inc['disposition'])}</td>
      <td>{_h(inc['first_seen'])}</td>
      <td>{_h(inc['last_seen'])}</td>
    </tr>"""

    metrics_section = _metrics_html(metrics) if metrics else ""
    no_data_msg = "<p>No incidents found.</p>" if not incidents else ""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NazarSOC Incident Report</title>
<style>
  body {{ font-family: -apple-system, "Segoe UI", sans-serif; margin: 2em; color: #1f2328; }}
  h1 {{ border-bottom: 2px solid #e5e7eb; padding-bottom: .4em; }}
  h2 {{ margin-top: 2em; }}
  table {{ border-collapse: collapse; width: 100%; font-size: .9em; }}
  th, td {{ border: 1px solid #e5e7eb; padding: .4em .6em; text-align: left; }}
  th {{ background: #f7f8fa; }}
  .label {{ color: #57606a; font-style: italic; }}
  footer {{ margin-top: 3em; color: #57606a; font-size: .8em; border-top: 1px solid #e5e7eb; padding-top: .5em; }}
</style>
</head>
<body>
<h1>NazarSOC — Incident Report</h1>
<p class="label">Generated: {_h(generated_at)} UTC | All data is synthetic.</p>
{metrics_section}
<section>
  <h2>Incidents ({_h(len(incidents))} shown)</h2>
  {no_data_msg}
  {'<table><thead><tr>' if incidents else ''}
  {''.join(f'<th>{_h(c)}</th>' for c in ['ID','Rule','Title','Sev','Conf','Source IP','Users','Status','Disposition','First Seen','Last Seen']) if incidents else ''}
  {'</tr></thead><tbody>' if incidents else ''}
  {rows_html}
  {'</tbody></table>' if incidents else ''}
</section>
<footer>Made with NazarSOC &mdash; synthetic data only, not production-certified.</footer>
</body>
</html>"""
