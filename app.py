"""
app.py — NazarSOC Streamlit Dashboard (Phase 4)

Local-only application. No user authentication.
Data is stored in the local SQLite database at database.DEFAULT_DB_PATH.
Bind to 127.0.0.1 only (see run.bat or: streamlit run app.py --server.address 127.0.0.1).

Navigation:
    Overview | Events & Import | Incidents | Detection Quality Lab | Reports
"""

from __future__ import annotations

import io
import json
import sqlite3
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import streamlit as st

import database as db
import engine as eng
import reporting as rep
from database import (
    DEFAULT_DB_PATH,
    INCIDENT_DISPOSITIONS,
    INCIDENT_STATUSES,
    MAX_ANALYST_NOTE_LEN,
    MAX_IMPORT_BYTES,
    MAX_IMPORT_RECORDS,
    _get_connection,
    load_all_events_for_detection,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PAGE_SIZE = 25          # incidents per page
PREVIEW_ROWS = 10       # max rows shown in upload preview
DEMO_FILE = Path("demo_events.json")

_SEVERITY_COLOURS = {
    "Critical": "🔴",
    "High":     "🟠",
    "Medium":   "🟡",
    "Low":      "🟢",
}

# ---------------------------------------------------------------------------
# Helpers (pure — testable without Streamlit)
# ---------------------------------------------------------------------------

def _fmt_metric(value: Optional[float], decimals: int = 4) -> str:
    """Format a float metric; return 'Undefined' for None."""
    if value is None:
        return "Undefined"
    return f"{value:.{decimals}f}"


def _safe_display_size(n_bytes: int) -> str:
    """Human-readable file size string."""
    if n_bytes < 1024:
        return f"{n_bytes} B"
    if n_bytes < 1024 ** 2:
        return f"{n_bytes / 1024:.1f} KB"
    return f"{n_bytes / 1024**2:.1f} MB"


def _now_tag() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")


# ---------------------------------------------------------------------------
# App initialisation
# ---------------------------------------------------------------------------

def _init_app() -> None:
    """
    Called once per session via st.session_state guard.
    Initialises the database and runs a best-effort WAL checkpoint.
    """
    if st.session_state.get("_app_initialised"):
        return
    try:
        db.init_db(DEFAULT_DB_PATH)
        # Best-effort WAL checkpoint — reduces WAL file growth for long sessions.
        # This is not guaranteed to reclaim all WAL space; see Phase 4 limitations.
        conn = _get_connection(DEFAULT_DB_PATH)
        try:
            conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
            conn.commit()
        finally:
            conn.close()
    except Exception as exc:
        st.error(f"Database initialisation failed: {exc}")
    st.session_state["_app_initialised"] = True


# ---------------------------------------------------------------------------
# Sidebar navigation
# ---------------------------------------------------------------------------

def _sidebar() -> str:
    with st.sidebar:
        st.title("🛡 NazarSOC")
        st.caption("Local-only · No authentication · Synthetic data only")
        page = st.radio(
            "Navigate",
            ["Overview", "Events & Import", "Incidents",
             "Detection Quality Lab", "Reports"],
            key="nav_page",
        )
        st.divider()
        st.caption(
            "**Privacy notice:** All data is stored locally in "
            f"`{DEFAULT_DB_PATH}`. "
            "There is no account-based access control. "
            "Do not process real personal data on this system."
        )
    return page


# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------

def page_overview() -> None:
    st.header("Overview")

    # ── Summary counts ──────────────────────────────────────────────────────
    try:
        total_events = db.get_events(limit=1, offset=0, db_path=DEFAULT_DB_PATH)
        # Count all events via a direct query for accuracy
        conn = _get_connection(DEFAULT_DB_PATH)
        try:
            event_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            inc_by_status = {s: conn.execute(
                "SELECT COUNT(*) FROM incidents WHERE status=?", (s,)
            ).fetchone()[0] for s in INCIDENT_STATUSES}
            inc_by_sev = conn.execute(
                "SELECT severity, COUNT(*) FROM incidents GROUP BY severity"
            ).fetchall()
            inc_by_sev = {row[0]: row[1] for row in inc_by_sev}
        finally:
            conn.close()
    except Exception as exc:
        st.error(f"Could not load overview data: {exc}")
        return

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Events", event_count)
    c2.metric("New Incidents",         inc_by_status.get("New", 0))
    c3.metric("Investigating",         inc_by_status.get("Investigating", 0))
    c4.metric("Resolved",              inc_by_status.get("Resolved", 0))

    if inc_by_sev:
        st.subheader("Incidents by Severity")
        sev_cols = st.columns(len(inc_by_sev))
        for col, (sev, cnt) in zip(sev_cols, sorted(inc_by_sev.items())):
            icon = _SEVERITY_COLOURS.get(sev, "⚪")
            col.metric(f"{icon} {sev}", cnt)

    # ── Recent incidents ────────────────────────────────────────────────────
    st.subheader("Recent Incidents")
    recent = db.list_incidents(limit=10, db_path=DEFAULT_DB_PATH)
    if not recent:
        st.info("No incidents yet. Import events and run detection to get started.")
    else:
        for inc in recent:
            icon = _SEVERITY_COLOURS.get(inc["severity"], "⚪")
            st.write(
                f"{icon} **{inc['title']}** — "
                f"`{inc['rule_id']}` · {inc['status']} · {inc['first_seen']}"
            )

    # ── Detection rules reference ───────────────────────────────────────────
    with st.expander("Detection Rules Reference"):
        st.markdown("""
**Rule A — Repeated Authentication Failures (Brute Force)**
≥ 5 failures for the same source IP and username within 5 minutes.
MITRE: T1110.001

**Rule B — Password Spraying**
≥ 10 failures from the same source IP targeting ≥ 5 distinct usernames within 10 minutes.
MITRE: T1110.003

**Rule C — Failures Followed by Successful Login**
≥ 3 failures for the same source IP and username followed by a success within 10 minutes.
MITRE: T1110.001
""")

    # ── Synthetic evaluation summary ────────────────────────────────────────
    st.subheader("Detection Quality (Synthetic Dataset)")
    st.caption(
        "⚠️ These metrics are measured on a small synthetic dataset. "
        "They do not represent real-world detection accuracy."
    )
    try:
        scenarios = rep.build_labelled_dataset()
        _, metrics = rep.evaluate_scenarios(scenarios)
        mc1, mc2, mc3, mc4 = st.columns(4)
        mc1.metric("Precision",  _fmt_metric(metrics.precision))
        mc2.metric("Recall",     _fmt_metric(metrics.recall))
        mc3.metric("F1 Score",   _fmt_metric(metrics.f1))
        mc4.metric("Accuracy",   _fmt_metric(metrics.accuracy))
    except Exception as exc:
        st.warning(f"Could not compute evaluation metrics: {exc}")


# ---------------------------------------------------------------------------
# Events & Import
# ---------------------------------------------------------------------------

def page_events() -> None:
    st.header("Events & Import")

    # ── Import demo data ────────────────────────────────────────────────────
    st.subheader("Load Demo Dataset")
    st.caption("Imports the synthetic `demo_events.json` bundled with the project.")
    if st.button("Import Demo Data", key="btn_demo"):
        _import_demo_data()

    st.divider()

    # ── File upload ─────────────────────────────────────────────────────────
    st.subheader("Upload Events File")
    st.caption(
        f"Accepted formats: JSON (list of event objects) or CSV. "
        f"Max size: {_safe_display_size(MAX_IMPORT_BYTES)}. "
        f"Max records: {MAX_IMPORT_RECORDS:,}."
    )
    uploaded = st.file_uploader(
        "Choose a JSON or CSV file",
        type=["json", "csv"],
        key="event_uploader",
    )
    if uploaded is not None:
        _handle_upload(uploaded)

    st.divider()

    # ── Run detection on all stored events ──────────────────────────────────
    st.subheader("Run Detection")
    st.caption(
        "Runs all three detection rules against every event currently stored "
        "in the database. Use this after any import, or to re-run detection "
        "without re-uploading data."
    )
    if st.button("▶ Run Detection on All Stored Events", key="btn_run_detection"):
        try:
            all_events = load_all_events_for_detection(db_path=DEFAULT_DB_PATH)
            if not all_events:
                st.warning("No events in the database. Import data first.")
            else:
                _run_detection_on_events(all_events)
        except Exception as exc:
            st.error(f"Detection failed: {exc}")

    st.divider()

    # ── Stored events preview ───────────────────────────────────────────────
    st.subheader("Stored Events")
    with st.form("event_filter_form"):
        col1, col2 = st.columns(2)
        ip_filter = col1.text_input("Filter by source IP", key="ev_ip")
        user_filter = col2.text_input("Filter by username", key="ev_user")
        submitted = st.form_submit_button("Apply")

    offset = st.session_state.get("ev_offset", 0)
    rows = db.get_events(
        limit=PAGE_SIZE,
        offset=offset,
        source_ip=ip_filter.strip() or None,
        username=user_filter.strip() or None,
        db_path=DEFAULT_DB_PATH,
    )

    if not rows:
        st.info("No events found. Import a file above.")
    else:
        display_cols = ["event_id", "timestamp", "source_ip", "username",
                        "event_type", "outcome", "hostname"]
        st.dataframe(
            [{k: r.get(k) for k in display_cols} for r in rows],
            use_container_width=True,
        )
        _pagination_buttons("ev_offset", len(rows))


def _import_demo_data() -> None:
    if not DEMO_FILE.exists():
        st.error(f"`{DEMO_FILE}` not found in the working directory.")
        return
    try:
        raw_list = json.loads(DEMO_FILE.read_text(encoding="utf-8"))
        data = [r for r in raw_list if "event_id" in r]
        events, errors = eng.parse_json_events(data)
        batch_id = f"demo-{_now_tag()}"
        db.create_import_batch(batch_id, "demo_events.json", db_path=DEFAULT_DB_PATH)
        counts = db.save_events_batch(events, batch_id=batch_id, db_path=DEFAULT_DB_PATH)
        db.update_import_batch(
            batch_id,
            total=len(data),
            accepted=counts["accepted"],
            rejected=len(errors),
            duplicates=counts["duplicate"],
            conflicts=counts["conflict"],
            db_path=DEFAULT_DB_PATH,
        )
        st.success(
            f"Demo data imported — accepted: {counts['accepted']}, "
            f"duplicates: {counts['duplicate']}, "
            f"rejected: {len(errors)}"
        )
        # Run detection against all stored events so incidents are created
        # even when the import reports all-duplicates on a second run.
        all_events = load_all_events_for_detection(db_path=DEFAULT_DB_PATH)
        _run_detection_on_events(all_events)
    except Exception as exc:
        st.error(f"Failed to import demo data: {exc}")


def _handle_upload(uploaded) -> None:
    raw_bytes = uploaded.read()

    # ── Size check ──────────────────────────────────────────────────────────
    if len(raw_bytes) > MAX_IMPORT_BYTES:
        st.error(
            f"File too large: {_safe_display_size(len(raw_bytes))}. "
            f"Maximum is {_safe_display_size(MAX_IMPORT_BYTES)}."
        )
        return

    # ── Decode ──────────────────────────────────────────────────────────────
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        st.error("File is not valid UTF-8. Only UTF-8 encoded files are accepted.")
        return

    # ── Parse ───────────────────────────────────────────────────────────────
    fname = uploaded.name.lower()
    if fname.endswith(".json"):
        events, errors = eng.parse_json_events(text)
    elif fname.endswith(".csv"):
        events, errors = eng.parse_csv_events(text)
    else:
        st.error("Unsupported file type. Upload a .json or .csv file.")
        return

    # ── Record count check ─────────────────────────────────────────────────
    if len(events) + len(errors) > MAX_IMPORT_RECORDS:
        st.error(
            f"File contains too many records "
            f"({len(events) + len(errors):,} > {MAX_IMPORT_RECORDS:,} limit)."
        )
        return

    # ── Preview ─────────────────────────────────────────────────────────────
    st.write(f"**Parsed:** {len(events)} valid, {len(errors)} rejected")
    if events:
        with st.expander(f"Preview (first {min(PREVIEW_ROWS, len(events))} records)"):
            preview_data = [
                {k: getattr(e, k, None)
                 for k in ["event_id", "timestamp", "source_ip",
                            "username", "event_type", "outcome"]}
                for e in events[:PREVIEW_ROWS]
            ]
            st.dataframe(preview_data, use_container_width=True)

    if errors:
        with st.expander(f"Validation errors ({len(errors)})"):
            for err in errors[:20]:
                st.caption(f"❌ {err.reason}")

    if not events:
        st.warning("No valid events to import.")
        return

    # ── Persist ─────────────────────────────────────────────────────────────
    if st.button("Confirm Import", key="btn_confirm_import"):
        try:
            batch_id = f"upload-{_now_tag()}-{uuid.uuid4().hex[:8]}"
            # Use a safe display name — never trust the uploaded filename directly
            safe_name = f"upload_{_now_tag()}.{fname.rsplit('.', 1)[-1]}"
            db.create_import_batch(batch_id, safe_name, db_path=DEFAULT_DB_PATH)
            counts = db.save_events_batch(
                events, batch_id=batch_id, db_path=DEFAULT_DB_PATH
            )
            db.update_import_batch(
                batch_id,
                total=len(events) + len(errors),
                accepted=counts["accepted"],
                rejected=len(errors),
                duplicates=counts["duplicate"],
                conflicts=counts["conflict"],
                db_path=DEFAULT_DB_PATH,
            )
            st.success(
                f"Saved — accepted: **{counts['accepted']}**, "
                f"duplicates: {counts['duplicate']}, "
                f"conflicts: {counts['conflict']}, "
                f"rejected: {len(errors)}"
            )
            _run_detection_on_events(events)
        except Exception as exc:
            st.error(f"Import failed: {exc}")


def _run_detection_on_events(events: list) -> None:
    """Run detection on a list of NormalizedEvents and report results."""
    try:
        result = db.run_detection_pipeline(events, db_path=DEFAULT_DB_PATH)
        st.info(
            f"Detection complete — "
            f"new incidents: **{result['new_incidents']}**, "
            f"updated: {result['updated_incidents']}, "
            f"total detections: {result['total_detections']}"
        )
    except Exception as exc:
        st.warning(f"Detection pipeline error: {exc}")


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------

def page_incidents() -> None:
    st.header("Incidents")

    # ── Filters ─────────────────────────────────────────────────────────────
    with st.form("incident_filter_form"):
        fc1, fc2, fc3 = st.columns(3)
        status_filter = fc1.selectbox(
            "Status", ["All"] + list(INCIDENT_STATUSES), key="inc_status_filter"
        )
        sev_filter = fc2.selectbox(
            "Severity", ["All", "Critical", "High", "Medium", "Low"],
            key="inc_sev_filter"
        )
        rule_filter = fc3.selectbox(
            "Rule", ["All", "RULE_A", "RULE_B", "RULE_C"],
            key="inc_rule_filter"
        )
        ip_filter = st.text_input("Source IP contains", key="inc_ip_filter")
        st.form_submit_button("Apply Filters")

    # ── Fetch ────────────────────────────────────────────────────────────────
    offset = st.session_state.get("inc_offset", 0)
    status_arg = None if status_filter == "All" else status_filter
    all_incs = db.list_incidents(
        limit=PAGE_SIZE * 4,   # fetch a wider slice for client-side secondary filters
        offset=offset,
        status=status_arg,
        db_path=DEFAULT_DB_PATH,
    )

    # Apply secondary filters (severity, rule, IP) client-side
    if sev_filter != "All":
        all_incs = [i for i in all_incs if i["severity"] == sev_filter]
    if rule_filter != "All":
        all_incs = [i for i in all_incs if i["rule_id"] == rule_filter]
    if ip_filter.strip():
        all_incs = [i for i in all_incs if ip_filter.strip() in i["source_ip"]]

    incidents = all_incs[:PAGE_SIZE]

    if not incidents:
        st.info("No incidents match the current filters.")
        _pagination_buttons("inc_offset", 0)
        return

    # ── Table ────────────────────────────────────────────────────────────────
    table_data = []
    for inc in incidents:
        icon = _SEVERITY_COLOURS.get(inc["severity"], "⚪")
        table_data.append({
            "ID":          inc["incident_id"],
            "Rule":        inc["rule_id"],
            "Severity":    f"{icon} {inc['severity']}",
            "Confidence":  inc["confidence"],
            "Source IP":   inc["source_ip"],
            "Status":      inc["status"],
            "Disposition": inc["disposition"],
            "First Seen":  inc["first_seen"],
        })
    st.dataframe(table_data, use_container_width=True, hide_index=True)
    _pagination_buttons("inc_offset", len(incidents))

    # ── Detail view ──────────────────────────────────────────────────────────
    st.divider()
    st.subheader("Incident Detail")
    inc_ids = [i["incident_id"] for i in incidents]
    selected_id = st.selectbox("Select incident", inc_ids, key="inc_selected")
    if selected_id:
        _render_incident_detail(selected_id)


def _render_incident_detail(incident_id: str) -> None:
    inc = db.get_incident(incident_id, db_path=DEFAULT_DB_PATH)
    if not inc:
        st.error("Incident not found.")
        return

    icon = _SEVERITY_COLOURS.get(inc["severity"], "⚪")
    st.markdown(f"### {icon} {inc['title']}")
    st.write(inc["explanation"])

    d1, d2, d3, d4 = st.columns(4)
    d1.metric("Severity",    inc["severity"])
    d2.metric("Confidence",  inc["confidence"])
    d3.metric("Status",      inc["status"])
    d4.metric("Disposition", inc["disposition"])

    col_l, col_r = st.columns(2)
    col_l.write(f"**Rule:** `{inc['rule_id']}`")
    col_l.write(f"**Source IP:** `{inc['source_ip']}`")
    col_l.write(f"**Affected users:** {', '.join(inc['affected_usernames'])}")
    col_r.write(f"**First seen:** {inc['first_seen']}")
    col_r.write(f"**Last seen:** {inc['last_seen']}")
    if inc.get("mitre_technique"):
        col_r.write(f"**MITRE:** `{inc['mitre_technique']}`")

    with st.expander("Recommended Action"):
        st.write(inc.get("recommended_action") or "—")

    with st.expander(f"Evidence ({len(inc['evidence_event_ids'])} events)"):
        if inc["evidence_event_ids"]:
            for eid in inc["evidence_event_ids"]:
                ev = db.get_event(eid, db_path=DEFAULT_DB_PATH)
                if ev:
                    st.code(
                        f"{ev['timestamp']}  {ev['source_ip']}  "
                        f"{ev['username']}  {ev['event_type']}  {ev['outcome']}",
                        language=None,
                    )
                else:
                    st.caption(f"Event `{eid}` not found in database.")
        else:
            st.caption("No evidence linked.")

    with st.expander("Analyst Notes"):
        if inc.get("analyst_notes"):
            # Display as plain text — never render as HTML
            st.text(inc["analyst_notes"])
        else:
            st.caption("No notes yet.")

    # ── Update status / disposition ─────────────────────────────────────────
    st.divider()
    st.subheader("Update Incident")

    with st.form(f"update_form_{incident_id}"):
        ua, ub = st.columns(2)
        new_status = ua.selectbox(
            "Status", INCIDENT_STATUSES,
            index=list(INCIDENT_STATUSES).index(inc["status"]),
            key=f"sel_status_{incident_id}",
        )
        new_disposition = ub.selectbox(
            "Disposition", INCIDENT_DISPOSITIONS,
            index=list(INCIDENT_DISPOSITIONS).index(inc["disposition"]),
            key=f"sel_disp_{incident_id}",
        )
        note = st.text_area(
            f"Add analyst note (max {MAX_ANALYST_NOTE_LEN} chars)",
            key=f"note_{incident_id}",
            max_chars=MAX_ANALYST_NOTE_LEN,
        )
        save_clicked = st.form_submit_button("Save")

    if save_clicked:
        try:
            if new_status != inc["status"]:
                db.update_incident_status(incident_id, new_status, db_path=DEFAULT_DB_PATH)
            if new_disposition != inc["disposition"]:
                db.update_incident_disposition(incident_id, new_disposition, db_path=DEFAULT_DB_PATH)
            if note.strip():
                db.add_analyst_note(incident_id, note.strip(), db_path=DEFAULT_DB_PATH)
            st.success("Incident updated successfully.")
            st.rerun()
        except ValueError as exc:
            st.error(f"Validation error: {exc}")
        except Exception as exc:
            st.error(f"Update failed: {exc}")


# ---------------------------------------------------------------------------
# Detection Quality Lab
# ---------------------------------------------------------------------------

def page_quality_lab() -> None:
    st.header("Detection Quality Lab")
    st.caption(
        "⚠️ **Synthetic data only.** Results are computed on a small labelled "
        "dataset bundled with the project. They do not represent real-world "
        "detection accuracy and must not be cited as production SOC metrics."
    )

    try:
        scenarios = rep.build_labelled_dataset()
        results, metrics = rep.evaluate_scenarios(scenarios)
    except Exception as exc:
        st.error(f"Evaluation failed: {exc}")
        return

    # ── Aggregate metrics ────────────────────────────────────────────────────
    st.subheader("Aggregate Metrics")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("TP", metrics.tp)
    c2.metric("FP", metrics.fp)
    c3.metric("FN", metrics.fn)
    c4.metric("TN", metrics.tn)

    c5, c6, c7, c8 = st.columns(4)
    c5.metric("Precision",  _fmt_metric(metrics.precision))
    c6.metric("Recall",     _fmt_metric(metrics.recall))
    c7.metric("F1 Score",   _fmt_metric(metrics.f1))
    c8.metric("Accuracy",   _fmt_metric(metrics.accuracy))

    st.caption(f"Scenarios evaluated: {metrics.scenario_count} | {metrics.dataset_label}")

    # ── Per-scenario results ─────────────────────────────────────────────────
    st.subheader("Scenario Results")
    table = []
    for r in results:
        tp_set = r.true_positives
        fp_set = r.false_positives
        fn_set = r.false_negatives
        outcome = "✅ Pass" if not fp_set and not fn_set else "⚠️ Mismatch"
        table.append({
            "Scenario":       r.scenario_name,
            "Expected":       ", ".join(sorted(r.expected_rules)) or "—",
            "Fired":          ", ".join(sorted(r.fired_rules)) or "—",
            "TP":             ", ".join(sorted(tp_set)) or "—",
            "FP":             ", ".join(sorted(fp_set)) or "—",
            "FN":             ", ".join(sorted(fn_set)) or "—",
            "Outcome":        outcome,
        })
    st.dataframe(table, use_container_width=True, hide_index=True)


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

def page_reports() -> None:
    st.header("Reports")
    st.caption(
        "Exports use existing API functions. HTML escaping and "
        "CSV formula sanitization are always applied."
    )

    limit = st.slider(
        "Max incidents to include", min_value=10, max_value=1000,
        value=100, step=10, key="report_limit"
    )

    # ── Incident exports ─────────────────────────────────────────────────────
    st.subheader("Incident Exports")
    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button("Generate JSON export", key="btn_json"):
            try:
                payload = rep.export_incidents_json(db_path=DEFAULT_DB_PATH, limit=limit)
                st.download_button(
                    "⬇ Download incidents.json",
                    data=payload.encode("utf-8"),
                    file_name=f"nazarsoc_incidents_{_now_tag()}.json",
                    mime="application/json",
                    key="dl_json",
                )
            except Exception as exc:
                st.error(f"JSON export failed: {exc}")

    with col2:
        if st.button("Generate CSV export", key="btn_csv"):
            try:
                payload = rep.export_incidents_csv(db_path=DEFAULT_DB_PATH, limit=limit)
                st.download_button(
                    "⬇ Download incidents.csv",
                    data=payload.encode("utf-8"),
                    file_name=f"nazarsoc_incidents_{_now_tag()}.csv",
                    mime="text/csv",
                    key="dl_csv",
                )
            except Exception as exc:
                st.error(f"CSV export failed: {exc}")

    with col3:
        if st.button("Generate HTML report", key="btn_html"):
            try:
                _, metrics = rep.evaluate_scenarios(rep.build_labelled_dataset())
                payload = rep.generate_html_report(
                    db_path=DEFAULT_DB_PATH, metrics=metrics, limit=limit
                )
                st.download_button(
                    "⬇ Download report.html",
                    data=payload.encode("utf-8"),
                    file_name=f"nazarsoc_report_{_now_tag()}.html",
                    mime="text/html",
                    key="dl_html",
                )
            except Exception as exc:
                st.error(f"HTML export failed: {exc}")

    # ── Metrics export ───────────────────────────────────────────────────────
    st.divider()
    st.subheader("Detection Quality Metrics Export")
    st.caption("Always reflects the synthetic labelled dataset.")
    if st.button("Export metrics JSON", key="btn_metrics_json"):
        try:
            _, metrics = rep.evaluate_scenarios(rep.build_labelled_dataset())
            payload = rep.export_metrics_json(metrics)
            st.download_button(
                "⬇ Download metrics.json",
                data=payload.encode("utf-8"),
                file_name=f"nazarsoc_metrics_{_now_tag()}.json",
                mime="application/json",
                key="dl_metrics_json",
            )
        except Exception as exc:
            st.error(f"Metrics export failed: {exc}")

    if st.button("Export metrics CSV", key="btn_metrics_csv"):
        try:
            _, metrics = rep.evaluate_scenarios(rep.build_labelled_dataset())
            payload = rep.export_metrics_csv(metrics)
            st.download_button(
                "⬇ Download metrics.csv",
                data=payload.encode("utf-8"),
                file_name=f"nazarsoc_metrics_{_now_tag()}.csv",
                mime="text/csv",
                key="dl_metrics_csv",
            )
        except Exception as exc:
            st.error(f"Metrics CSV export failed: {exc}")


# ---------------------------------------------------------------------------
# Pagination helper
# ---------------------------------------------------------------------------

def _pagination_buttons(offset_key: str, n_shown: int) -> None:
    """Render Previous / Next buttons for a given offset state key."""
    offset = st.session_state.get(offset_key, 0)
    c1, c2, _ = st.columns([1, 1, 8])
    if c1.button("◀ Prev", key=f"prev_{offset_key}", disabled=(offset == 0)):
        st.session_state[offset_key] = max(0, offset - PAGE_SIZE)
        st.rerun()
    if c2.button("Next ▶", key=f"next_{offset_key}", disabled=(n_shown < PAGE_SIZE)):
        st.session_state[offset_key] = offset + PAGE_SIZE
        st.rerun()


# ---------------------------------------------------------------------------
# Entry point — guarded so app.py can be imported safely in tests
# ---------------------------------------------------------------------------

if __name__ == "__main__" or "streamlit" in __import__("sys").modules.get("__main__", type("", (), {"__spec__": None})).__spec__.name if hasattr(__import__("sys").modules.get("__main__", type("", (), {"__spec__": None})), "__spec__") and __import__("sys").modules.get("__main__", type("", (), {"__spec__": None})).__spec__ else False:
    pass  # handled below

# Detect whether we are running under Streamlit (not imported by a test runner).
import sys as _sys

def _is_streamlit_runtime() -> bool:
    """Return True only when executed by the Streamlit runner."""
    try:
        from streamlit.runtime.scriptrunner import get_script_run_ctx
        return get_script_run_ctx() is not None
    except Exception:
        return False


if _is_streamlit_runtime():
    st.set_page_config(
        page_title="NazarSOC",
        page_icon="🛡",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    _init_app()
    _page = _sidebar()

    if _page == "Overview":
        page_overview()
    elif _page == "Events & Import":
        page_events()
    elif _page == "Incidents":
        page_incidents()
    elif _page == "Detection Quality Lab":
        page_quality_lab()
    elif _page == "Reports":
        page_reports()
