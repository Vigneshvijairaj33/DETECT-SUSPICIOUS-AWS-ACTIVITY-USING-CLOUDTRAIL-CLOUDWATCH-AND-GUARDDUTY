"""
app.py — AWS Security Monitoring Dashboard
==========================================
Phase 9 — Local Streamlit dashboard.

Displays processed security events and findings from the pipeline.
Uses synthetic / exported data — never connects directly to AWS.

RUN:
    streamlit run dashboard/app.py
    streamlit run dashboard/app.py --server.port 8501

REQUIREMENTS:
    pip install streamlit plotly pandas
"""

import json
import sys
import logging
from pathlib import Path
from datetime import datetime

# ── Streamlit guard ─────────────────────────────────────────────────────── #
try:
    import streamlit as st
    import pandas as pd
    import plotly.express as px
    DEPS_OK = True
except ImportError as e:
    DEPS_OK = False
    _missing = str(e)

if not DEPS_OK:
    print(f"Missing dependency: {_missing}")
    print("Install with: pip install streamlit plotly pandas")
    sys.exit(1)

# ── Path setup ────────────────────────────────────────────────────────────── #
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────── #
# Data loading helpers
# ─────────────────────────────────────────────────────────────────────────── #

@st.cache_data(ttl=30)
def load_report() -> dict | None:
    """Load the latest security report from output/security_report.json."""
    report_path = ROOT / "output" / "security_report.json"
    if report_path.exists():
        with open(report_path) as f:
            return json.load(f)
    return None


@st.cache_data(ttl=30)
def load_events_csv() -> pd.DataFrame | None:
    """Load processed events from output/processed_events.csv."""
    csv_path = ROOT / "output" / "processed_events.csv"
    if csv_path.exists():
        df = pd.read_csv(csv_path)
        if "eventTime" in df.columns:
            df["eventTime"] = pd.to_datetime(df["eventTime"], utc=True, errors="coerce")
        return df
    return None


def load_sample_as_dataframe() -> pd.DataFrame:
    """Fallback: load synthetic sample events as a DataFrame."""
    from src.collect_events   import load_sample_events
    from src.parse_events     import parse_events
    from src.normalize_events import normalize_events

    raw  = load_sample_events()
    norm = normalize_events(parse_events(raw))

    rows = []
    for e in norm:
        rows.append({
            "eventTime":     e.get("eventTime", ""),
            "eventName":     e.get("eventName", ""),
            "eventSource":   e.get("eventSource", ""),
            "userName":      e.get("userName", ""),
            "sourceIPAddress": e.get("sourceIPAddress", ""),
            "errorCode":     e.get("errorCode", ""),
            "severity":      e.get("severity", "info"),
            "isSuspicious":  e.get("isSuspicious", False),
            "isOffHours":    e.get("isOffHours", False),
        })
    df = pd.DataFrame(rows)
    if not df.empty:
        df["eventTime"] = pd.to_datetime(df["eventTime"], utc=True, errors="coerce")
    return df


# ─────────────────────────────────────────────────────────────────────────── #
# Page layout
# ─────────────────────────────────────────────────────────────────────────── #

def render_header() -> None:
    st.set_page_config(
        page_title="AWS Security Dashboard",
        page_icon="🔒",
        layout="wide",
    )
    st.title("🔒 AWS Suspicious Activity Detector")
    st.caption(
        "Local security dashboard — displays processed pipeline output. "
        "Does not connect to AWS directly."
    )


def render_metrics(report: dict | None, df: pd.DataFrame) -> None:
    st.subheader("📊 Event Summary")
    col1, col2, col3, col4, col5 = st.columns(5)

    if report:
        s = report.get("summary", {})
        col1.metric("Total Events",      s.get("totalEvents", len(df)))
        col2.metric("Failed API Calls",  s.get("failedApiCalls", 0))
        col3.metric("Root Activity",     s.get("rootActivityCount", 0))
        col4.metric("Off-Hours Events",  s.get("offHoursEvents", 0))
        col5.metric("Total Findings",    s.get("totalFindings", 0))
    else:
        col1.metric("Total Events",     len(df))
        col2.metric("Failed API Calls", int(df.get("isFailed", pd.Series([False])).sum()) if "isFailed" in df else "—")
        col3.metric("Root Activity",    int(df["isRootActivity"].sum()) if "isRootActivity" in df else "—")
        col4.metric("Off-Hours Events", int(df["isOffHours"].sum()) if "isOffHours" in df else "—")
        col5.metric("Suspicious Events", int(df["isSuspicious"].sum()) if "isSuspicious" in df else "—")


def render_event_charts(df: pd.DataFrame) -> None:
    st.subheader("📈 Event Analysis")
    col_a, col_b = st.columns(2)

    with col_a:
        st.markdown("**Top Event Names**")
        if "eventName" in df.columns:
            top = df["eventName"].value_counts().head(10).reset_index()
            top.columns = ["Event", "Count"]
            fig = px.bar(top, x="Count", y="Event", orientation="h",
                         color_discrete_sequence=["#1f77b4"])
            fig.update_layout(height=350, margin=dict(l=10, r=10, t=10, b=10))
            st.plotly_chart(fig, use_container_width=True)

    with col_b:
        st.markdown("**Activity by User**")
        if "userName" in df.columns:
            top = df["userName"].value_counts().head(10).reset_index()
            top.columns = ["User", "Count"]
            fig = px.bar(top, x="Count", y="User", orientation="h",
                         color_discrete_sequence=["#ff7f0e"])
            fig.update_layout(height=350, margin=dict(l=10, r=10, t=10, b=10))
            st.plotly_chart(fig, use_container_width=True)

    col_c, col_d = st.columns(2)
    with col_c:
        st.markdown("**Severity Distribution**")
        if "severity" in df.columns:
            sev = df["severity"].value_counts().reset_index()
            sev.columns = ["Severity", "Count"]
            color_map = {"high": "#d62728", "medium": "#ff7f0e", "info": "#2ca02c"}
            fig = px.pie(sev, names="Severity", values="Count",
                         color="Severity", color_discrete_map=color_map)
            fig.update_layout(height=300, margin=dict(l=10, r=10, t=10, b=10))
            st.plotly_chart(fig, use_container_width=True)

    with col_d:
        st.markdown("**Activity by Source IP**")
        if "sourceIPAddress" in df.columns:
            top = df["sourceIPAddress"].value_counts().head(8).reset_index()
            top.columns = ["Source IP", "Count"]
            fig = px.bar(top, x="Count", y="Source IP", orientation="h",
                         color_discrete_sequence=["#9467bd"])
            fig.update_layout(height=300, margin=dict(l=10, r=10, t=10, b=10))
            st.plotly_chart(fig, use_container_width=True)


def render_findings(report: dict | None) -> None:
    st.subheader("⚠️ Security Findings")
    if not report:
        st.info("No report loaded. Run the pipeline first: "
                "`python src/report_findings.py`")
        return

    findings = report.get("findings", [])
    if not findings:
        st.success("No findings detected in the current dataset.")
        return

    for f in findings:
        severity = f.get("severity", "info")
        icon = "🔴" if severity == "high" else "🟡" if severity == "medium" else "🔵"
        with st.expander(
            f"{icon} [{f.get('ruleId','?')}] {f.get('ruleName','?')} "
            f"— {f.get('eventTime','')[:19]}"
        ):
            st.json(f)


def render_suspicious_events(df: pd.DataFrame) -> None:
    st.subheader("🚨 Suspicious Events")
    if "isSuspicious" in df.columns:
        susp = df[df["isSuspicious"] == True].copy()
        if susp.empty:
            st.success("No suspicious events in the current dataset.")
        else:
            st.dataframe(
                susp[["eventTime", "eventName", "userName",
                      "sourceIPAddress", "severity", "errorCode"]].head(50),
                use_container_width=True,
            )
    else:
        st.info("Severity data not available in this dataset.")


def render_raw_events(df: pd.DataFrame) -> None:
    st.subheader("📋 All Events")
    st.caption(f"Showing up to 200 of {len(df)} events")
    display_cols = [c for c in [
        "eventTime", "eventName", "eventSource", "userName",
        "sourceIPAddress", "errorCode", "severity"
    ] if c in df.columns]
    st.dataframe(df[display_cols].head(200), use_container_width=True)


def render_footer() -> None:
    st.markdown("---")
    st.caption(
        "⚠️ This dashboard uses local processed data only. "
        "No live AWS connection. "
        "An anomaly score or rule finding is NOT a confirmed security incident — "
        "always investigate manually before taking action."
    )


# ─────────────────────────────────────────────────────────────────────────── #
# Main
# ─────────────────────────────────────────────────────────────────────────── #

def main() -> None:
    render_header()

    # Load data
    report = load_report()
    df = load_events_csv()

    if df is None or df.empty:
        st.info(
            "No processed events found in output/. "
            "Loading synthetic sample data for demonstration."
        )
        df = load_sample_as_dataframe()
        st.warning(
            "🔔 Displaying SYNTHETIC data. "
            "Run `python src/report_findings.py` to process real events."
        )

    if df is None or df.empty:
        st.error("Could not load any event data.")
        return

    render_metrics(report, df)
    render_event_charts(df)
    render_findings(report)
    render_suspicious_events(df)
    render_raw_events(df)
    render_footer()


if __name__ == "__main__":
    main()
