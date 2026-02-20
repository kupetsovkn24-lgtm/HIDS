import streamlit as st
import pandas as pd
import json
import sys
import os
import logging
from datetime import datetime

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from core.database import DatabaseManager
from core.baseline_manager import BaselineManager
from core.config import DB_PATH, DAYS_TO_KEEP, SENSOR_MAP
from core.scanner_engine import run_scan_generator

st.set_page_config(
    page_title="🛡️ HIDS Security Dashboard",
    page_icon="🛡️",
    layout="wide"
)

db_anomalies = DatabaseManager(DB_PATH)
baseline_db = BaselineManager()

@st.cache_data(ttl=60)
def load_data(days=DAYS_TO_KEEP):
    anomalies = db_anomalies.get_anomalies(days=days)
    if not anomalies:
        return pd.DataFrame(columns=["timestamp", "severity", "category", "description", "details"])

    return pd.DataFrame([{
        "timestamp": pd.to_datetime(ev.timestamp),
        "severity": ev.severity,
        "category": ev.category,
        "description": ev.description,
        "details_str": json.dumps(ev.details, ensure_ascii=False, indent=2),
        "details_obj": ev.details
    } for ev in anomalies])

st.title("🛡️ HIDS Security Center")
st.caption("Interactive panel for monitoring, analysis and threat response")

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📊 Dashboard",
    "🔬 Manual Scan",
    "🩹 Triage",
    "⚙️ Settings",
    "Baseline Manager"
])

# --- Tab 1: Dashboard ---
with tab1:
    st.subheader("📈 Anomaly Overview")

    kpi_cols = st.columns(4)

    try:
        df = load_data()
    except Exception as e:
        st.error(f"❌ Failed to load anomaly database: {e}")
        st.stop()

    if df.empty:
        st.success(f"🎉 No anomalies found in the last {DAYS_TO_KEEP} days. System is clean!")
    else:
        st.sidebar.header("⚙️ Dashboard Filters")
        sev_min, sev_max = st.sidebar.slider("Severity range", 1, 10, (1, 10))
        categories = sorted(df["category"].unique())
        cat_filter = st.sidebar.multiselect("Categories", categories, default=categories)

        filtered_df = df[
            (df["severity"].between(sev_min, sev_max)) &
            (df["category"].isin(cat_filter))
        ]

        kpi_cols[0].metric("🧾 Total anomalies", len(filtered_df))
        kpi_cols[1].metric("🔥 Critical (≥8)", (filtered_df["severity"] >= 8).sum())
        kpi_cols[2].metric("🧠 Categories", filtered_df["category"].nunique())
        kpi_cols[3].metric("⏰ Last activity", filtered_df["timestamp"].max().strftime("%Y-%m-%d %H:%M"))

        st.divider()

        st.subheader("📄 Anomaly details")
        st.dataframe(
            filtered_df.sort_values("timestamp", ascending=False),
            width='stretch',
            hide_index=True,
            column_config={
                "timestamp": st.column_config.DatetimeColumn("Time", format="YYYY-MM-DD HH:mm:ss"),
                "severity": "Severity", "category": "Category", "description": "Description",
                "details_str": st.column_config.TextColumn("Details (JSON)"),
                "details_obj": None
            }
        )

# --- Tab 2: Manual Scan ---
with tab2:
    st.subheader("🔬 Run scan manually")
    st.caption(f"Runs a full scan cycle (equivalent to `run_scan_once.py`) and shows the live log.")

    if 'active_sensors' not in st.session_state:
        st.session_state.active_sensors = list(SENSOR_MAP.keys())

    if st.button("🚀 Run scan now", type="primary"):

        st.subheader("Execution Log (Live)")
        log_container = st.empty()
        log_text = ""

        with st.spinner("Scan in progress... This may take up to a minute."):
            active_sensors_list = st.session_state.get('active_sensors', list(SENSOR_MAP.keys()))
            for line in run_scan_generator(active_sensors_list):
                log_text += line + "\n"
                log_container.code(log_text, language="log")

        st.success("✅ Scan completed successfully!")
        st.balloons()

        st.cache_data.clear()
        st.info("Data updated. Switch to the 'Triage' tab to review results.")

# --- Tab 3: Triage ---
with tab3:
    st.subheader("🩹 Triage: Files pending review")
    st.caption("Review files with status 'pending_review' or 'not_found' and make a decision.")

    @st.cache_data(ttl=60)
    def load_pending_files():
        return db_anomalies.get_pending_review_files()

    pending_files = load_pending_files()

    if not pending_files:
        st.success("🎉 No files pending review!")

        if st.button("🔄 Refresh Triage list"):
            st.cache_data.clear()
            st.rerun()

    else:
        df_triage = pd.DataFrame(pending_files)
        st.info(f"Found {len(df_triage)} unique files pending review.")

        if st.button("🔄 Refresh Triage list"):
            st.cache_data.clear()
            st.rerun()

        selected_df = st.dataframe(
            df_triage,
            on_select="rerun",
            selection_mode="single-row",
            hide_index=True,
            width='stretch'
        )

        if not selected_df.selection.rows:
            st.warning("Select a file from the list to make a decision.")
        else:
            selected_row_index = selected_df.selection.rows[0]
            selected_file = df_triage.iloc[selected_row_index]

            sha_to_trust = selected_file["sha256"]
            name_to_trust = selected_file["name"]

            st.subheader(f"Selected: {name_to_trust}")
            st.json(selected_file.to_dict())

            col1, col2 = st.columns(2)

            if col1.button("✅ Trust file (set 'user_trusted')", type="primary"):
                success = baseline_db.set_executable_status(sha_to_trust, "user_trusted")
                if success:
                    st.success(f"File {name_to_trust} added to trusted. Refreshing list...")
                    st.cache_data.clear()
                    st.rerun()
                else:
                    st.error("Failed to update status in baseline.db. Check console log.")

            if col2.button("❌ Mark as Malicious (TODO)"):
                st.warning("Quarantine feature not yet implemented.")

# --- Tab 4: Settings ---
with tab4:
    st.subheader("⚙️ Scanner Settings")
    st.caption("These settings apply to 'Manual Scan'.")

    if 'active_sensors' not in st.session_state:
        st.session_state.active_sensors = list(SENSOR_MAP.keys())

    st.subheader("Active Sensors")
    active_sensors_list = []
    for name in SENSOR_MAP.keys():
        is_active = st.checkbox(name, value=(name in st.session_state.active_sensors), key=f"setting_{name}")
        if is_active:
            active_sensors_list.append(name)

    st.session_state.active_sensors = active_sensors_list

    st.divider()
    st.subheader("Scheduler (Info)")
    st.info("""
    Automatic background scanning is configured outside this dashboard.

    Use Windows **Task Scheduler** to run the script:
    `python D:\\Alex\\HIDS_Project\\run_scan_once.py`

    Recommended interval: every 4-6 hours.
    """)

# --- Tab 5: Baseline Manager ---
with tab5:
    st.subheader("Baseline Manager: View `baseline.db`")

    @st.cache_data(ttl=60)
    def load_baseline_data():
        # TODO: Add .get_all_executables() method to BaselineManager
        if hasattr(baseline_db, 'get_all_executables'):
            return pd.DataFrame(baseline_db.get_all_executables())
        else:
            st.warning("Method `get_all_executables()` is not yet implemented in `BaselineManager`.")
            return pd.DataFrame(columns=["sha256", "path", "publisher", "status"])

    df_baseline = load_baseline_data()

    if st.button("🔄 Refresh Baseline data"):
        st.cache_data.clear()
        st.rerun()

    st.dataframe(df_baseline, width='stretch', hide_index=True)

    st.caption("TODO: Add buttons here to manually delete or change status of records in baseline.")