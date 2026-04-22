#!/usr/bin/env python3
"""
CI/CD Security Dashboard — entry point.

Orchestrates layout and delegates all rendering to components.
No business logic or data loading lives here.
"""

from datetime import datetime

import streamlit as st

from security_system.dashboard.components import (
    display_ai_analysis,
    display_scan_summary,
    display_findings_table,
    display_decision_card,
    display_history_chart,
)
from security_system.dashboard.services.data_loader import (
    load_ai_analysis,
    load_scan_results,
    load_decision_report,
    load_analysis_history,
)

# ============================================================================
# Page configuration (must be the first Streamlit call)
# ============================================================================

st.set_page_config(
    page_title="CI/CD Security Dashboard",
    page_icon="shield",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================================
# Sidebar
# ============================================================================

def _setup_sidebar() -> tuple[bool, bool]:
    st.sidebar.title("Dashboard Settings")

    if st.sidebar.button("Refresh Data", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

    st.sidebar.markdown("---")
    st.sidebar.markdown("**Display Options:**")
    show_findings = st.sidebar.checkbox("Show Detailed Findings", value=True)
    show_history = st.sidebar.checkbox("Show Historical Trends", value=True)

    st.sidebar.markdown("---")
    st.sidebar.info(
        "**CI/CD Security Dashboard**\n\n"
        "Monitors results from:\n"
        "- Gitleaks (secrets)\n"
        "- Semgrep (code)\n"
        "- Trivy (dependencies)\n"
        "- AI analysis (intent)"
    )
    return show_findings, show_history


# ============================================================================
# Main
# ============================================================================

def main() -> None:
    st.title("CI/CD Security Dashboard")
    st.markdown("Real-time security analysis and threat detection for code commits.")

    show_findings, show_history = _setup_sidebar()

    # --- Load data ---
    analysis = load_ai_analysis()
    scan = load_scan_results()
    decision = load_decision_report()

    # --- Render sections ---
    st.markdown("---")
    display_ai_analysis(analysis)

    st.markdown("---")
    display_scan_summary(scan)

    st.markdown("---")
    display_decision_card(decision, analysis)

    if show_findings:
        st.markdown("---")
        display_findings_table(scan)

    if show_history:
        st.markdown("---")
        history = load_analysis_history(days=30)
        display_history_chart(history)

    # --- Footer ---
    st.markdown("---")
    last_updated = (
        analysis.get("timestamp", "") if analysis else datetime.now().isoformat()
    )
    st.caption(f"Last updated: {last_updated}")


if __name__ == "__main__":
    main()
