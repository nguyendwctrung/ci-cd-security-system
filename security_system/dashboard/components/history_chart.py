"""
History chart UI component.

Renders a risk-score trend line, severity distribution bar chart,
and a tabular summary of recent analyses.
"""

from __future__ import annotations

from typing import Any, Dict, List

import pandas as pd
import streamlit as st

from security_system.dashboard.services.formatters import format_timestamp


def display_history_chart(history: List[Dict[str, Any]]) -> None:
    """
    Render historical analysis trends.

    Args:
        history: List of analysis dicts sorted newest-first.
    """
    st.subheader("Historical Analysis")

    if not history:
        st.info("No historical data available yet.")
        return

    df = _to_dataframe(history[:30])

    # Risk score trend
    st.markdown("**Risk Score Trend:**")
    st.line_chart(df.set_index("Timestamp")[["Risk Score"]], use_container_width=True)

    # Risk level distribution
    st.markdown("**Risk Level Distribution:**")
    st.bar_chart(df["Risk Level"].value_counts(), use_container_width=True)

    # Table
    st.markdown("**Recent Analyses:**")
    display_df = df[["Timestamp", "Risk Score", "Risk Level", "Issues"]].copy()
    display_df["Timestamp"] = display_df["Timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    st.dataframe(display_df, use_container_width=True)


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _to_dataframe(history: List[Dict[str, Any]]) -> pd.DataFrame:
    rows = [
        {
            "Timestamp": entry.get("timestamp", ""),
            "Risk Score": float(entry.get("risk_score", 0.0)),
            "Risk Level": entry.get("risk_level", "UNKNOWN"),
            "Issues": int(entry.get("scan_issues_count", 0)),
        }
        for entry in history
    ]
    df = pd.DataFrame(rows)
    df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")
    return df.sort_values("Timestamp")
