"""
AI analysis UI component.

Renders risk score, threat status, detected patterns, and recommendations
from the LLM analysis report.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

import streamlit as st

from security_system.dashboard.services.formatters import risk_color, format_timestamp


def display_ai_analysis(analysis: Optional[Dict[str, Any]]) -> None:
    """Render the AI security analysis card."""
    st.subheader("AI Security Analysis")

    if not analysis:
        st.warning("No AI analysis results available.")
        return

    risk_score: float = analysis.get("risk_score", 0.0)
    risk_level: str = analysis.get("risk_level", "UNKNOWN")
    is_malicious: bool = analysis.get("is_malicious", False)
    patterns: list = analysis.get("detected_patterns", [])
    recommendations: list = analysis.get("recommendations", [])
    reasoning: str = analysis.get("reasoning", "No reasoning provided.")
    errors: list = analysis.get("errors", [])

    # --- Metric row ---
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Risk Score", f"{risk_score:.1f} / 10", delta=risk_level, delta_color="off")
        color = risk_color(risk_level)
        st.markdown(
            f'<div style="background:{color};padding:8px;border-radius:5px;'
            f'text-align:center;color:white;font-weight:bold;">{risk_level}</div>',
            unsafe_allow_html=True,
        )

    with col2:
        st.metric("Threat Status", "MALICIOUS" if is_malicious else "SAFE")

    with col3:
        st.metric("Detected Patterns", len(patterns))

    with col4:
        st.metric("Scan Issues", analysis.get("scan_issues_count", 0))

    # --- Details ---
    st.markdown("---")
    st.markdown("**Reasoning:**")
    st.info(reasoning)

    if patterns:
        st.markdown("**Detected Patterns:**")
        for i, p in enumerate(patterns, 1):
            st.write(f"{i}. {p}")

    if recommendations:
        st.markdown("**Recommendations:**")
        for i, r in enumerate(recommendations, 1):
            st.write(f"{i}. {r}")

    if errors:
        with st.expander("Errors encountered"):
            for e in errors:
                st.write(f"- {e}")

    st.caption(f"Analysis timestamp: {format_timestamp(analysis.get('timestamp', ''))}")
