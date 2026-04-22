"""
Decision card UI component.

Renders a color-coded BLOCK / REVIEW / ALLOW banner and supporting metrics.
Reads from the DecisionReport if available; falls back to deriving from analysis.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

import streamlit as st

from security_system.dashboard.services.formatters import decision_style


def display_decision_card(
    decision_report: Optional[Dict[str, Any]],
    analysis: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Render the security decision card.

    Prefers data from `decision_report` (decision_report.json).
    Falls back to deriving the decision from `analysis` if the report is absent.
    """
    st.subheader("Security Decision")

    decision, risk_score, is_malicious, reason = _resolve(decision_report, analysis)

    if decision is None:
        st.warning("No decision data available.")
        return

    color, label = decision_style(decision)
    desc = _decision_description(decision)

    st.markdown(
        f'<div style="background:{color};padding:20px;border-radius:10px;'
        f'text-align:center;color:white;">'
        f'<h2 style="margin:0;color:white;">{label}</h2>'
        f'<p style="margin:10px 0 0;font-size:16px;">{desc}</p></div>',
        unsafe_allow_html=True,
    )

    st.markdown("---")
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Risk Score", f"{risk_score:.1f} / 10")
        st.metric("Fail Threshold", str(decision_report.get("fail_threshold", 7.0)) if decision_report else "7.0")
    with col2:
        st.metric("Malicious Detected", "Yes" if is_malicious else "No")
        if reason:
            st.metric("Reason", reason[:60] + "..." if len(reason) > 60 else reason)


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _resolve(
    report: Optional[Dict[str, Any]],
    analysis: Optional[Dict[str, Any]],
) -> tuple:
    """Returns (decision, risk_score, is_malicious, reason)."""
    if report:
        return (
            report.get("decision"),
            float(report.get("risk_score", 0.0)),
            bool(report.get("is_malicious", False)),
            report.get("reason", ""),
        )
    if analysis:
        score = float(analysis.get("risk_score", 0.0))
        mal = bool(analysis.get("is_malicious", False))
        if mal or score >= 7.0:
            dec = "FAIL"
        elif score >= 4.0:
            dec = "WARN"
        else:
            dec = "PASS"
        return dec, score, mal, ""
    return None, 0.0, False, ""


def _decision_description(decision: str) -> str:
    return {
        "FAIL": "High-risk commit detected. Block merge until reviewed.",
        "WARN": "Medium-risk commit. Manual review recommended.",
        "PASS": "Low-risk commit. Safe to merge.",
    }.get(decision.upper(), "")
