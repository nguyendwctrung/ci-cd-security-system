"""
Scan summary UI component.

Renders finding counts and per-tool breakdowns for Gitleaks, Semgrep, Trivy.
"""

from __future__ import annotations

from typing import Any, Dict, List

import streamlit as st


def display_scan_summary(scan: Dict[str, List[Dict[str, Any]]]) -> None:
    """
    Render the scan summary metrics.

    Args:
        scan: Dict with keys 'gitleaks', 'semgrep', 'trivy'.
    """
    st.subheader("Scan Summary")

    gitleaks: List[Dict] = scan.get("gitleaks", [])
    semgrep: List[Dict] = scan.get("semgrep", [])
    trivy: List[Dict] = scan.get("trivy", [])

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("Gitleaks (Secrets)", len(gitleaks))
        if gitleaks:
            counts: Dict[str, int] = {}
            for leak in gitleaks:
                key = leak.get("RuleID") or leak.get("SecretType", "Unknown")
                counts[key] = counts.get(key, 0) + 1
            for label, count in list(counts.items())[:5]:
                st.caption(f"  {label}: {count}")

    with col2:
        st.metric("Semgrep (Code)", len(semgrep))
        if semgrep:
            by_sev: Dict[str, int] = {}
            for issue in semgrep:
                sev = issue.get("severity", "UNKNOWN").upper()
                by_sev[sev] = by_sev.get(sev, 0) + 1
            for sev, count in sorted(by_sev.items(), reverse=True)[:5]:
                st.caption(f"  {sev}: {count}")

    with col3:
        total_vulns = sum(
            len(r.get("Vulnerabilities", [])) + len(r.get("Misconfigurations", []))
            for r in trivy
        )
        st.metric("Trivy (Dependencies)", total_vulns)
        for result in trivy[:3]:
            target = result.get("Target", "?")
            count = len(result.get("Vulnerabilities", [])) + len(result.get("Misconfigurations", []))
            st.caption(f"  {target}: {count}")
