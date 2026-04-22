"""
Findings table UI component.

Renders tabbed DataFrames for Gitleaks, Semgrep, and Trivy findings.
"""

from __future__ import annotations

from typing import Any, Dict, List

import pandas as pd
import streamlit as st

from security_system.dashboard.services.formatters import truncate


def display_findings_table(scan: Dict[str, List[Dict[str, Any]]]) -> None:
    """
    Render per-tool findings as tabbed DataFrames.

    Args:
        scan: Dict with keys 'gitleaks', 'semgrep', 'trivy'.
    """
    st.subheader("Detailed Findings")

    gitleaks: List[Dict] = scan.get("gitleaks", [])
    semgrep: List[Dict] = scan.get("semgrep", [])
    trivy: List[Dict] = scan.get("trivy", [])

    tab_gl, tab_sg, tab_tv = st.tabs(["Gitleaks", "Semgrep", "Trivy"])

    with tab_gl:
        if gitleaks:
            rows = [
                {
                    "Secret Type": leak.get("RuleID") or leak.get("SecretType", "Unknown"),
                    "File": leak.get("File") or leak.get("Path", "Unknown"),
                    "Line": leak.get("StartLine") or leak.get("Line", "N/A"),
                    "Match": truncate(leak.get("Match", ""), 50),
                    "Entropy": f"{leak.get('Entropy', 0):.2f}",
                }
                for leak in gitleaks
            ]
            st.dataframe(pd.DataFrame(rows), use_container_width=True)
        else:
            st.success("No secrets detected.")

    with tab_sg:
        if semgrep:
            rows = [
                {
                    "Rule ID": issue.get("check_id", "Unknown"),
                    "Severity": issue.get("severity", "Unknown").upper(),
                    "File": issue.get("path", "Unknown"),
                    "Line": issue.get("start", {}).get("line", "N/A"),
                    "Message": truncate(issue.get("extra", {}).get("message", ""), 60),
                }
                for issue in semgrep
            ]
            st.dataframe(pd.DataFrame(rows), use_container_width=True)
        else:
            st.success("No code issues detected.")

    with tab_tv:
        rows = []
        for result in trivy:
            target = result.get("Target", "Unknown")
            for vuln in result.get("Vulnerabilities", []):
                rows.append({
                    "Target": target,
                    "ID": vuln.get("VulnerabilityID", "?"),
                    "Package": vuln.get("PkgName", "?"),
                    "Severity": vuln.get("Severity", "Unknown"),
                    "Title": truncate(vuln.get("Title", ""), 60),
                })
            for mc in result.get("Misconfigurations", []):
                rows.append({
                    "Target": target,
                    "ID": mc.get("ID", "?"),
                    "Package": "",
                    "Severity": mc.get("Severity", "Unknown"),
                    "Title": truncate(mc.get("Title", ""), 60),
                })
        if rows:
            st.dataframe(pd.DataFrame(rows), use_container_width=True)
        else:
            st.success("No vulnerabilities detected.")
