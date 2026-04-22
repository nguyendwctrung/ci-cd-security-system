"""
Dashboard data loading service.

All report reading and caching lives here.
Components import from this module — they never touch the filesystem directly.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import streamlit as st

from security_system.config.constants import (
    REPORTS_DIR,
    GITLEAKS_REPORT,
    SEMGREP_REPORT,
    TRIVY_REPORT,
    AI_ANALYSIS_REPORT,
    DECISION_REPORT,
)
from security_system.utils.file_utils import read_json


@st.cache_data(ttl=30)
def load_ai_analysis() -> Optional[Dict[str, Any]]:
    """Load the latest AI analysis report."""
    return read_json(REPORTS_DIR / AI_ANALYSIS_REPORT)


@st.cache_data(ttl=30)
def load_scan_results() -> Dict[str, List[Dict[str, Any]]]:
    """
    Load raw scan reports from all three tools.

    Returns a dict with keys 'gitleaks', 'semgrep', 'trivy'.
    Each value is a list of raw finding dicts (empty list if file missing).
    """
    def _leaks(d: Optional[dict]) -> list:
        if d is None:
            return []
        return d if isinstance(d, list) else d.get("Leaks", [])

    return {
        "gitleaks": _leaks(read_json(REPORTS_DIR / GITLEAKS_REPORT)),
        "semgrep": (read_json(REPORTS_DIR / SEMGREP_REPORT) or {}).get("results", []),
        "trivy": (read_json(REPORTS_DIR / TRIVY_REPORT) or {}).get("Results", []),
    }


@st.cache_data(ttl=30)
def load_decision_report() -> Optional[Dict[str, Any]]:
    """Load the latest decision report."""
    return read_json(REPORTS_DIR / DECISION_REPORT)


@st.cache_data(ttl=300)
def load_analysis_history(days: int = 30) -> List[Dict[str, Any]]:
    """
    Loads all timestamped ai_analysis*.json files from the reports directory.

    Returns analyses newer than `days` days, sorted newest-first.
    """
    cutoff = datetime.now() - timedelta(days=days)
    history: List[Dict[str, Any]] = []

    try:
        for path in REPORTS_DIR.glob("ai_analysis*.json"):
            data = read_json(path)
            if data is None:
                continue
            ts_raw = data.get("timestamp", "")
            try:
                if datetime.fromisoformat(ts_raw) >= cutoff:
                    history.append(data)
            except ValueError:
                pass
    except Exception:
        pass

    history.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return history
