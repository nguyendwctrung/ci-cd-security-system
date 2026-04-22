"""
Display formatters for the dashboard.

Pure functions — no Streamlit calls, no I/O.
Used by components to derive colors and human-readable strings.
"""

from __future__ import annotations

from datetime import datetime

from security_system.config.constants import RISK_COLORS


# Fallback color for unknown levels
_DEFAULT_COLOR = "#999999"


def risk_color(level: str) -> str:
    """Returns the hex color for a given risk/severity level string."""
    return RISK_COLORS.get(level.upper(), _DEFAULT_COLOR)


def severity_color(severity: str) -> str:
    """Alias of risk_color — used when the label comes from a scan tool."""
    return risk_color(severity)


def format_timestamp(ts: str) -> str:
    """
    Converts an ISO 8601 timestamp to a readable local format.
    Returns the raw string unchanged if parsing fails.
    """
    try:
        return datetime.fromisoformat(ts).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return ts or "Unknown"


def truncate(text: str, max_len: int = 60) -> str:
    """Truncates a string and appends '...' if it exceeds max_len."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + "..."


def decision_style(decision: str) -> tuple[str, str]:
    """
    Returns (background_color, label_text) for a decision value.

    Args:
        decision: One of FAIL / WARN / PASS (or BLOCK / REVIEW / ALLOW).
    """
    mapping = {
        "FAIL":   ("#FF4444", "BLOCK COMMIT"),
        "WARN":   ("#FF8844", "REVIEW REQUIRED"),
        "PASS":   ("#44DD44", "ALLOW COMMIT"),
    }
    return mapping.get(decision.upper(), (_DEFAULT_COLOR, decision.upper()))
