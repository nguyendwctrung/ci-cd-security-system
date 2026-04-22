"""
Input validation utilities for the CI/CD Security System.

Used at module boundaries to verify incoming data before processing.
Avoids defensive checks scattered across business logic.
"""

import json
from typing import Any, Optional

from security_system.utils.logger import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# JSON / String validation
# ---------------------------------------------------------------------------

def validate_json_string(text: Optional[str]) -> Optional[dict]:
    """
    Parses a raw JSON string and returns the resulting dict.

    Args:
        text: A string expected to contain valid JSON.

    Returns:
        Parsed dict, or None if text is None, empty, or malformed.
    """
    if not text:
        logger.debug("validate_json_string: received empty or None input")
        return None

    try:
        result = json.loads(text)
        if not isinstance(result, dict):
            logger.warning("validate_json_string: expected object, got %s", type(result).__name__)
            return None
        return result
    except json.JSONDecodeError as exc:
        logger.error("validate_json_string: JSON parse error — %s", exc)
        return None


# ---------------------------------------------------------------------------
# Report structure validation
# ---------------------------------------------------------------------------

_ANALYSIS_REQUIRED_FIELDS = {"risk_score", "is_malicious", "risk_level"}
_DECISION_REQUIRED_FIELDS = {"decision", "risk_score", "reason"}
_SUMMARY_REQUIRED_FIELDS = {"total_findings", "overall_score"}


def validate_report_structure(data: Any, report_type: str) -> bool:
    """
    Checks that a loaded report dict contains the expected top-level fields.

    Args:
        data:        The loaded report dict.
        report_type: One of 'analysis', 'decision', 'summary'.

    Returns:
        True if valid, False otherwise.
    """
    if not isinstance(data, dict):
        logger.warning("validate_report_structure: expected dict, got %s", type(data).__name__)
        return False

    required: set[str] = {
        "analysis": _ANALYSIS_REQUIRED_FIELDS,
        "decision": _DECISION_REQUIRED_FIELDS,
        "summary": _SUMMARY_REQUIRED_FIELDS,
    }.get(report_type, set())

    missing = required - data.keys()
    if missing:
        logger.warning(
            "validate_report_structure: '%s' report missing fields: %s",
            report_type,
            missing,
        )
        return False

    return True


# ---------------------------------------------------------------------------
# Value range validation
# ---------------------------------------------------------------------------

def validate_risk_score(score: Any) -> bool:
    """Returns True if score is a float/int in the range [0.0, 10.0]."""
    if not isinstance(score, (int, float)):
        return False
    return 0.0 <= float(score) <= 10.0


def validate_severity(value: Any) -> bool:
    """Returns True if value is one of the canonical severity strings."""
    return value in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
