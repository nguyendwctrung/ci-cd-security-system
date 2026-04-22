#!/usr/bin/env python3
"""
DEPRECATED COMPATIBILITY WRAPPER

This script is deprecated and kept only for CI backward compatibility.
Use security_system/monitor/pipeline.py as the primary entry point.
"""

from __future__ import annotations

import sys
from datetime import datetime
from typing import Any, Dict

from security_system.config.constants import (
    REPORTS_DIR,
    AI_ANALYSIS_REPORT,
    SUMMARY_REPORT,
)
from security_system.models.analysis_result import AnalysisResult
from security_system.monitor.decision import DecisionEngine
from security_system.utils.file_utils import read_json
from security_system.utils.logger import get_logger

logger = get_logger(__name__)


def _to_analysis_result(data: Dict[str, Any]) -> AnalysisResult:
    """Map persisted JSON to AnalysisResult model."""
    return AnalysisResult(
        timestamp=str(data.get("timestamp", datetime.now().isoformat())),
        risk_score=float(data.get("risk_score", 0.0)),
        risk_level=str(data.get("risk_level", "UNKNOWN")),
        is_malicious=bool(data.get("is_malicious", False)),
        detected_patterns=list(data.get("detected_patterns", [])),
        recommendations=list(data.get("recommendations", [])),
        reasoning=str(data.get("reasoning", "")),
        scan_issues_count=int(data.get("scan_issues_count", 0)),
        errors=list(data.get("errors", [])),
    )


def main() -> int:
    """Legacy CLI wrapper for decision step."""
    logger.warning(
        "DEPRECATED: decision_engine.py is a compatibility wrapper. "
        "Use security_system/monitor/pipeline.py instead."
    )

    try:
        analysis_data = read_json(REPORTS_DIR / AI_ANALYSIS_REPORT)
        if analysis_data:
            analysis = _to_analysis_result(analysis_data)
        else:
            logger.warning("AI analysis not found, using fallback result.")
            analysis = AnalysisResult.fallback(
                datetime.now().isoformat(),
                "AI analysis not available",
            )

        summary = read_json(REPORTS_DIR / SUMMARY_REPORT) or None

        engine = DecisionEngine(reports_dir=REPORTS_DIR)
        report = engine.decide(analysis, summary)
        engine.save(report)

        logger.info("Decision step completed via DecisionEngine (decision=%s).", report.decision)
        return report.exit_code()
    except Exception as exc:  # pylint: disable=broad-except
        logger.exception("Decision wrapper failed: %s", exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
