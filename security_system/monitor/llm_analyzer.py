#!/usr/bin/env python3
"""
DEPRECATED COMPATIBILITY WRAPPER

This script is deprecated and kept only for CI backward compatibility.
Use security_system/monitor/pipeline.py as the primary entry point.
"""

from __future__ import annotations

import sys

from security_system.monitor.pipeline import SecurityPipeline
from security_system.monitor.decision.evaluator import RiskEvaluator
from security_system.utils.logger import get_logger

logger = get_logger(__name__)


def main() -> int:
    """Legacy CLI wrapper for LLM analysis step."""
    logger.warning(
        "DEPRECATED: llm_analyzer.py is a compatibility wrapper. "
        "Use security_system/monitor/pipeline.py instead."
    )

    try:
        pipeline = SecurityPipeline()
        scan_data = pipeline._step_load_raw_scan_data()
        git_ctx = pipeline._step_git_context()
        analysis = pipeline._step_llm_analysis(scan_data, git_ctx)

        # Preserve legacy CLI contract: non-zero only for blocking/high-risk output.
        decision, _ = RiskEvaluator().evaluate(analysis)
        exit_code = 1 if decision == "FAIL" else 0

        logger.info("LLM step completed via SecurityPipeline (decision=%s).", decision)
        return exit_code
    except Exception as exc:  # pylint: disable=broad-except
        logger.exception("LLM wrapper failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
