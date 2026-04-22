#!/usr/bin/env python3
"""
DEPRECATED COMPATIBILITY WRAPPER

This script is deprecated and kept only for CI backward compatibility.
Use security_system/monitor/pipeline.py as the primary entry point.
"""

from __future__ import annotations

import sys

from security_system.monitor.pipeline import SecurityPipeline
from security_system.utils.logger import get_logger

logger = get_logger(__name__)


def main() -> int:
    """Legacy CLI wrapper for parse step."""
    logger.warning(
        "DEPRECATED: parse_results.py is a compatibility wrapper. "
        "Use security_system/monitor/pipeline.py instead."
    )

    try:
        SecurityPipeline()._step_parse()
        logger.info("Parse step completed via SecurityPipeline.")
        return 0
    except Exception as exc:  # pylint: disable=broad-except
        logger.exception("Parse wrapper failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
