"""
Centralized logger factory for the CI/CD Security System.

All modules obtain their logger via `get_logger(__name__)` to ensure
consistent formatting and a single configuration point.
"""

import logging
import sys
from pathlib import Path
from typing import Optional

from security_system.config.constants import LOG_FORMAT, LOG_DATE_FORMAT, REPORTS_DIR


_configured = False


def _configure_root_logger(log_level: int, log_file: Optional[Path] = None) -> None:
    """
    Applies handlers and format to the root logger once per process.
    Subsequent calls are no-ops.
    """
    global _configured
    if _configured:
        return

    handlers: list[logging.Handler] = [
        logging.StreamHandler(sys.stdout),
    ]

    if log_file is not None:
        try:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
        except OSError:
            pass  # Non-critical — stdout logging continues

    logging.basicConfig(
        level=log_level,
        format=LOG_FORMAT,
        datefmt=LOG_DATE_FORMAT,
        handlers=handlers,
    )
    _configured = True


def setup_logging(
    log_level: int = logging.INFO,
    log_file: Optional[Path] = None,
) -> None:
    """
    Explicit setup entry point called once from pipeline or CLI entry points.

    Args:
        log_level: Numeric level (e.g. logging.DEBUG).
        log_file:  Optional path to write logs to disk.
    """
    _configure_root_logger(log_level, log_file)


def get_logger(name: str) -> logging.Logger:
    """
    Returns a named logger, initializing root config with defaults if needed.

    Usage:
        logger = get_logger(__name__)
        logger.info("message")
    """
    _configure_root_logger(logging.INFO, REPORTS_DIR / "security_system.log")
    return logging.getLogger(name)
