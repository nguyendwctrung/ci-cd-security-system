"""
Central constants for the CI/CD Security System.

All magic numbers, thresholds, paths, and fixed values are defined here.
No environment-dependent logic — use settings.py for that.
"""

from pathlib import Path

# ============================================================================
# Directory Paths
# ============================================================================

SECURITY_SYSTEM_DIR = Path("security_system")
REPORTS_DIR = SECURITY_SYSTEM_DIR / "reports"
HISTORY_DIR = REPORTS_DIR / "history"

# Report file names
GITLEAKS_REPORT = "gitleaks-report.json"
SEMGREP_REPORT = "semgrep-report.json"
TRIVY_REPORT = "trivy-report.json"
SUMMARY_REPORT = "summary.json"
AI_ANALYSIS_REPORT = "ai_analysis.json"
DECISION_REPORT = "decision_report.json"

# ============================================================================
# LLM Configuration
# ============================================================================

LLM_MODEL = "gemini-2.5-flash-lite"
LLM_MAX_TOKENS = 2048
LLM_TIMEOUT = 30  # seconds

# ============================================================================
# Input Size Limits
# ============================================================================

MAX_DIFF_SIZE = 10_000        # characters
MAX_COMMIT_MESSAGE_SIZE = 500  # characters
MAX_FILE_PATH_SIZE = 200       # characters

# ============================================================================
# Risk Thresholds
# ============================================================================

RISK_THRESHOLD_FAIL = 7.0   # Decision: FAIL (block commit)
RISK_THRESHOLD_WARN = 4.0   # Decision: WARN (allow with notification)

# ============================================================================
# Severity Levels
# ============================================================================

SEVERITY_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

SEVERITY_SCORE: dict[str, float] = {
    "LOW": 1.0,
    "MEDIUM": 3.0,
    "HIGH": 7.0,
    "CRITICAL": 10.0,
}

# Severity mapping from tool-specific labels
SEMGREP_SEVERITY_MAP: dict[str, str] = {
    "INFO": "LOW",
    "WARNING": "MEDIUM",
    "ERROR": "HIGH",
}

TRIVY_SEVERITY_MAP: dict[str, str] = {
    "LOW": "LOW",
    "MEDIUM": "MEDIUM",
    "HIGH": "HIGH",
    "CRITICAL": "CRITICAL",
}

# ============================================================================
# Dashboard Colors
# ============================================================================

COLOR_CRITICAL = "#FF4444"
COLOR_HIGH = "#FF8844"
COLOR_MEDIUM = "#FFAA44"
COLOR_LOW = "#44AA44"
COLOR_SAFE = "#44DD44"

RISK_COLORS: dict[str, str] = {
    "CRITICAL": COLOR_CRITICAL,
    "HIGH": COLOR_HIGH,
    "MEDIUM": COLOR_MEDIUM,
    "LOW": COLOR_LOW,
    "SAFE": COLOR_SAFE,
}

# ============================================================================
# Logging
# ============================================================================

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s - %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
