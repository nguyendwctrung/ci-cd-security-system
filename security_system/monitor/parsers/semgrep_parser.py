"""
Semgrep parser.

Reads the semgrep-report.json produced by:
    semgrep --config=p/security-audit --json --output <file>

Semgrep uses its own severity labels (INFO / WARNING / ERROR).
These are mapped to the canonical levels used by this system.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

from security_system.models.security_issue import SecurityIssue, Severity
from security_system.config.constants import SEMGREP_SEVERITY_MAP
from security_system.utils.logger import get_logger
from .base_parser import BaseParser, ToolSummary

logger = get_logger(__name__)

# Maximum characters preserved from a Semgrep message for readability
_MESSAGE_MAX_LEN = 200


class SemgrepParser(BaseParser):
    """Parses Semgrep JSON report into normalized SecurityIssue objects."""

    tool_name = "semgrep"

    def parse(self, report_path: Path) -> ToolSummary:
        with report_path.open("r", encoding="utf-8") as fh:
            raw = json.load(fh)

        results: list = raw.get("results", [])
        issues: List[SecurityIssue] = []

        for result in results:
            severity = self._normalize_severity(
                result.get("severity", ""),
                SEMGREP_SEVERITY_MAP,
            )

            rule_id = result.get("check_id", "unknown-rule")
            message = result.get("extra", {}).get("message", "No message provided")
            message = message[:_MESSAGE_MAX_LEN]

            issue = SecurityIssue(
                tool=self.tool_name,
                severity=severity,
                type=rule_id,
                message=message,
                file=result.get("path"),
                line=result.get("start", {}).get("line"),
            )
            issues.append(issue)

        logger.info("[%s] Found %d finding(s)", self.tool_name, len(issues))

        return ToolSummary(
            tool=self.tool_name,
            total_findings=len(issues),
            by_severity=self._count_by_severity(issues),
            issues=issues,
            average_score=self._compute_average(issues),
        )
