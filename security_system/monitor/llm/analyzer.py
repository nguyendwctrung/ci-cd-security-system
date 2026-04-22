"""
LLM security analyzer.

Orchestrates the full LLM analysis flow:
  1. Build prompt from git context and scan data
  2. Call the LLM client
  3. Validate and map the response to an AnalysisResult
  4. Return a safe fallback if any step fails
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, Any, Optional

from security_system.models.analysis_result import AnalysisResult
from security_system.models.git_context import GitContext
from security_system.utils.logger import get_logger
from security_system.utils.validators import validate_report_structure, validate_risk_score
from .client import LLMClient
from .prompts import SYSTEM_PROMPT, build_analysis_prompt

logger = get_logger(__name__)

# Expected top-level keys from the LLM JSON response
_REQUIRED_RESPONSE_FIELDS = {"risk_score", "is_malicious", "risk_level"}


class LLMAnalyzer:
    """
    Orchestrates LLM-based security analysis.

    Usage:
        analyzer = LLMAnalyzer(LLMClient())
        result = analyzer.analyze(git_ctx, scan_data)
    """

    def __init__(self, client: LLMClient) -> None:
        self._client = client

    def analyze(
        self,
        git_ctx: GitContext,
        scan_data: Dict[str, Any],
    ) -> AnalysisResult:
        """
        Runs LLM analysis and returns a structured AnalysisResult.

        Always returns a valid AnalysisResult — uses a conservative fallback
        (risk_score=5.0, MEDIUM) if the LLM call or parsing fails.

        Args:
            git_ctx:   Commit metadata and diff.
            scan_data: Raw scan results keyed by tool name.

        Returns:
            AnalysisResult populated from the LLM response or a fallback.
        """
        timestamp = datetime.now().isoformat()
        issue_count = sum(
            len(scan_data.get(tool, []))
            for tool in ("gitleaks", "semgrep", "trivy")
        )

        logger.info("Starting LLM analysis (commit: %s)", git_ctx.commit_hash)

        raw = self._call_llm(git_ctx, scan_data)

        if raw is None:
            logger.warning("LLM call failed — returning fallback result")
            return AnalysisResult.fallback(timestamp, "LLM call returned no response")

        validation_error = self._validate_response(raw)
        if validation_error:
            logger.warning("LLM response invalid — %s", validation_error)
            return AnalysisResult.fallback(timestamp, validation_error)

        return self._build_result(raw, timestamp, issue_count)

    # -----------------------------------------------------------------------
    # Private helpers
    # -----------------------------------------------------------------------

    def _call_llm(
        self,
        git_ctx: GitContext,
        scan_data: Dict[str, Any],
    ) -> Optional[dict]:
        """Builds the prompt and calls the LLM. Returns parsed JSON or None."""
        user_prompt = build_analysis_prompt(git_ctx, scan_data)
        result = self._client.generate_json(SYSTEM_PROMPT, user_prompt)
        if result is not None:
            logger.info(
                "LLM response received (risk_score=%s)", result.get("risk_score")
            )
        return result

    @staticmethod
    def _validate_response(raw: dict) -> Optional[str]:
        """
        Checks that the LLM response has the expected structure and value ranges.

        Returns:
            An error message string if invalid, or None if the response is valid.
        """
        missing = _REQUIRED_RESPONSE_FIELDS - raw.keys()
        if missing:
            return f"Missing required fields: {missing}"

        if not validate_risk_score(raw.get("risk_score")):
            return f"risk_score out of range: {raw.get('risk_score')}"

        return None

    @staticmethod
    def _build_result(
        raw: dict,
        timestamp: str,
        issue_count: int,
    ) -> AnalysisResult:
        """Maps the validated LLM response dict to an AnalysisResult."""
        return AnalysisResult(
            timestamp=timestamp,
            risk_score=float(raw["risk_score"]),
            risk_level=str(raw.get("risk_level", "MEDIUM")),
            is_malicious=bool(raw.get("is_malicious", False)),
            detected_patterns=list(raw.get("detected_patterns", [])),
            recommendations=list(raw.get("recommendations", [])),
            reasoning=str(raw.get("reasoning", "")),
            scan_issues_count=issue_count,
            errors=[],
        )
