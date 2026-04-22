"""
LLM security analyzer orchestration.

Coordinates:
  1. Building analysis prompt from git and scan data
  2. Calling Gemini via LLMClient
  3. Validating and mapping response to AnalysisResult
  4. Returning conservative fallback on any error
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Dict, Any, Optional

from security_system.models.analysis_result import AnalysisResult
from security_system.models.git_context import GitContext
from security_system.utils.logger import get_logger
from security_system.utils.validators import validate_risk_score
from .client import LLMClient
from .prompts import SYSTEM_PROMPT, build_analysis_prompt

logger = get_logger(__name__)

_REQUIRED_FIELDS = {"risk_score", "is_malicious", "risk_level"}


class LLMAnalyzer:
    """
    Orchestrates LLM-based security analysis via Gemini.

    Usage:
        client = LLMClient()
        analyzer = LLMAnalyzer(client)
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
        Run LLM analysis and return AnalysisResult.

        Always returns valid AnalysisResult — uses conservative fallback
        (risk_score=5.0, MEDIUM) if LLM call fails or response is invalid.

        Args:
            git_ctx:   Commit metadata and diff
            scan_data: Raw results from {gitleaks, semgrep, trivy}

        Returns:
            AnalysisResult (never raises)
        """
        timestamp = datetime.now().isoformat()
        issue_count = sum(
            len(scan_data.get(tool, []))
            for tool in ("gitleaks", "semgrep", "trivy")
        )

        logger.info("Starting LLM analysis (commit: %s)", git_ctx.commit_hash)

        # Call LLM client (returns dict or None)
        user_prompt = build_analysis_prompt(git_ctx, scan_data)
        raw = self._client.generate_json(SYSTEM_PROMPT, user_prompt)

        # Case 1: LLM API call failed
        if raw is None:
            logger.warning("LLM call returned no response")
            return AnalysisResult.fallback(
                timestamp,
                "LLM call returned no response"
            )

        # Case 2: Response is not a dict
        if not isinstance(raw, dict):
            logger.warning("LLM response is not a dict: %s", type(raw))
            return AnalysisResult.fallback(
                timestamp,
                "Invalid LLM response format"
            )

        # Case 3: Validate required fields exist
        missing = _REQUIRED_FIELDS - raw.keys()
        if missing:
            logger.warning("Missing required fields: %s", missing)
            return AnalysisResult.fallback(
                timestamp,
                f"Missing required fields: {missing}"
            )

        # Case 4: Validate and extract fields with type checking
        try:
            risk_score = float(raw["risk_score"])
            if not validate_risk_score(risk_score):
                raise ValueError(f"risk_score {risk_score} out of valid range")
            
            risk_level = str(raw.get("risk_level", "MEDIUM"))
            is_malicious = bool(raw.get("is_malicious", False))
            detected_patterns = list(raw.get("detected_patterns", []))
            recommendations = list(raw.get("recommendations", []))
            reasoning = str(raw.get("reasoning", ""))
            
        except (TypeError, ValueError) as exc:
            logger.warning("LLM response validation failed: %s", exc)
            return AnalysisResult.fallback(
                timestamp,
                "Invalid LLM response format"
            )

        # All validations passed — build result
        return AnalysisResult(
            timestamp=timestamp,
            risk_score=risk_score,
            risk_level=risk_level,
            is_malicious=is_malicious,
            detected_patterns=detected_patterns,
            recommendations=recommendations,
            reasoning=reasoning,
            scan_issues_count=issue_count,
            errors=[],
        )

    # -----------------------------------------------------------------------
    # Private helpers
    # -----------------------------------------------------------------------

    def _call_gemini(
        self,
        git_ctx: GitContext,
        scan_data: Dict[str, Any],
    ) -> Optional[dict]:
        """Build prompt and call Gemini. Return parsed JSON or None."""
        user_prompt = build_analysis_prompt(git_ctx, scan_data)
        return self._client.generate_json(SYSTEM_PROMPT, user_prompt)

    @staticmethod
    def _validate(raw: dict) -> Optional[str]:
        """Validate response structure. Return error string if invalid."""
        missing = _REQUIRED_FIELDS - raw.keys()
        if missing:
            return f"Missing required fields: {missing}"

        if not validate_risk_score(raw.get("risk_score")):
            return f"risk_score out of valid range: {raw.get('risk_score')}"

        return None

    @staticmethod
    def _build_result(
        raw: dict,
        timestamp: str,
        issue_count: int,
    ) -> AnalysisResult:
        """Map validated Gemini response to AnalysisResult."""
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
