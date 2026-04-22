"""
Security pipeline orchestrator.

Wires together all modules in the correct sequence:
  1. Parse scan results (Gitleaks, Semgrep, Trivy)
  2. Load raw scan data for LLM prompt context
  3. Collect git context
  4. Run LLM analysis
  5. Make security decision
  6. Persist all reports

Contains NO business logic — only calls into existing modules.
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from security_system.config.constants import (
    REPORTS_DIR,
    GITLEAKS_REPORT,
    SEMGREP_REPORT,
    TRIVY_REPORT,
    SUMMARY_REPORT,
    AI_ANALYSIS_REPORT,
)
from security_system.monitor.parsers import GitleaksParser, SemgrepParser, TrivyParser
from security_system.monitor.parsers.base_parser import ToolSummary
from security_system.monitor.git import GitService
from security_system.monitor.llm import LLMClient, LLMAnalyzer
from security_system.monitor.decision import DecisionEngine
from security_system.models.decision_report import DecisionReport
from security_system.utils.file_utils import read_json, write_json, ensure_dir
from security_system.utils.logger import get_logger

logger = get_logger(__name__)


class SecurityPipeline:
    """
    Orchestrates the full CI/CD security scan pipeline.

    Usage:
        report = SecurityPipeline().run()
        sys.exit(report.exit_code())
    """

    def __init__(self, reports_dir: Path = REPORTS_DIR) -> None:
        self._reports_dir = reports_dir
        ensure_dir(reports_dir)

    def run(self) -> DecisionReport:
        """
        Executes the complete pipeline and returns the final DecisionReport.

        Never raises — returns a WARN-level fallback report on unexpected errors.
        """
        logger.info("=" * 60)
        logger.info("CI/CD Security Pipeline started")
        logger.info("=" * 60)

        try:
            # Step 1 — Parse scan-tool reports
            summary_dict = self._step_parse()

            # Step 2 — Load raw scan data for the LLM prompt
            scan_data = self._step_load_raw_scan_data()

            # Step 3 — Git context
            git_ctx = self._step_git_context()

            # Step 4 — LLM analysis
            analysis = self._step_llm_analysis(scan_data, git_ctx)

            # Step 5 — Decision
            report = self._step_decide(analysis, summary_dict)

            logger.info("Pipeline completed — decision: %s", report.decision)
            return report

        except Exception as exc:
            logger.exception("Unexpected pipeline error: %s", exc)
            return self._emergency_fallback(str(exc))

    # -----------------------------------------------------------------------
    # Pipeline steps
    # -----------------------------------------------------------------------

    def _step_parse(self) -> Dict[str, Any]:
        """Run all three parsers and persist summary.json."""
        logger.info("Step 1/5 — Parsing scan results")

        summaries = {
            "gitleaks": GitleaksParser().parse_file(self._reports_dir / GITLEAKS_REPORT),
            "semgrep":  SemgrepParser().parse_file(self._reports_dir / SEMGREP_REPORT),
            "trivy":    TrivyParser().parse_file(self._reports_dir / TRIVY_REPORT),
        }

        summary_dict = self._build_summary_dict(summaries)
        write_json(self._reports_dir / SUMMARY_REPORT, summary_dict)
        logger.info(
            "Parsed %d total findings", summary_dict["total_findings"]
        )
        return summary_dict

    def _step_load_raw_scan_data(self) -> Dict[str, Any]:
        """Load raw JSON reports — used to build the LLM prompt."""
        logger.info("Step 2/5 — Loading raw scan data for LLM")

        def _leaks(d: Optional[dict]) -> list:
            if d is None:
                return []
            return d if isinstance(d, list) else d.get("Leaks", [])

        return {
            "gitleaks": _leaks(read_json(self._reports_dir / GITLEAKS_REPORT)),
            "semgrep":  (read_json(self._reports_dir / SEMGREP_REPORT) or {}).get("results", []),
            "trivy":    (read_json(self._reports_dir / TRIVY_REPORT) or {}).get("Results", []),
        }

    def _step_git_context(self):
        """Collect git metadata and diff."""
        logger.info("Step 3/5 — Collecting git context")
        return GitService().get_context()

    def _step_llm_analysis(self, scan_data: Dict[str, Any], git_ctx):
        """Run LLM analysis; fall back gracefully if the client is unavailable."""
        logger.info("Step 4/5 — Running LLM analysis")
        from security_system.config.settings import settings

        if not settings.is_llm_configured():
            logger.warning("GOOGLE_API_KEY not set — skipping LLM analysis")
            from security_system.models.analysis_result import AnalysisResult
            result = AnalysisResult.fallback(
                datetime.now().isoformat(), "GOOGLE_API_KEY not configured"
            )
        else:
            result = LLMAnalyzer(LLMClient()).analyze(git_ctx, scan_data)

        write_json(self._reports_dir / AI_ANALYSIS_REPORT, result.to_dict())
        return result

    def _step_decide(self, analysis, summary_dict: Dict[str, Any]) -> DecisionReport:
        """Evaluate risk and persist the decision report."""
        logger.info("Step 5/5 — Making security decision")
        engine = DecisionEngine(reports_dir=self._reports_dir)
        report = engine.decide(analysis, summary_dict)
        engine.save(report)
        return report

    # -----------------------------------------------------------------------
    # Private helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _build_summary_dict(summaries: Dict[str, ToolSummary]) -> Dict[str, Any]:
        """Aggregates ToolSummary objects into the summary.json structure."""
        by_severity: Dict[str, int] = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for ts in summaries.values():
            for level, count in ts.by_severity.items():
                by_severity[level] = by_severity.get(level, 0) + count

        total = sum(ts.total_findings for ts in summaries.values())

        return {
            "timestamp": datetime.now().isoformat(),
            "total_findings": total,
            "by_tool": {name: ts.total_findings for name, ts in summaries.items()},
            "by_severity": by_severity,
            "overall_score": round(
                sum(ts.average_score for ts in summaries.values()) / len(summaries), 1
            ),
            "tools": [ts.to_dict() for ts in summaries.values()],
        }

    @staticmethod
    def _emergency_fallback(error: str) -> DecisionReport:
        """Returns a safe WARN report when the pipeline itself crashes."""
        from security_system.models.analysis_result import AnalysisResult
        from security_system.monitor.decision import DecisionEngine

        ts = datetime.now().isoformat()
        analysis = AnalysisResult.fallback(ts, f"Pipeline error: {error}")
        return DecisionEngine().decide(analysis)
