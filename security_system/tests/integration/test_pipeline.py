"""Integration tests for end-to-end pipeline execution."""
import json
from unittest.mock import patch, MagicMock
import pytest

from security_system.monitor.pipeline import SecurityPipeline


class TestSecurityPipelineE2E:
    """Test complete pipeline execution."""

    @pytest.fixture
    def mock_reports_dir(self, tmp_path):
        """Use temporary directory for reports."""
        reports_dir = tmp_path / "reports"
        reports_dir.mkdir()
        return reports_dir

    @pytest.fixture
    def mock_scan_reports(self, mock_reports_dir):
        """Create mock scan reports."""
        # Mock Gitleaks report
        gitleaks = {
            "Leaks": [
                {
                    "File": "config.py",
                    "SecretType": "AWS API Key",
                    "StartLine": 42,
                    "Match": "AKIA...",
                    "Entropy": 4.8,
                }
            ]
        }
        with open(mock_reports_dir / "gitleaks-report.json", "w") as f:
            json.dump(gitleaks, f)

        # Mock Semgrep report
        semgrep = {
            "results": [
                {
                    "check_id": "hardcoded-secret",
                    "path": "config.py",
                    "start": {"line": 42},
                    "severity": "ERROR",
                    "extra": {"message": "Hardcoded secret"},
                }
            ]
        }
        with open(mock_reports_dir / "semgrep-report.json", "w") as f:
            json.dump(semgrep, f)

        # Mock Trivy report
        trivy = {"Results": []}
        with open(mock_reports_dir / "trivy-report.json", "w") as f:
            json.dump(trivy, f)

        return mock_reports_dir

    def test_pipeline_generates_summary_report(
        self, mock_reports_dir, mock_scan_reports
    ):
        """Test that pipeline generates summary.json."""
        with patch(
            "security_system.monitor.pipeline.REPORTS_DIR", mock_reports_dir
        ):
            pipeline = SecurityPipeline(reports_dir=mock_reports_dir)
            summary_dict = pipeline._step_parse()

            # 1 gitleaks + 1 semgrep = 2 total findings
            assert summary_dict["total_findings"] == 2
            assert summary_dict["by_tool"]["gitleaks"] == 1
            assert summary_dict["by_tool"]["semgrep"] == 1
            assert summary_dict["by_severity"]["HIGH"] >= 1

            # Verify summary.json was written
            summary_file = mock_reports_dir / "summary.json"
            assert summary_file.exists()
            with open(summary_file) as f:
                saved = json.load(f)
                assert saved["total_findings"] == 2

    def test_pipeline_full_run_pass_decision(self, mock_reports_dir):
        """Test complete pipeline execution with PASS decision."""
        with patch("security_system.monitor.pipeline.GitService") as mock_git_service_class, \
             patch("security_system.monitor.pipeline.LLMAnalyzer") as mock_llm_analyzer_class, \
             patch("security_system.monitor.pipeline.LLMClient"), \
             patch("security_system.config.settings.is_llm_configured", return_value=True), \
             patch("security_system.monitor.pipeline.REPORTS_DIR", mock_reports_dir):

            # Mock git service
            mock_git_service = MagicMock()
            mock_git_service.get_context.return_value = MagicMock(
                commit_hash="abc1234",
                author="test@example.com",
                commit_message="Fix: clean code",
                timestamp="2026-04-22T10:00:00Z",
                files_changed=["app.py"],
                diff="No suspicious changes",
            )
            mock_git_service_class.return_value = mock_git_service

            # Mock LLM analyzer
            mock_analyzer = MagicMock()
            mock_analyzer.analyze.return_value = MagicMock(
                timestamp="2026-04-22T10:00:00Z",
                risk_score=2.0,
                risk_level="LOW",
                is_malicious=False,
                detected_patterns=[],
                recommendations=[],
                reasoning="No security concerns",
                scan_issues_count=0,
                errors=[],
                to_dict=lambda: {
                    "timestamp": "2026-04-22T10:00:00Z",
                    "risk_score": 2.0,
                    "risk_level": "LOW",
                    "is_malicious": False,
                    "detected_patterns": [],
                    "recommendations": [],
                    "reasoning": "No security concerns",
                    "scan_issues_count": 0,
                    "errors": [],
                },
            )
            mock_llm_analyzer_class.return_value = mock_analyzer

            pipeline = SecurityPipeline(reports_dir=mock_reports_dir)
            report = pipeline.run()

            assert report.decision == "PASS"
            assert report.risk_score == 2.0
            assert report.exit_code() == 0

            # Verify all reports exist
            assert (mock_reports_dir / "summary.json").exists()
            assert (mock_reports_dir / "ai_analysis.json").exists()
            assert (mock_reports_dir / "decision_report.json").exists()