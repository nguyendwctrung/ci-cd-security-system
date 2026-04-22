"""Unit tests for decision engine."""
from datetime import datetime
import pytest

from security_system.monitor.decision.evaluator import RiskEvaluator
from security_system.models.analysis_result import AnalysisResult


class TestRiskEvaluator:
    """Test risk evaluation logic."""

    @pytest.fixture
    def evaluator(self):
        return RiskEvaluator(fail_threshold=7.0, warn_threshold=4.0)

    def test_evaluate_fail_malicious_intent(self, evaluator):
        """Test that malicious intent always triggers FAIL."""
        result = AnalysisResult(
            timestamp=datetime.now().isoformat(),
            risk_score=2.0,  # Below warn threshold
            risk_level="LOW",
            is_malicious=True,  # But malicious!
            detected_patterns=["Backdoor pattern"],
            recommendations=["Block immediately"],
            reasoning="Malicious code detected",
            scan_issues_count=0,
        )

        decision, reason = evaluator.evaluate(result)

        assert decision == "FAIL"
        assert "Malicious" in reason

    def test_evaluate_fail_high_risk_score(self, evaluator):
        """Test FAIL when risk score >= fail threshold."""
        result = AnalysisResult(
            timestamp=datetime.now().isoformat(),
            risk_score=7.5,  # Above fail threshold
            risk_level="CRITICAL",
            is_malicious=False,
            detected_patterns=["High-risk pattern"],
            recommendations=["Review manually"],
            reasoning="Multiple vulnerabilities detected",
            scan_issues_count=10,
        )

        decision, reason = evaluator.evaluate(result)

        assert decision == "FAIL"
        assert "7.5" in reason

    def test_evaluate_warn_medium_risk(self, evaluator):
        """Test WARN when risk score is in medium range."""
        result = AnalysisResult(
            timestamp=datetime.now().isoformat(),
            risk_score=5.0,  # Between warn (4.0) and fail (7.0)
            risk_level="MEDIUM",
            is_malicious=False,
            detected_patterns=["Medium-risk pattern"],
            recommendations=["Review recommended"],
            reasoning="Moderate security concerns",
            scan_issues_count=3,
        )

        decision, reason = evaluator.evaluate(result)

        assert decision == "WARN"
        assert "5.0" in reason

    def test_evaluate_pass_low_risk(self, evaluator):
        """Test PASS when risk score is low."""
        result = AnalysisResult(
            timestamp=datetime.now().isoformat(),
            risk_score=2.0,  # Below warn threshold
            risk_level="LOW",
            is_malicious=False,
            detected_patterns=[],
            recommendations=[],
            reasoning="No security concerns",
            scan_issues_count=0,
        )

        decision, reason = evaluator.evaluate(result)

        assert decision == "PASS"
        assert "acceptable range" in reason