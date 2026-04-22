"""Unit tests for LLM analyzer."""
from datetime import datetime
from unittest.mock import MagicMock, patch
import pytest

from security_system.monitor.llm.analyzer import LLMAnalyzer
from security_system.models.git_context import GitContext
from security_system.models.analysis_result import AnalysisResult


class TestLLMAnalyzer:
    """Test LLM analysis orchestration."""

    @pytest.fixture
    def mock_llm_client(self):
        """Mock LLM client."""
        return MagicMock()

    @pytest.fixture
    def git_context(self):
        """Create sample git context."""
        return GitContext(
            commit_hash="abc1234567",
            author="attacker@evil.com",
            commit_message="Fix: update config with new API key",
            timestamp=datetime.now().isoformat(),
            files_changed=["config.py", "secrets.env"],
            diff="""
+GOOGLE_API_KEY=AIza1234567890abcdefghijklmnop
+AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY
            """,
        )

    @pytest.fixture
    def scan_data(self):
        """Create sample scan results."""
        return {
            "gitleaks": [
                {
                    "File": "config.py",
                    "SecretType": "AWS API Key",
                    "Match": "AKIA...",
                }
            ],
            "semgrep": [
                {
                    "check_id": "hardcoded-secrets",
                    "severity": "ERROR",
                    "extra": {"message": "Hardcoded secret detected"},
                }
            ],
            "trivy": [],
        }

    def test_analyze_malicious_intent_detected(
        self, mock_llm_client, git_context, scan_data
    ):
        """Test that LLM correctly identifies malicious intent."""
        # Mock LLM response indicating malicious intent
        mock_llm_client.generate_json.return_value = {
            "risk_score": 8.5,
            "risk_level": "CRITICAL",
            "is_malicious": True,
            "detected_patterns": [
                "Credential exfiltration",
                "Obfuscated API keys",
            ],
            "recommendations": [
                "Rotate all exposed API keys immediately",
                "Block this commit",
            ],
            "reasoning": "Multiple high-entropy secrets added with obfuscation patterns typical of supply chain attacks.",
        }

        analyzer = LLMAnalyzer(mock_llm_client)
        result = analyzer.analyze(git_context, scan_data)

        assert result.is_malicious is True
        assert result.risk_score == 8.5
        assert result.risk_level == "CRITICAL"
        assert "Credential exfiltration" in result.detected_patterns

    def test_analyze_llm_unavailable_fallback(
        self, mock_llm_client, git_context, scan_data
    ):
        """Test fallback when LLM is unavailable."""
        mock_llm_client.generate_json.return_value = None

        analyzer = LLMAnalyzer(mock_llm_client)
        result = analyzer.analyze(git_context, scan_data)

        assert result.risk_score == 5.0  # Conservative fallback
        assert result.risk_level == "MEDIUM"
        assert "LLM call returned no response" in result.errors

    def test_analyze_invalid_llm_response(
        self, mock_llm_client, git_context, scan_data
    ):
        """Test handling of invalid LLM JSON response."""
        mock_llm_client.generate_json.return_value = {
            "risk_score": "invalid",  # Should be float
            # Missing required fields
        }

        analyzer = LLMAnalyzer(mock_llm_client)
        result = analyzer.analyze(git_context, scan_data)

        assert result.risk_score == 5.0
        assert len(result.errors) > 0