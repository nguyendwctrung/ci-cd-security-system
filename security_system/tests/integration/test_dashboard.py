"""Integration tests for dashboard."""
import json
import pytest

from security_system.dashboard.services import data_loader as data_loader_module
from security_system.dashboard.services.data_loader import (
    load_ai_analysis,
    load_decision_report,
)


class TestDashboardDataLoading:
    """Test dashboard data loading and rendering."""

    @pytest.fixture
    def sample_reports(self, tmp_path):
        """Create sample report files."""
        # AI Analysis Report
        ai_analysis = {
            "timestamp": "2026-04-22T10:00:00Z",
            "risk_score": 6.5,
            "risk_level": "MEDIUM",
            "is_malicious": False,
            "detected_patterns": ["SQL injection vulnerability"],
            "recommendations": ["Use parameterized queries"],
            "reasoning": "Medium risk due to SQL patterns",
            "scan_issues_count": 2,
            "errors": [],
        }
        with open(tmp_path / "ai_analysis.json", "w") as f:
            json.dump(ai_analysis, f)

        # Decision Report
        decision_report = {
            "timestamp": "2026-04-22T10:00:00Z",
            "decision": "WARN",
            "reason": "Risk score 6.5 exceeds warn threshold 4.0",
            "risk_score": 6.5,
            "is_malicious": False,
            "fail_threshold": 7.0,
            "warn_threshold": 4.0,
            "detected_patterns": ["SQL injection"],
            "recommendations": ["Update queries"],
            "metadata": {"scan_issues_count": 2},
        }
        with open(tmp_path / "decision_report.json", "w") as f:
            json.dump(decision_report, f)

        return tmp_path

    def test_dashboard_loads_ai_analysis(self, sample_reports):
        """Test dashboard can load and display AI analysis."""
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(data_loader_module, "REPORTS_DIR", sample_reports)
            load_ai_analysis.clear()  # clear Streamlit cache between tests
            analysis = load_ai_analysis()

            assert analysis is not None
            assert analysis["risk_score"] == 6.5
            assert analysis["risk_level"] == "MEDIUM"

    def test_dashboard_loads_decision_report(self, sample_reports):
        """Test dashboard can load and display decision."""
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(data_loader_module, "REPORTS_DIR", sample_reports)
            load_decision_report.clear()  # clear Streamlit cache between tests
            decision = load_decision_report()

            assert decision is not None
            assert decision["decision"] == "WARN"
            assert decision["risk_score"] == 6.5