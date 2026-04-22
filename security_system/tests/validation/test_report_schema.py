"""Schema validation tests for generated report JSON files."""
import json
from unittest.mock import MagicMock, patch

import pytest

from security_system.monitor.pipeline import SecurityPipeline


def _write_scan_reports(reports_dir):
    with open(reports_dir / "gitleaks-report.json", "w", encoding="utf-8") as handle:
        json.dump(
            {"Leaks": [{"File": "config.py", "SecretType": "AWS API Key", "StartLine": 3, "Match": "AKIA...", "Entropy": 4.8}]},
            handle,
        )

    with open(reports_dir / "semgrep-report.json", "w", encoding="utf-8") as handle:
        json.dump(
            {"results": [{"check_id": "hardcoded-secret", "path": "config.py", "start": {"line": 3}, "severity": "ERROR", "extra": {"message": "Hardcoded secret"}}]},
            handle,
        )

    with open(reports_dir / "trivy-report.json", "w", encoding="utf-8") as handle:
        json.dump({"Results": []}, handle)


def _load_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _assert_types(payload, schema):
    for key, expected_type in schema.items():
        assert key in payload, f"Missing required field: {key}"
        assert isinstance(payload[key], expected_type), (
            f"Field {key} should be {expected_type}, got {type(payload[key])}"
        )


def _run_pipeline_with_analysis(reports_dir, risk_score, risk_level, is_malicious):
    with patch("security_system.monitor.pipeline.GitService") as git_service_class, \
         patch("security_system.monitor.pipeline.LLMAnalyzer") as llm_analyzer_class, \
         patch("security_system.monitor.pipeline.LLMClient"), \
         patch("security_system.config.settings.is_llm_configured", return_value=True):

        git_service = MagicMock()
        git_service.get_context.return_value = MagicMock(
            commit_hash="abc1234",
            author="tester@example.com",
            commit_message="Schema validation test",
            timestamp="2026-04-22T10:00:00Z",
            files_changed=["config.py"],
            diff="+AWS_ACCESS_KEY_ID='AKIA...'",
        )
        git_service_class.return_value = git_service

        analysis_dict = {
            "timestamp": "2026-04-22T10:00:00Z",
            "risk_score": risk_score,
            "risk_level": risk_level,
            "is_malicious": is_malicious,
            "detected_patterns": ["pattern-a"],
            "recommendations": ["recommendation-a"],
            "reasoning": "Schema validation reasoning",
            "scan_issues_count": 2,
            "errors": [],
        }
        analysis = MagicMock(**analysis_dict)
        analysis.to_dict.return_value = analysis_dict
        llm_analyzer_class.return_value.analyze.return_value = analysis

        return SecurityPipeline(reports_dir=reports_dir).run()


@pytest.fixture
def reports_dir(tmp_path):
    path = tmp_path / "reports"
    path.mkdir()
    _write_scan_reports(path)
    return path


def test_generated_reports_have_valid_schema_for_warn(reports_dir):
    report = _run_pipeline_with_analysis(reports_dir, 5.0, "MEDIUM", False)

    summary = _load_json(reports_dir / "summary.json")
    analysis = _load_json(reports_dir / "ai_analysis.json")
    decision = _load_json(reports_dir / "decision_report.json")

    assert report.decision == "WARN"
    assert report.exit_code() == 0

    _assert_types(
        summary,
        {
            "timestamp": str,
            "total_findings": int,
            "by_tool": dict,
            "by_severity": dict,
            "overall_score": float,
            "tools": list,
        },
    )
    assert set(summary["by_tool"]) == {"gitleaks", "semgrep", "trivy"}
    assert set(summary["by_severity"]) == {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert summary["total_findings"] == 2

    _assert_types(
        analysis,
        {
            "timestamp": str,
            "risk_score": float,
            "risk_level": str,
            "is_malicious": bool,
            "detected_patterns": list,
            "recommendations": list,
            "reasoning": str,
            "scan_issues_count": int,
            "errors": list,
        },
    )

    _assert_types(
        decision,
        {
            "timestamp": str,
            "decision": str,
            "reason": str,
            "risk_score": float,
            "is_malicious": bool,
            "fail_threshold": float,
            "warn_threshold": float,
            "detected_patterns": list,
            "recommendations": list,
            "metadata": dict,
        },
    )
    assert decision["decision"] == "WARN"
    assert "scan_summary" in decision["metadata"]


def test_generated_reports_have_valid_schema_for_fail(reports_dir):
    report = _run_pipeline_with_analysis(reports_dir, 8.0, "HIGH", False)
    decision = _load_json(reports_dir / "decision_report.json")

    assert report.decision == "FAIL"
    assert report.exit_code() == 1
    assert decision["decision"] == "FAIL"
    assert isinstance(decision["risk_score"], float)
    assert decision["risk_score"] >= 7.0