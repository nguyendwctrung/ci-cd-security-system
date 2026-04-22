"""Unit tests for security tool parsers."""
import json
from pathlib import Path
import pytest

from security_system.monitor.parsers import (
    GitleaksParser,
    SemgrepParser,
    TrivyParser,
)
from security_system.models.security_issue import Severity


class TestGitleaksParser:
    """Test Gitleaks parser normalization."""

    @pytest.fixture
    def parser(self):
        return GitleaksParser()

    @pytest.fixture
    def gitleaks_report_path(self, tmp_path):
        """Create a mock Gitleaks report."""
        report = {
            "Leaks": [
                {
                    "File": "config.py",
                    "SecretType": "AWS API Key",
                    "StartLine": 42,
                    "Match": "AKIA1234567890ABCDEF",
                    "Entropy": 4.8,
                },
                {
                    "File": "secrets.env",
                    "SecretType": "Private Key",
                    "StartLine": 10,
                    "Match": "-----BEGIN PRIVATE KEY-----",
                    "Entropy": 5.2,
                },
            ]
        }
        report_path = tmp_path / "gitleaks-report.json"
        with open(report_path, "w") as f:
            json.dump(report, f)
        return report_path

    def test_parse_gitleaks_high_entropy(self, parser, gitleaks_report_path):
        """Test that high-entropy secrets are marked CRITICAL."""
        summary = parser.parse_file(gitleaks_report_path)
        
        assert summary.total_findings == 2
        assert summary.by_severity["CRITICAL"] == 1  # entropy 5.2
        assert summary.by_severity["HIGH"] == 1      # entropy 4.8
        assert summary.average_score > 7.0

    def test_parse_missing_gitleaks_report(self, parser, tmp_path):
        """Test graceful handling of missing report."""
        missing_path = tmp_path / "nonexistent.json"
        summary = parser.parse_file(missing_path)
        
        assert summary.total_findings == 0
        assert summary.average_score == 0.0


class TestSemgrepParser:
    """Test Semgrep parser normalization."""

    @pytest.fixture
    def parser(self):
        return SemgrepParser()

    @pytest.fixture
    def semgrep_report_path(self, tmp_path):
        """Create a mock Semgrep report."""
        report = {
            "results": [
                {
                    "check_id": "python.lang.security.audit.hardcoded-sql-string",
                    "path": "app.py",
                    "start": {"line": 15},
                    "severity": "ERROR",
                    "extra": {"message": "Hardcoded SQL query detected"},
                },
                {
                    "check_id": "python.django.security.injection.sql.hardcoded-sql-string",
                    "path": "views.py",
                    "start": {"line": 42},
                    "severity": "WARNING",
                    "extra": {"message": "Potential SQL injection"},
                },
            ]
        }
        report_path = tmp_path / "semgrep-report.json"
        with open(report_path, "w") as f:
            json.dump(report, f)
        return report_path

    def test_parse_semgrep_severity_mapping(self, parser, semgrep_report_path):
        """Test severity mapping (ERROR→HIGH, WARNING→MEDIUM)."""
        summary = parser.parse_file(semgrep_report_path)
        
        assert summary.total_findings == 2
        assert summary.by_severity["HIGH"] == 1       # ERROR
        assert summary.by_severity["MEDIUM"] == 1     # WARNING

    def test_parse_semgrep_issue_structure(self, parser, semgrep_report_path):
        """Test that normalized issues have required fields."""
        summary = parser.parse_file(semgrep_report_path)
        
        for issue in summary.issues:
            assert issue.tool == "semgrep"
            assert issue.severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            assert issue.file is not None
            assert issue.line >= 0


class TestTrivyParser:
    """Test Trivy dependency vulnerability parser."""

    @pytest.fixture
    def parser(self):
        return TrivyParser()

    @pytest.fixture
    def trivy_report_path(self, tmp_path):
        """Create a mock Trivy report."""
        report = {
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Type": "python-pkg",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2021-12345",
                            "PkgName": "requests",
                            "InstalledVersion": "2.25.0",
                            "Severity": "HIGH",
                            "Title": "XXE vulnerability in requests library",
                        },
                        {
                            "VulnerabilityID": "CVE-2021-54321",
                            "PkgName": "django",
                            "InstalledVersion": "3.1.0",
                            "Severity": "CRITICAL",
                            "Title": "SQL injection in ORM",
                        },
                    ],
                }
            ]
        }
        report_path = tmp_path / "trivy-report.json"
        with open(report_path, "w") as f:
            json.dump(report, f)
        return report_path

    def test_parse_trivy_vulnerabilities(self, parser, trivy_report_path):
        """Test parsing of dependency vulnerabilities."""
        summary = parser.parse_file(trivy_report_path)
        
        assert summary.total_findings == 2
        assert summary.by_severity["HIGH"] == 1
        assert summary.by_severity["CRITICAL"] == 1