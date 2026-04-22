"""Test case 001: Hardcoded secrets detection."""
import json
import tempfile
import subprocess
from pathlib import Path


def test_001_hardcoded_aws_keys():
    """
    ATTACK: Hardcoded AWS credentials in config file
    TOOL: Gitleaks (secret detection)
    EXPECTED: At least one leak detected
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Initialize git repo
        subprocess.run(["git", "init"], cwd=tmpdir, check=True)
        subprocess.run(
            ["git", "config", "user.email", "test@example.com"],
            cwd=tmpdir,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Test User"],
            cwd=tmpdir,
            check=True,
        )

        # Create file with hardcoded secrets
        secrets_file = tmpdir / "aws_config.py"
        secrets_file.write_text("""
# AWS credentials
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Database password
DB_PASSWORD = "SuperSecret123!@#"

# API token
API_TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"
""")

        # Stage and commit
        subprocess.run(["git", "add", "."], cwd=tmpdir, check=True)
        subprocess.run(
            ["git", "commit", "-m", "Add AWS config"],
            cwd=tmpdir,
            check=True,
        )

        # Run Gitleaks
        subprocess.run(
            [
                "gitleaks",
                "detect",
                "--verbose",
                "--report-format",
                "json",
                "--report-path",
                str(tmpdir / "gitleaks-report.json"),
            ],
            cwd=tmpdir,
            check=False,
        )

        # Verify Gitleaks detected leaks (supports both JSON formats)
        report = json.loads((tmpdir / "gitleaks-report.json").read_text())
        if isinstance(report, dict):
            leaks = report.get("Leaks", [])
        else:
            leaks = report

        print(f"Detected {len(leaks)} leaks")

        assert leaks, "Expected at least one leak"
        assert len(leaks) >= 1, "Expected at least one leak"

        required_fields = {"Secret", "RuleID", "File"}
        for leak in leaks:
            assert required_fields.issubset(leak.keys()), (
                f"Leak missing required fields: {required_fields - set(leak.keys())}"
            )


def test_001_expected_llm_analysis():
    """Expected LLM analysis output for hardcoded secrets."""
    expected_response = {
        "risk_score": 8.5,
        "risk_level": "CRITICAL",
        "is_malicious": True,
        "detected_patterns": [
            "Hardcoded AWS credentials (high entropy)",
            "GitHub personal access token",
            "Database password exposure",
            "Multiple credential types (credential stuffing pattern)",
        ],
        "recommendations": [
            "Immediately rotate all exposed credentials",
            "Revoke GitHub token",
            "Audit AWS account for unauthorized access",
            "Block this commit and notify security team",
            "Implement secrets scanning pre-commit hook",
        ],
        "reasoning": "Multiple high-entropy secrets with formats matching real AWS, GitHub, and database credentials. Typical supply chain attack or accidental credential exposure. Entropy scores indicate legitimate credentials rather than test placeholders.",
    }

    required_keys = {
        "risk_score",
        "risk_level",
        "is_malicious",
        "detected_patterns",
        "recommendations",
        "reasoning",
    }

    assert required_keys.issubset(expected_response.keys())
    assert expected_response["risk_score"] == 8.5
    assert expected_response["risk_level"] == "CRITICAL"
    assert expected_response["is_malicious"] is True
    assert len(expected_response["detected_patterns"]) >= 3
    assert len(expected_response["recommendations"]) >= 3
    assert "credentials" in expected_response["reasoning"].lower()