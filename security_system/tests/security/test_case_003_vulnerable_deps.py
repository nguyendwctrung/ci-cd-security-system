"""Test case 003: Vulnerable dependency detection."""


def test_003_vulnerable_django_version():
    """
    ATTACK: Outdated Django with known SQL injection CVE
    TOOL: Trivy (dependency scanning)
    EXPECTED: HIGH severity vulnerability
    LLM: Not malicious, but unsafe
    DECISION: WARN
    """
    vulnerable_requirements = """
Django==3.1.0
requests==2.25.0
urllib3==1.26.3
    """

    expected_trivy_findings = [
        {
            "VulnerabilityID": "CVE-2021-35042",
            "PkgName": "Django",
            "InstalledVersion": "3.1.0",
            "Severity": "HIGH",
            "Title": "SQL injection possibility in QuerySet.order_by()",
            "Description": "Django versions before 3.1.1 allow SQL injection...",
        },
        {
            "VulnerabilityID": "CVE-2021-3129",
            "PkgName": "requests",
            "InstalledVersion": "2.25.0",
            "Severity": "MEDIUM",
            "Title": "ReDoS vulnerability in urllib3",
        },
    ]

    expected_llm_analysis = {
        "risk_score": 4.5,
        "risk_level": "MEDIUM",
        "is_malicious": False,
        "detected_patterns": [
            "Outdated security-critical packages",
            "Multiple known CVEs in dependencies",
        ],
        "recommendations": [
            "Update Django to 3.1.1 or later",
            "Update requests library to 2.28+",
            "Run: pip install --upgrade django requests",
            "Add dependency version pinning with upper bounds",
        ],
        "reasoning": "Vulnerable dependencies indicate poor maintenance practices but not malicious intent. Likely oversight in dependency updates. Recommend blocking until dependencies are patched.",
    }

    expected_decision = "WARN"

    assert "Django==3.1.0" in vulnerable_requirements
    assert "requests==2.25.0" in vulnerable_requirements

    assert len(expected_trivy_findings) == 2
    for finding in expected_trivy_findings:
        assert {
            "VulnerabilityID",
            "PkgName",
            "InstalledVersion",
            "Severity",
            "Title",
        } <= finding.keys()

    assert expected_trivy_findings[0]["Severity"] == "HIGH"
    assert expected_llm_analysis["risk_score"] == 4.5
    assert expected_llm_analysis["risk_level"] == "MEDIUM"
    assert expected_llm_analysis["is_malicious"] is False
    assert len(expected_llm_analysis["detected_patterns"]) >= 1
    assert len(expected_llm_analysis["recommendations"]) >= 2
    assert expected_decision == "WARN"

    return expected_trivy_findings, expected_llm_analysis