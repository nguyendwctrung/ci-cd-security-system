"""Test case 002: SQL injection pattern detection."""


def test_002_sql_injection_vulnerability():
    """
    ATTACK: Dynamic SQL query without parameterization
    TOOL: Semgrep (pattern detection)
    EXPECTED: HIGH severity, suspicious user input handling
    LLM ANALYSIS: High risk but not malicious intent
    DECISION: WARN
    """
    vulnerable_code = '''
# Vulnerable Django ORM usage
from django.db import connection

def search_users(username):
    """Vulnerable: SQL injection in raw query."""
    query = f"SELECT * FROM users WHERE username = '{username}'"
    with connection.cursor() as cursor:
        cursor.execute(query)
        return cursor.fetchall()

def delete_user(user_id):
    """Vulnerable: Direct string concatenation."""
    query = "DELETE FROM users WHERE id = " + str(user_id)
    connection.cursor().execute(query)
    '''

    expected_semgrep_findings = [
        {
            "check_id": "python.lang.security.injection.sql.hardcoded-sql-string",
            "severity": "ERROR",
            "message": "Potential SQL injection: Detected f-string in SQL query",
            "file": "app.py",
            "line": 6,
        },
        {
            "check_id": "python.lang.security.injection.sql.hardcoded-sql-string",
            "severity": "ERROR",
            "message": "Potential SQL injection: String concatenation in SQL query",
            "file": "app.py",
            "line": 13,
        },
    ]

    expected_llm_analysis = {
        "risk_score": 6.5,
        "risk_level": "MEDIUM",
        "is_malicious": False,
        "detected_patterns": [
            "Dynamic SQL query construction from user input",
            "Missing parameterization/prepared statements",
            "Direct string interpolation in queries",
        ],
        "recommendations": [
            "Use parameterized queries or ORM with parameter binding",
            "Replace f-strings with query parameters",
            "Use Django ORM User.objects.filter() instead of raw SQL",
            "Add input validation and sanitization",
        ],
        "reasoning": "Code pattern indicates accidental SQL injection vulnerability rather than malicious intent. However, demonstrates poor security practices and should be blocked for production.",
    }

    expected_decision = "WARN"

    assert "SELECT * FROM users WHERE username" in vulnerable_code
    assert 'query = "DELETE FROM users WHERE id = " + str(user_id)' in vulnerable_code

    assert len(expected_semgrep_findings) == 2
    for finding in expected_semgrep_findings:
        assert {"check_id", "severity", "message", "file", "line"} <= finding.keys()
        assert finding["severity"] == "ERROR"
        assert finding["line"] > 0

    assert expected_llm_analysis["risk_score"] == 6.5
    assert expected_llm_analysis["risk_level"] == "MEDIUM"
    assert expected_llm_analysis["is_malicious"] is False
    assert len(expected_llm_analysis["detected_patterns"]) >= 2
    assert len(expected_llm_analysis["recommendations"]) >= 2
    assert expected_decision == "WARN"

    return expected_semgrep_findings, expected_llm_analysis