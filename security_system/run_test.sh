#!/bin/bash
# Complete test execution runbook

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT"

echo "=== 1. Unit Tests ==="
pytest security_system/tests/unit/ -v \
  --cov=security_system \
  --cov-report=term-missing \
  --cov-report=html

echo "=== 2. Integration Tests ==="
pytest security_system/tests/integration/ -v

echo "=== 3. Security Attack Scenarios ==="
pytest security_system/tests/security/ -v

echo "=== 4. Dashboard Tests ==="
pytest security_system/tests/integration/test_dashboard.py -v

echo "=== 5. Validate Report Schema ==="
python -m pytest security_system/tests/validation/test_report_schema.py -v

echo "=== All tests passed! ==="
echo "Coverage HTML report: $PROJECT_ROOT/htmlcov/index.html"