#!/usr/bin/env bash
# run-unit-tests.sh — Build and run the full xUnit test suite.
# Usage: ./run-unit-tests.sh [--verbose]
#
# Exit codes:
#   0  All tests passed
#   1  One or more tests failed (details in output)
#   2  Build failed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TEST_PROJECT="$PROJECT_ROOT/OpenClawSecurityMonitorMac.Tests/OpenClawSecurityMonitorMac.Tests.csproj"

VERBOSE=false
if [[ "${1:-}" == "--verbose" ]]; then
    VERBOSE=true
fi

echo "=== OpenClaw Security Monitor — Unit Test Runner ==="
echo "    Project root: $PROJECT_ROOT"
echo ""

# Build
echo "[1/2] Building..."
if ! dotnet build "$TEST_PROJECT" -c Release --nologo -v quiet 2>&1; then
    echo ""
    echo "ERROR: Build failed. Fix compilation errors before running tests."
    exit 2
fi
echo "      Build OK"
echo ""

# Run tests
echo "[2/2] Running 53 unit tests..."
if $VERBOSE; then
    dotnet test "$TEST_PROJECT" -c Release --no-build --nologo -v normal
else
    dotnet test "$TEST_PROJECT" -c Release --no-build --nologo
fi

RESULT=$?
echo ""
if [[ $RESULT -eq 0 ]]; then
    echo "✓ All tests passed."
else
    echo "✗ Some tests failed. Run with --verbose for details."
fi
exit $RESULT
