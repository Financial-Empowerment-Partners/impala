#!/usr/bin/env bash
#
# Run APDU tests against a CAP file using CAPRunner's runcap.py.
# Usage: ./test.sh <test_script.txt> [jc_version]
#
# Arguments:
#   test_script.txt  - Path to a CAPRunner test script
#   jc_version       - JavaCard version (default: 3.0.1)
#
# Exit codes:
#   0 - All APDUs matched expected responses
#   1 - APDU mismatch or error
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
CAPRUNNER_DIR="$SCRIPT_DIR/vendor/caprunner"

if [ $# -lt 1 ]; then
    echo "Usage: ./test.sh <test_script.txt> [jc_version]"
    echo ""
    echo "Example: ./test.sh scripts/test_basic.txt"
    exit 1
fi

TEST_SCRIPT="$1"
JC_VERSION="${2:-3.0.1}"

if [ ! -f "$TEST_SCRIPT" ]; then
    echo "Error: Test script not found: $TEST_SCRIPT"
    exit 1
fi

if [ ! -d "$VENV_DIR" ]; then
    echo "Error: Virtual environment not found. Run ./setup.sh first."
    exit 1
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

echo "=== Running test: $TEST_SCRIPT (JC $JC_VERSION) ==="
echo ""
python3 "$CAPRUNNER_DIR/runcap.py" "$JC_VERSION" < "$TEST_SCRIPT"
exit_code=$?

if [ $exit_code -eq 0 ]; then
    echo ""
    echo "=== PASSED ==="
else
    echo ""
    echo "=== FAILED ==="
fi

exit $exit_code
