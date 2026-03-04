#!/usr/bin/env bash
#
# Inspect a CAP file using CAPRunner's readcap.py.
# Usage: ./inspect.sh [path/to/file.cap]
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
CAPRUNNER_DIR="$SCRIPT_DIR/vendor/caprunner"
DEFAULT_CAP="$SCRIPT_DIR/../applet/build/ImpalaApplet.cap"

CAP_FILE="${1:-$DEFAULT_CAP}"

if [ ! -f "$CAP_FILE" ]; then
    echo "Error: CAP file not found: $CAP_FILE"
    echo "Build first with: cd ../applet && gradle buildJavacard"
    exit 1
fi

if [ ! -d "$VENV_DIR" ]; then
    echo "Error: Virtual environment not found. Run ./setup.sh first."
    exit 1
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

echo "=== Inspecting: $CAP_FILE ==="
echo ""
python3 "$CAPRUNNER_DIR/readcap.py" "$CAP_FILE"
