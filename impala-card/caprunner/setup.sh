#!/usr/bin/env bash
#
# One-time setup for CAPRunner integration.
# Creates a Python venv, clones vendor repos, and generates JC reference files.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENDOR_DIR="$SCRIPT_DIR/vendor"
VENV_DIR="$SCRIPT_DIR/.venv"
APPLET_DIR="$(cd "$SCRIPT_DIR/../applet" && pwd)"

echo "=== CAPRunner Setup ==="

# --- Python virtual environment ---
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating Python 3 virtual environment..."
    python3 -m venv "$VENV_DIR"
else
    echo "Virtual environment already exists."
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

# --- Clone vendor repositories ---
mkdir -p "$VENDOR_DIR"

clone_repo() {
    local name="$1"
    local url="$2"
    if [ ! -d "$VENDOR_DIR/$name" ]; then
        echo "Cloning $name..."
        git clone "$url" "$VENDOR_DIR/$name"
    else
        echo "$name already cloned."
    fi
}

clone_repo caprunner https://github.com/benallard/caprunner.git
clone_repo pythoncard https://github.com/benallard/pythoncard.git
clone_repo pythonplatform https://github.com/benallard/pythonplatform.git

# --- Symlink pythoncard modules into caprunner ---
# caprunner expects python/, pythoncard/, pythoncardx/ in its root directory
CAPRUNNER_DIR="$VENDOR_DIR/caprunner"

for module in python pythoncard pythoncardx; do
    target="$CAPRUNNER_DIR/$module"
    source_dir="$VENDOR_DIR/pythoncard/$module"
    if [ -d "$source_dir" ] && [ ! -e "$target" ]; then
        echo "Symlinking $module into caprunner..."
        ln -s "$source_dir" "$target"
    fi
done

# Symlink pythonplatform's org/ module
if [ -d "$VENDOR_DIR/pythonplatform/org" ] && [ ! -e "$CAPRUNNER_DIR/org" ]; then
    echo "Symlinking org (pythonplatform) into caprunner..."
    ln -s "$VENDOR_DIR/pythonplatform/org" "$CAPRUNNER_DIR/org"
fi

# --- Generate JavaCard reference files ---
GENREF="$CAPRUNNER_DIR/genref.py"

generate_ref() {
    local version="$1"
    local sdk_path="$2"
    local export_dir="$sdk_path/api_export_files"
    local output="$CAPRUNNER_DIR/$version.json"

    if [ ! -d "$export_dir" ]; then
        echo "Warning: Export directory not found for $version at $export_dir, skipping."
        return
    fi

    if [ ! -f "$output" ]; then
        echo "Generating reference file for JavaCard $version..."
        python3 "$GENREF" --dump "$output" "$export_dir"
    else
        echo "Reference file for $version already exists."
    fi
}

generate_ref "3.0.1" "$APPLET_DIR/libs/sdks/jc303_kit"
generate_ref "3.0.4" "$APPLET_DIR/libs/sdks/jc304_kit"
generate_ref "3.0.5" "$APPLET_DIR/libs/sdks/jc305u4_kit"

# --- Make scripts executable ---
chmod +x "$SCRIPT_DIR/inspect.sh"
chmod +x "$SCRIPT_DIR/test.sh"
chmod +x "$SCRIPT_DIR/captest.py"

echo ""
echo "=== Setup complete ==="
echo "Run ./inspect.sh to inspect a CAP file"
echo "Run ./test.sh scripts/test_basic.txt to run APDU tests"
