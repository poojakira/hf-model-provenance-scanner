#!/usr/bin/env bash
# Install the reviewed LOCAL checkout into a new virtual environment.
# Never deletes directories, fetches remote code, edits shell profiles or upgrades in place.
set -euo pipefail
PYTHON="${PYTHON:-python3}"
"$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else "Python 3.10+ required")'
SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
INSTALL_DIR="${HF_SCANNER_DIR:-$SOURCE_DIR/.venv}"
if [[ -e "$INSTALL_DIR" || -L "$INSTALL_DIR" ]]; then
    echo "Refusing to replace existing path: $INSTALL_DIR" >&2
    exit 1
fi
"$PYTHON" -m venv "$INSTALL_DIR"
"$INSTALL_DIR/bin/python" -m pip install "$SOURCE_DIR"
echo "Installed reviewed local source. Start: $INSTALL_DIR/bin/hf-inspector"
