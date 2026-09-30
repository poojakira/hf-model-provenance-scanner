#!/bin/bash
# Reviewed installer for HF Model Provenance Scanner
# Download this script from an immutable commit, inspect it, then run it locally.
# Set HF_SCANNER_REF to another reviewed full commit SHA only when intentionally upgrading.
set -euo pipefail

echo "Installing HF Model Provenance Scanner..."

# Detect Python
if command -v python3 &>/dev/null; then
    PYTHON=python3
elif command -v python &>/dev/null; then
    PYTHON=python
else
    echo "ERROR: Python 3.9+ is required but not found."
    echo "Install Python from https://python.org/downloads"
    exit 1
fi

# Check version
VERSION=$($PYTHON -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
MAJOR=$($PYTHON -c "import sys; print(sys.version_info.major)")
MINOR=$($PYTHON -c "import sys; print(sys.version_info.minor)")
if [ "$MAJOR" -lt 3 ] || ([ "$MAJOR" -eq 3 ] && [ "$MINOR" -lt 9 ]); then
    echo "ERROR: Python 3.9+ required, found $VERSION"
    exit 1
fi

# Install from an immutable revision by default.
INSTALL_DIR="${HF_SCANNER_DIR:-$HOME/.hf-scanner}"
HF_SCANNER_REF="${HF_SCANNER_REF:-9a9aa1fe37dd3366a0034ab3d6d5b35222a26fc4}"
if [ ! -d "$INSTALL_DIR/.git" ]; then
    rm -rf "$INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"
    git -C "$INSTALL_DIR" init --quiet
    git -C "$INSTALL_DIR" remote add origin https://github.com/poojakira/hf-model-provenance-scanner.git
fi
git -C "$INSTALL_DIR" fetch --quiet --depth 1 origin "$HF_SCANNER_REF"
git -C "$INSTALL_DIR" checkout --quiet --detach FETCH_HEAD

# Add to PATH (if not already)
SHELL_RC=""
if [ -f "$HOME/.bashrc" ]; then SHELL_RC="$HOME/.bashrc"
elif [ -f "$HOME/.zshrc" ]; then SHELL_RC="$HOME/.zshrc"
fi

ALIAS_LINE="alias hf-scanner='$PYTHON -m scanner.cli'"
BIN_PATH="export PATH=\"$INSTALL_DIR:\$PATH\""

if [ -n "$SHELL_RC" ]; then
    if ! grep -q "hf-scanner" "$SHELL_RC" 2>/dev/null; then
        echo "" >> "$SHELL_RC"
        echo "# HF Model Provenance Scanner" >> "$SHELL_RC"
        echo "export HF_SCANNER_DIR=\"$INSTALL_DIR\"" >> "$SHELL_RC"
        echo "alias hf-scanner='cd $INSTALL_DIR && $PYTHON -m scanner.cli'" >> "$SHELL_RC"
    fi
fi

# Create wrapper script
cat > "$INSTALL_DIR/hf-scanner" << WRAPPER
#!/bin/bash
cd "$INSTALL_DIR" && $PYTHON -m scanner.cli "\$@"
WRAPPER
chmod +x "$INSTALL_DIR/hf-scanner"

echo ""
echo "✅ HF Scanner installed to: $INSTALL_DIR"
echo ""
echo "Usage:"
echo "  cd $INSTALL_DIR && $PYTHON -m scanner.cli --help"
echo ""
echo "Or restart your shell and use:"
echo "  hf-scanner --help"
echo ""
echo "Quick test:"
echo "  cd $INSTALL_DIR && $PYTHON -m scanner.cli tests/fixtures/binary --mode local --fail-on never"
