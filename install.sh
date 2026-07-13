#!/bin/bash
# Installer for HF Model Provenance Scanner
#
# SECURITY NOTE
# -------------
# Piping a remote script straight into a shell ("curl ... | bash") runs
# whatever the server returns, unreviewed. For a *supply-chain security* tool
# that is exactly the risk we exist to prevent. Please prefer one of:
#
#   1. pip (recommended, pinned + hash-verifiable):
#        pip install --require-hashes -r requirements.txt   # once published
#        # or from a tagged release:
#        pip install "git+https://github.com/poojakira/hf-model-provenance-scanner.git@v0.2.0"
#
#   2. Download, READ, then run (never blind-pipe):
#        curl -fsSLO https://raw.githubusercontent.com/poojakira/hf-model-provenance-scanner/v0.2.0/install.sh
#        less install.sh          # review it
#        bash install.sh
#
# This script pins to a release ref, refuses to modify your shell config
# without consent, and can verify the git commit's GPG signature.
set -euo pipefail

echo "Installing HF Model Provenance Scanner..."

# Pin to a specific, reviewable ref instead of a moving branch. Override with
# HF_SCANNER_REF=<tag|commit>. Using "main" is allowed but warned against.
HF_SCANNER_REF="${HF_SCANNER_REF:-v0.2.0}"
REPO_URL="https://github.com/poojakira/hf-model-provenance-scanner.git"

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
if [ "$MAJOR" -lt 3 ] || { [ "$MAJOR" -eq 3 ] && [ "$MINOR" -lt 9 ]; }; then
    echo "ERROR: Python 3.9+ required, found $VERSION"
    exit 1
fi

# Install
INSTALL_DIR="${HF_SCANNER_DIR:-$HOME/.hf-scanner}"
if [ -d "$INSTALL_DIR/.git" ]; then
    echo "Updating existing installation (ref: $HF_SCANNER_REF)..."
    git -C "$INSTALL_DIR" fetch --quiet --tags origin
    git -C "$INSTALL_DIR" checkout --quiet "$HF_SCANNER_REF"
else
    git clone --quiet "$REPO_URL" "$INSTALL_DIR"
    git -C "$INSTALL_DIR" checkout --quiet "$HF_SCANNER_REF" || {
        echo "WARNING: ref '$HF_SCANNER_REF' not found; staying on default branch."
        echo "         Pin a released tag via HF_SCANNER_REF for a verifiable install."
    }
fi

# Optional: verify the checked-out commit is GPG-signed by a trusted key.
if [ "${HF_SCANNER_VERIFY_GPG:-0}" = "1" ]; then
    echo "Verifying commit signature..."
    if ! git -C "$INSTALL_DIR" verify-commit HEAD; then
        echo "ERROR: GPG signature verification failed. Aborting."
        exit 1
    fi
fi

# Create wrapper script (does not touch PATH or shell config on its own)
cat > "$INSTALL_DIR/hf-scanner" << WRAPPER
#!/bin/bash
cd "$INSTALL_DIR" && $PYTHON -m scanner.cli "\$@"
WRAPPER
chmod +x "$INSTALL_DIR/hf-scanner"

# Only offer to edit shell rc files with explicit consent. When the script is
# piped (no TTY) we NEVER modify user files silently — we print instructions.
add_shell_integration() {
    local shell_rc="$1"
    if grep -q "HF_SCANNER_DIR" "$shell_rc" 2>/dev/null; then
        echo "Shell integration already present in $shell_rc"
        return
    fi
    {
        echo ""
        echo "# HF Model Provenance Scanner"
        echo "export HF_SCANNER_DIR=\"$INSTALL_DIR\""
        echo "export PATH=\"$INSTALL_DIR:\$PATH\""
    } >> "$shell_rc"
    echo "Added shell integration to $shell_rc"
}

SHELL_RC=""
if [ -n "${SHELL:-}" ] && [ -f "$HOME/.zshrc" ] && [[ "$SHELL" == *zsh* ]]; then
    SHELL_RC="$HOME/.zshrc"
elif [ -f "$HOME/.bashrc" ]; then
    SHELL_RC="$HOME/.bashrc"
fi

MODIFY_RC="no"
if [ "${HF_SCANNER_ASSUME_YES:-0}" = "1" ]; then
    MODIFY_RC="yes"
elif [ -t 0 ] && [ -n "$SHELL_RC" ]; then
    # Interactive terminal: ask.
    read -r -p "Add hf-scanner to your PATH via $SHELL_RC? [y/N] " reply
    case "$reply" in [Yy]*) MODIFY_RC="yes";; esac
fi

if [ "$MODIFY_RC" = "yes" ] && [ -n "$SHELL_RC" ]; then
    add_shell_integration "$SHELL_RC"
    NEED_RESTART=1
else
    NEED_RESTART=0
fi

echo ""
echo "HF Scanner installed to: $INSTALL_DIR (ref: $HF_SCANNER_REF)"
echo ""
if [ "$NEED_RESTART" = "1" ]; then
    echo "Restart your shell, then run: hf-scanner --help"
else
    echo "To add it to your PATH, add these lines to your shell rc file:"
    echo "  export HF_SCANNER_DIR=\"$INSTALL_DIR\""
    echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
    echo ""
    echo "Or run directly:"
    echo "  \"$INSTALL_DIR/hf-scanner\" --help"
fi
