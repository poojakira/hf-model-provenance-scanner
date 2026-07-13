#!/bin/bash
# Uninstaller for HF Model Provenance Scanner.
# Removes the install directory and any shell-rc integration this installer
# added (only the lines it wrote, matched by the HF_SCANNER_DIR marker).
set -euo pipefail

INSTALL_DIR="${HF_SCANNER_DIR:-$HOME/.hf-scanner}"

echo "This will remove: $INSTALL_DIR"
if [ -t 0 ] && [ "${HF_SCANNER_ASSUME_YES:-0}" != "1" ]; then
    read -r -p "Proceed? [y/N] " reply
    case "$reply" in [Yy]*) ;; *) echo "Aborted."; exit 0;; esac
fi

if [ -d "$INSTALL_DIR" ]; then
    rm -rf "$INSTALL_DIR"
    echo "Removed $INSTALL_DIR"
else
    echo "Nothing to remove at $INSTALL_DIR"
fi

# Remove the shell-rc block we added (marker: HF_SCANNER_DIR).
for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
    if [ -f "$rc" ] && grep -q "HF_SCANNER_DIR" "$rc"; then
        # Delete our comment line and the two export lines we added.
        tmp="$(mktemp)"
        grep -v "HF Model Provenance Scanner" "$rc" \
            | grep -v "HF_SCANNER_DIR" \
            | grep -v "hf-scanner:\$PATH" > "$tmp" || true
        # Fallback: only drop lines mentioning our install dir / vars.
        grep -vE "HF_SCANNER_DIR|\.hf-scanner" "$rc" > "$tmp" || true
        mv "$tmp" "$rc"
        echo "Cleaned shell integration from $rc"
    fi
done

echo "Uninstall complete."
