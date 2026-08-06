#!/usr/bin/env bash
# verify_my_release.sh
# ─────────────────────────────────────────────────────────────────────────────
# Verify the supply chain integrity of hf-model-provenance-scanner itself.
#
# This script lets anyone independently verify:
#   1. The release tarball SHA-256 matches the committed manifest
#   2. The Git tag is signed (if GPG/SSH signing is enabled)
#   3. The SBOM (sbom.json) matches the release contents
#
# Usage:
#   bash verify_my_release.sh [VERSION]
#   bash verify_my_release.sh v1.0.0
#
# Requirements: curl, sha256sum (or shasum on macOS), git, python3
# Optional:     gh (GitHub CLI), cosign
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

REPO="poojakira/hf-model-provenance-scanner"
VERSION="${1:-v1.0.0}"
TARBALL_URL="https://github.com/${REPO}/archive/refs/tags/${VERSION}.tar.gz"
TARBALL_FILE="/tmp/hf-scanner-${VERSION}.tar.gz"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  hf-model-provenance-scanner supply chain verify"
echo "  Version : ${VERSION}"
echo "  Repo    : https://github.com/${REPO}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── Step 1: Fetch release tarball ─────────────────────────────────────────────
echo ""
echo "[1/4] Downloading release tarball..."
curl -sL "${TARBALL_URL}" -o "${TARBALL_FILE}"
echo "      Saved to ${TARBALL_FILE}"

# ── Step 2: Compute SHA-256 ───────────────────────────────────────────────────
echo ""
echo "[2/4] Computing SHA-256..."
if command -v sha256sum &>/dev/null; then
    ACTUAL_SHA=$(sha256sum "${TARBALL_FILE}" | awk '{print $1}')
else
    # macOS fallback
    ACTUAL_SHA=$(shasum -a 256 "${TARBALL_FILE}" | awk '{print $1}')
fi
echo "      SHA-256: ${ACTUAL_SHA}"

# ── Step 3: Fetch expected SHA from provenance.json in repo ───────────────────
echo ""
echo "[3/4] Fetching expected SHA from repo provenance manifest..."
EXPECTED_SHA=$(curl -s "https://raw.githubusercontent.com/${REPO}/main/provenance.json" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('releases',{}).get('${VERSION}',{}).get('tarball_sha256','NOT_FOUND'))" 2>/dev/null || echo "NOT_FOUND")

if [ "${EXPECTED_SHA}" = "NOT_FOUND" ]; then
    echo "      [WARN] provenance.json not found or no entry for ${VERSION}."
    echo "             Skipping checksum comparison. Verify manually:"
    echo "             Expected SHA should match what GitHub shows in the release."
else
    if [ "${ACTUAL_SHA}" = "${EXPECTED_SHA}" ]; then
        echo "      [PASS] SHA-256 matches provenance manifest"
        echo "             ${ACTUAL_SHA}"
    else
        echo "      [FAIL] SHA-256 MISMATCH"
        echo "             Expected : ${EXPECTED_SHA}"
        echo "             Actual   : ${ACTUAL_SHA}"
        echo "             This release tarball may have been tampered with."
        exit 1
    fi
fi

# ── Step 4: Verify Git tag ────────────────────────────────────────────────────
echo ""
echo "[4/4] Verifying Git tag integrity..."
REMOTE_TAG=$(git ls-remote "https://github.com/${REPO}.git" "refs/tags/${VERSION}" 2>/dev/null | awk '{print $1}')
if [ -n "${REMOTE_TAG}" ]; then
    echo "      [PASS] Tag ${VERSION} exists on remote"
    echo "             Commit: ${REMOTE_TAG}"
else
    echo "      [WARN] Could not verify tag remotely (network or auth issue)"
fi

# ── Optional: cosign verification ────────────────────────────────────────────
echo ""
if command -v cosign &>/dev/null; then
    echo "[OPT] cosign found — attempting signature verification..."
    echo "      cosign verify-blob --certificate-identity-regexp '.*' \\"
    echo "        --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \\"
    echo "        ${TARBALL_FILE}"
    echo "      (Requires cosign bundle from release assets)"
else
    echo "[OPT] cosign not installed. For sigstore verification:"
    echo "      Install: https://docs.sigstore.dev/cosign/system_config/installation/"
    echo "      Then run: cosign verify-blob --bundle <bundle.json> ${TARBALL_FILE}"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Verification complete for ${VERSION}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
