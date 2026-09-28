# Supply-chain signing & attestation

This repository already generates a **CycloneDX 1.6 AIBOM/SBOM** in code
(`scanner/aibom_generator.py`, verified by the test suite). This document covers
the additional container **signing and attestation** layer.

## Status matrix (honest scoping)

| Capability | Where | Status |
|---|---|---|
| CycloneDX AIBOM/SBOM generation from scan results | `scanner/aibom_generator.py` | **VERIFIED** (unit tests pass locally) |
| Cosign **keyless** image signing (Fulcio/Rekor, OIDC) | `.github/workflows/supply-chain-attest.yml` | **UNVERIFIED locally** — requires a GitHub Actions runner with `id-token: write` and registry access. Not run on the maintainer's Windows box (no cosign binary, no OIDC token). |
| Signed CycloneDX SBOM **attestation** (`cosign attest`) | same workflow | **UNVERIFIED locally** — same reason |
| **SLSA build provenance** attestation (`actions/attest-build-provenance`) | same workflow | **UNVERIFIED locally** — same reason |
| Signature + attestation **verification gate** (`cosign verify`, `verify-attestation`) | same workflow | **UNVERIFIED locally** — same reason |

No long-lived signing private key is stored in the repo or in secrets: signing
is **keyless**, using the CI runner's short-lived OIDC identity via Sigstore
Fulcio, with transparency logged to Rekor.

## Verification runbook (run this on CI or a Linux box with the tools)

Prerequisites: `cosign` (v2+), `syft`, Docker, and — for keyless signing — an
OIDC identity (GitHub Actions provides this automatically; locally you can use
`cosign sign --yes <ref>` which opens an interactive OIDC flow).

1. **Trigger the workflow** by pushing to `main` or a `v*` tag, or via
   *Actions → supply-chain-attest → Run workflow*.
2. **Confirm the run is green.** The `VERIFY` step fails the build if the
   signature or SBOM attestation cannot be verified against the expected OIDC
   identity/issuer.
3. **Independently verify from any machine** (replace `<owner>/<repo>` and digest):

   ```bash
   cosign verify \
     --certificate-identity-regexp "^https://github.com/<owner>/<repo>/" \
     --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
     ghcr.io/<owner>/<repo>@sha256:<digest>

   cosign verify-attestation --type cyclonedx \
     --certificate-identity-regexp "^https://github.com/<owner>/<repo>/" \
     --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
     ghcr.io/<owner>/<repo>@sha256:<digest>
   ```
4. **Verify SLSA provenance** via the GitHub CLI:

   ```bash
   gh attestation verify oci://ghcr.io/<owner>/<repo>@sha256:<digest> \
     --owner <owner>
   ```

When these commands succeed on CI, update the status matrix above from
UNVERIFIED to VERIFIED and paste the run URL as evidence — consistent with the
repository's evidence-first convention.
