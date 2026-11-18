# Supply-chain inventory, signing and attestation

The CLI's `--aibom` path invokes `scanner/aibom_generator.py` and produces scan-derived CycloneDX inventory. A generated SBOM/AIBOM, checksum or local inspector report is not a signature, trusted publisher identity or proof of complete dependencies. Schema/conformance and content correctness require actual checks at the candidate source.

The separate CLI signature helper in `scanner/provenance.py` discovers detached signatures and invokes a resolved cosign/gpg/minisign executable with fixed arguments and timeout. It reports failures/unavailable verifiers; it does not establish a trusted key/certificate/publisher policy merely by finding a signature or executable. The local upload inspector does not authenticate publisher signatures/training lineage.

## Optional workflow boundary

`.github/workflows/supply-chain-attest.yml` contains signing/attestation/verification steps tied to its actual triggers, permissions and registry/OIDC prerequisites. Source presence is not execution. Registry publication, cosign signing, Rekor/Fulcio interaction and OIDC identities are separate external operations; no such operation was executed by this documentation pass. Do not trigger them merely to make a status table green.

| Capability | Evidence required before a passing claim |
|---|---|
| AIBOM generation | Actual emitted artifact and source/schema/content checks |
| Image signing | Exact image digest, signing identity/issuer and successful signing record |
| Signed SBOM attestation | Exact subject digest, predicate content and independent verification |
| Build provenance | Actual build/subject/source/runner provenance with valid verification |
| Consumer verification | Exact expected workflow identity/issuer, digest and result; existence of a signature is insufficient |

Never treat a broad repository identity regexp as a complete trust policy. Operators must choose approved issuer/workflow/ref/artifact identities, preserve immutable digests, validate predicate/source relationships and record real failures. Keyless describes the intended credential flow; it does not prove no secrets exist anywhere, that a workflow ran, or that current registry artifacts are signed.

Current head signing/attestation/runtime is **NOT VERIFIED** unless a generated source/digest-scoped record establishes it. Older Windows/tooling observations are historical. [EVIDENCE.md](../EVIDENCE.md) distinguishes actual hosted Docker build from unverified product-container runtime, publication and operations.
