# Product validation contract

The smallest local journey is launch → choose actual authorized file(s) → static inspect → review evidence/unknowns → replace/rerun/compare → download/checksum. The browser must use real analyzers, not a visualization-only dashboard. [INSPECTOR.md](docs/INSPECTOR.md) maps the implementation and acceptance limits.

Validation layers are distinct: existing unit/parser regressions; actual bounded worker recovery/containment; HTTP/format contracts; real browser interaction; installed-wheel source/asset behavior; dependency/build/CI; documentation commands/links/artifacts. Each requires a fresh source-scoped run. A container build is not runtime startup; a generated SBOM is not an attestation; a parsed fixture is not model safety.

Optional remote canaries require explicitly authorized repositories/credentials/network policy and an immutable revision, then report every skipped weight/error and completeness. They test interoperability, not malware efficacy. Broader representative format/corpus evaluation and deployment/operations/privacy review remain separate milestones, with no committed production pilot claimed.

Independent closing security review remains BLOCKED; all full-contract requirements must pass before VERIFIED LOCAL RELEASE CANDIDATE. Current status remains PARTIAL. See [evidence](docs/EVIDENCE.md) for actually published source/run identities and [limitations](LIMITATIONS.md) for missing properties.
