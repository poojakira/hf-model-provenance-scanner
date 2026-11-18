# HF Model Trust Inspector candidate assessment

PRODUCT: poojakira/hf-model-provenance-scanner
SOURCE: 16ff6f87f2f8f2832624d736c57c16e8809c1e5b
BRANCH: codex/local-workbench-20261116
VERSION: software0.3.0; local API1; existing remote admission API1.0.0
DECISION: **PARTIAL**. Independent closing review is BLOCKED; no production approval.

The local browser inspector serves ML engineers reviewing one or two authorized artifacts. It runs the actual repository static analyzers on supplied bytes, exposes hashes, structures, offsets and findings, compares changes, and exports a report/checksum bundle. It never loads a model. Supported bounded inputs are raw pickle, SafeTensors, GGUF metadata/descriptors and Python source. No universal safety or authenticated-origin claim is made.

## Entry point

Use the candidate README's Linux/Python3.10+ setup with libseccomp installed:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-local.lock
.venv/bin/python -m pip install --no-deps -e .
.venv/bin/python -m scanner.workbench.server
```

Open http://127.0.0.1:8763. Select files, inspect, review evidence, replace a selection and rerun, then explicitly download. No provider key or paid service is required. Installed distributions report source UNKNOWN rather than inheriting a parent repository. This is a trusted single-operator local application, not a public service.

## Fresh results at the exact source

| Gate | Observed result | Evidence |
|---|---|---|
| Full primary Linux regression |312 passed,3 skipped,6 passing native subtests; no failures/errors |junit.xml, regression.log |
| Statement coverage |76.08318890814559%; unchanged75% gate |coverage.json |
| Python3.10 focused workbench |57 passed, no failures/skips |python310-junit.xml |
| Browser source-file workflow |Actual uploads, findings, changes, downloads, async cancellation, recovery and mobile checks passed |browser/browser.json and screenshots |
| Browser binary workflow |Two actual SafeTensors files; changed data/metadata differed; identical renamed bytes compared equal; export digest matched |browser-binary/result.json and reports |
| Installed wheel |Actual isolated HTTP/assets/worker analysis under unrelated Git passed; source UNKNOWN |installed-wheel-smoke.json and report |
| Optional ATT&CK integration |5 mapping/reporter checks passed separately in isolated nonroot Docker |optional-integration/junit.xml, run.json |
| Static/build/docs/security |Lint, format, typing against actual pinned optional API, actionlint, docs check, JavaScript/bash syntax, build, Bandit and both locked/installed-environment audits passed |run-log.json and named outputs |
| Current hosted workflows |All5 succeeded, including CI, security, docs, poster parity and Production Gate |remote-ci/run-status.json |
| Hosted offline acceptance artifact |312 passed,3 skipped,6 subtests;76.13270611537509% coverage;14 embedded digests matched |remote-ci/ci-manifest.json and artifact-verification.json |

Exact commands, UTC intervals, platform/tool versions, locks and digests are in manifest.json and supplemental records. Native subtests are separate from individual testcase outcomes; JUnit suite totals include additional subtest counts and must not inflate the headline. The full suite emitted one upstream Starlette TestClient deprecation warning. The scanner's existing warning policy was preserved.

The three primary skips are the optional ATT&CK test module, the optional Navigator reporter prerequisite, and a Windows-only behavior check on Linux. The first two integrations were exercised separately by the5 container tests; do not combine different environment totals into a fictitious single full-suite run. The container used exact core76cf874cd6d8a012c20a76efc06b44907663751d and checksum-verified official v19.2 bundles. Its default HOME remained unchanged with an ephemeral writable cache; host HOME and dependency source were untouched. This proves only those tests, not a product container deployment.

The hosted artifact ZIP SHA256 is c2f5a0d7fc7017e09acd7ff3ff295b2167016a5f207ed9d545c9109b27439606. Actual checked-out source and clean state matched the candidate; saved health evidence contains no session nonce. The Docker Build job passed; no current product-container runtime smoke or public deployment is claimed. Release-to-PyPI was intentionally skipped because no manual release was requested. Workflow names do not approve production.

## Security autopsy and independent-review boundary

Initial independent review at earlier source86931c3 reproduced two MEDIUM defects: mutable state could pair a newer report with an older pending checksum, and old export authority remained visible during a new scan. It also confirmed LOW hygiene risk from persisting a process-local CSRF nonce in health evidence. Current code captures report/revision before hashing, cancels obsolete exports, clears old output on every scan, and saves only allowed health fields. Fresh actual-browser regressions at this source passed; engine output was not mocked. Installed-wheel provenance was separately corrected to require the exact tracked Git root.

Both broad and subsequently limited current-source independent closure attempts stopped with the service error “This content was flagged for possible cybersecurity risk.” Those attempts are **BLOCKED**, not passing checks. No further retry or safeguard bypass was used. Earlier-source independent success counts are not represented as current-source evidence. Root engineering regressions establish the named observed fixes, but independent closure remains NOT VERIFIED. See independent-review-status.json.

Current engineering checks exercise actual syscall denial, bounded pipe flooding/timeouts/reaping, worker failure/recovery, malformed and non-finite headers, polyglots, oversized dimensions, archive rejection, origin/token/framing/size/concurrency controls and inert rendering. Such bounded checks do not prove absence of every bypass. Secret scanning's single new heuristic match was the public pinned Git commit, not a credential; no live credential validation was attempted. The environment SBOM describes installed verification dependencies, not an OS/image/model certification.

## Implemented scope and remaining blockers

See product-matrix.json for capability/source/evidence mappings. Worker limits are4MiB/file, two files,4 CPU seconds,384MiB address space,8-second parent deadline and bounded output. A fail-closed libseccomp allowlist prevents opens/network/exec/fork after trusted initialization. It is not a VM or protection against kernel vulnerabilities. No uploaded bytes are extracted or persisted by the backend; existing source files and explicit downloads remain on the operator's disk. Memory is reclaimed, not cryptographically erased.

Model behavior, trusted signatures/publishers/training lineage, semantic equivalence, large production files, archive extraction, full GGUF payload/quantization validation, exhaustive fuzz/mutation coverage, authenticated internet hosting and environment-specific privacy/operational signoff remain NOT IMPLEMENTED/NOT VERIFIED as documented. The current input/config/source hashes bind the supported inspection scope, not a signed attestation.

All194 tracked candidate files were inventoried and safely parsed by type, with no reported syntax/local-link errors. Current task docs are consolidated; older documents carry historical notices. This is not an exhaustive semantic, image, external-link or historical-claim audit. Those documentary gates remain incomplete.

## Branch and release state

DraftPR103 contains this source; default main is unchanged. Retained remote branches are main, this reviewed candidate, and five active dependency PR branches. No obsolete feature branch was identified, no HF branch was deleted, and no evidence branch was created. The intended evidence tag is an immutable non-release archive, not a software release. Source publication and hosted CI have occurred. The detailed report and immutable evidence archive are prepared for specifically approved publication; the PR records actual publication status.

NEXT SAFE ACTION: obtain independent closing review for the final source, reconcile remaining historical/operational gates, and reviewPR103. Any later source requires fresh commit-scoped checks. No merge, public service, package publication or production release occurred.
