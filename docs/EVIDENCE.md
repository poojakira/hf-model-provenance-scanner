# Exact-source evidence and release limits

**Release decision: PARTIAL.** The independent closing security review remains **BLOCKED**, not passing. Documentation reconciliation is distinct from that review. Any later source, including documentation changes, needs its own fresh complete regression/browser/build/security proof before results are called current.

## Published implementation-source proof

The last published implementation-source evidence identifies **16ff6f87f2f8f2832624d736c57c16e8809c1e5b**, software 0.3.0/local API 1. Its [complete immutable archive](https://github.com/poojakira/hf-model-provenance-scanner/tree/f151c25cea44b6b3225bbf50a2fbabe95c60b94a/release-evidence) records 312 passing individual tests, 3 skips, 6 passing native subtests and 76.08318890814559% local statement coverage at the unchanged 75% gate. 315 individual testcases and native subtests must not be inflated into 318 passing tests or 321 individual testcases. One upstream TestClient deprecation warning remained visible.

The three skips concern absent optional ATT&CK mapping/reporter prerequisites and Windows behavior on Linux. Separate focused Python 3.10 tests passed 57/57; five optional mapping/reporter checks passed in another isolated environment with exact core 76cf874cd6d8a012c20a76efc06b44907663751d and checked official ATT&CKv19.2 bundles. Do not combine environments into a fictitious full-suite total. Actual source/binary-browser and installed-wheel checks passed. Five associated hosted workflows succeeded, including Docker build; no product-container runtime smoke or deployment was established.

Tag evidence/local-workbench-20261116-complete points to evidence-only commit f151c25cea44b6b3225bbf50a2fbabe95c60b94a. Parent public verification matched 64 archived files. The initial archive omitted Git-ignored files; it was preserved and superseded by the complete archive, not silently overwritten. Neither tag is a software release. Exact commands/times/dependencies/skips/hashes are in its manifest, rather than remembered counts.

## Independent-review boundary

An earlier independent review at 86931c3 reproduced two MEDIUM asynchronous export/stale-authority issues and a LOW nonce-persistence hygiene issue. Source16ff fixed them, and root engineering actual-browser regressions passed. Both broad and limited independent closing attempts at the corrected source stopped with the review service's automatic cybersecurity-risk flag. Those attempts are **BLOCKED / NOT VERIFIED**, not passing tests. No further retry or safeguard bypass was used; no current independent security PASS is claimed. See [the published review status](https://github.com/poojakira/hf-model-provenance-scanner/blob/f151c25cea44b6b3225bbf50a2fbabe95c60b94a/release-evidence/independent-review-status.json). This documentation task does not resume that blocked review.

## Documentation-head proof

The planned non-release archive for this pass is **evidence/docs-reconciliation-20261118**. New-head results are pending until an actually generated, published manifest identifies that exact clean commit. A planned tag name is not evidence it exists. [PR #103](https://github.com/poojakira/hf-model-provenance-scanner/pull/103) records actual publication/head status. The old 16ff results remain explicitly prior-source; they do not attest to a later documentation head.

[DOCUMENTATION_AUDIT.md](DOCUMENTATION_AUDIT.md) records all tracked documentation dispositions, source anchors, actual checks and unavailable prerequisites. Current guides are consolidated around the implemented workflow; historical reports retain chronology/source boundaries. A local semantic review does not independently verify earlier private chronology, third-party incidents, field efficacy, external anchors or deployment history.

## Generate and interpret evidence

Freeze a clean candidate, execute [all applicable checks](TESTING.md), and write output outside source. Record repository/SHA/branch/clean state, UTC intervals, environment/tool/dependency versions and lock hashes, exact commands/exits, individual pass/fail/skip/subtest counts, coverage settings, browser/runtime proof, findings and artifact digests. Capture only allowlisted non-secret health fields; never persist process-local CSRF nonce, credentials, real user input or private artifacts. Independently compare every published artifact's bytes/hash, including ignored logs/package/coverage files. The source cannot contain its own future commit hash; generated out-of-tree manifests solve that provenance boundary.

## Branch and remaining acceptance state

The prior pass retained seven remote branches: main, one reviewed candidate and five active dependency PR branches. No HF branch was deleted and no evidence branch created. Main remains unchanged; preserve active/unique work and re-read current remote state before future cleanup. Branch-protection detail visibility was unavailable through the connected integration; this does not mean protection is absent.

Remaining gaps include independent closure, authenticated publisher/signature/lineage/model identity, behavioral/semantic safety, full GGUF payload/quantization, large/archive UI inputs, exhaustive fuzz/representative corpus coverage, authenticated public multi-user hosting, current container runtime/clean-machine and deployment-specific privacy/operations/recovery approval. CLI/service/profiles/signing/remote templates do not establish these properties in the local inspector. See [limitations](../LIMITATIONS.md) and [release gates](../PRODUCTION.md).
