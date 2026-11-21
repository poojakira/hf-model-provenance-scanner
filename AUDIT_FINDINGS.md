# Audit findings

## Repository state

Default branch main is f4fe1da87755da3ed97f7f0faf09c17e40f545e9. Review started at ab26ad5cd6fe28ae1b0986e20da46be9ebb2f27a. The collected inventory contains 102 pull requests, 1 issues and 10 Git tags. The public Releases API returned zero release records.

### Open pull requests

- [#103 Add bounded local model inspection UI and source-scoped verification](https://github.com/poojakira/hf-model-provenance-scanner/pull/103)

Draft #103 was open and mergeable at the observed base and head. Audit assessment is **BLOCKED**.

### Open issues

No open issues in the collected inventory.



### Hosted runs in collected history

- Success on ab26ad5cd6fe28ae1b0986e20da46be9ebb2f27a, 2026-11-19T00:24:16Z. [Production Gate](https://github.com/poojakira/hf-model-provenance-scanner/actions/runs/44428485805)
- Failure on b392acc0dfe412c369500130c525e2618e4875e3, 2026-11-18T20:03:08Z. [Poster Artifact Parity](https://github.com/poojakira/hf-model-provenance-scanner/actions/runs/44386755295)
- Cancelled on 255f104237fb176c2495b1282815e51b5c517f0d, 2026-10-14T20:38:41Z. [Production Gate](https://github.com/poojakira/hf-model-provenance-scanner/actions/runs/38633571274)

Historical failure 44386755295 executed the poster job and failed the committed PNG parity assertion. Category B. A later exact-source poster run completed successfully.

## Confirmed defects

| ID | Severity | Affected file and lines | Root cause, impact and remediation | Status |
|---|---|---|---|---|
| HF-01 | Medium | .github/workflows/ci.yml:256–271 | Both optional-core paths used a collection pipeline that hid pytest’s status. The patched step retains the ten-test minimum and returns failure on unsuccessful collection. | Implemented locally |
| HF-02 | Low | README.md and docs/BRANCHES.md | Both files referenced a missing branch-cleanup.json in the evidence archive. HTTP returned 404 and the named object was absent from Git. The links now point to the existing immutable manifest or cleanup record. | Implemented locally |

## Residual risk

Seven open CodeQL comments were reviewed. Changes clarify intentional cleanup and string construction and move a subprocess call outside a test assertion. Independent security closure remains blocked. Bounded fixture success cannot establish model safety, publisher identity, lineage, field detection rates, parser resilience across arbitrary artifacts, or authenticated multi-user use.

The review includes the named PRs, selected source, local workflow syntax, relative file targets in Markdown, and the executed checks in [verification](VERIFICATION_REPORT.md). Complete source review, historical per-run root cause classification and validation of all operational documentation remain incomplete.
