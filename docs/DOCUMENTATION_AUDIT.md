# Documentation reconciliation audit

## Scope and status

This pass read all 36 original human documentation/text files plus requirements.txt at implementation base 16ff6f87f2f8f2832624d736c57c16e8809c1e5b, including every README variant, poster companion, historical report, raw trigger and legal record. Source, tests, metadata and workflows were consulted to substantiate current behavior. The table lists every original tracked md/mdx/rst/txt path; this audit page is new. Legal/dependency/trigger records remain unchanged.

**Documentation reconciliation is complete within the recorded local scope; full release remains PARTIAL.** Independent security closure remains BLOCKED by the review service. This is not a retry, rephrasing or replacement of that review. A documentation semantic cross-check is not a penetration test, field validation or execution of every example. New-head full regression/browser/security/build evidence is pending until the parent generates a manifest identifying that clean frozen source.

## Corrections

- Reconcile Linux inspector onboarding, actual input/status/comparison/download/lifecycle, error recovery and data privacy with the live static-worker path.
- Distinguish software 0.3.0, local API 1 and remote admission API 1.0.0; replace fabricated CLI flags, Python facade, JSON schema, compatibility promises and nonexistent test/release procedures with actual source contracts.
- Correct stale 0.2.0/currentmetrics, unsafe COMPLETE/exit 0 safety interpretations, disabled dynamic-execution capability tables, unverified timing guarantees and host-wide daemon claims.
- Keep optional CLI/network/provenance/signing/monitoring/executor/integration behavior accurately separate from the local worker. Correct manual-only webhook workflow and unproven precommit/GitLabSAST/serverless/notification claims.
- Preserve historical curated fixture counts and cited poster sources without presenting them as field accuracy, current-head results or confirmed real-world incident prevention. Preserve author-recorded chronology without manufacturing independent evidence.
- Record actual complete archive/publication status and explicitly retain blocked independent closure. No runtime/rule/test/security-gate/workflow/dependency behavior changed. Only poster presentation strings/diagram wording change outside Markdown.

## Per-document disposition

| Document | Disposition |
|---|---|
| `.github/format-trigger.txt` | Preserved dependency/trigger text; read, not a passing runtime claim |
| `ATTACKER_AND_USER_RUNBOOK.md` | Current guide/reference reconciled with actual source and explicit scope |
| `CHANGELOG.md` | Current guide/reference reconciled with actual source and explicit scope |
| `CONTRIBUTING.md` | Current guide/reference reconciled with actual source and explicit scope |
| `GETTING_STARTED.md` | Current guide/reference reconciled with actual source and explicit scope |
| `INCIDENT_RUNBOOK.md` | Current guide/reference reconciled with actual source and explicit scope |
| `INTEGRATION.md` | Current guide/reference reconciled with actual source and explicit scope |
| `LIMITATIONS.md` | Current guide/reference reconciled with actual source and explicit scope |
| `PRODUCTION.md` | Current guide/reference reconciled with actual source and explicit scope |
| `PRODUCT_VALIDATION.md` | Current guide/reference reconciled with actual source and explicit scope |
| `PROVENANCE.md` | Historical/source-bounded context; corrected current/fixture/incident inference where present |
| `README.md` | Current guide/reference reconciled with actual source and explicit scope |
| `RESEARCH_ASSESSMENT.md` | Current guide/reference reconciled with actual source and explicit scope |
| `RESUME_EVIDENCE.md` | Historical/source-bounded context; corrected current/fixture/incident inference where present |
| `RUNBOOK.md` | Current guide/reference reconciled with actual source and explicit scope |
| `SECURITY.md` | Current guide/reference reconciled with actual source and explicit scope |
| `SECURITY_AUDIT.md` | Historical/source-bounded context; corrected current/fixture/incident inference where present |
| `SECURITY_AUDIT_2026-09-30.md` | Historical/source-bounded context; corrected current/fixture/incident inference where present |
| `SECURITY_REVIEW_2026-09-30.md` | Historical/source-bounded context; corrected current/fixture/incident inference where present |
| `VERIFIED_METRICS.md` | Current guide/reference reconciled with actual source and explicit scope |
| `docs/API_VERSIONING.md` | Current guide/reference reconciled with actual source and explicit scope |
| `docs/EVIDENCE.md` | Current guide/reference reconciled with actual source and explicit scope |
| `docs/INSPECTOR.md` | Current guide/reference reconciled with actual source and explicit scope |
| `docs/PERFORMANCE_BASELINE.md` | Historical/source-bounded context; corrected current/fixture/incident inference where present |
| `docs/RECRUITER_EVIDENCE_AUDIT_2026-10-09.md` | Historical/source-bounded context; corrected current/fixture/incident inference where present |
| `docs/TESTING.md` | Current guide/reference reconciled with actual source and explicit scope |
| `docs/internal/REPOSITORY_AUDIT.md` | Historical/source-bounded context; corrected current/fixture/incident inference where present |
| `docs/license-history/LICENSE-BEFORE-2026-10-13.txt` | Preserved legal text byte-for-byte; read for historical attribution, not reinterpreted |
| `docs/supply-chain/SIGNING.md` | Current guide/reference reconciled with actual source and explicit scope |
| `evidence/DETECTION_PROOF.md` | Historical/source-bounded context; corrected current/fixture/incident inference where present |
| `evidence/INCIDENT_REPORT.md` | Historical/source-bounded context; corrected current/fixture/incident inference where present |
| `poster/01_research_brief.md` | Historical cited source/metrics retained; current-head/independent-closure boundary explicit |
| `poster/02_claim_ledger.md` | Historical cited source/metrics retained; current-head/independent-closure boundary explicit |
| `poster/03_verified_metrics.md` | Historical cited source/metrics retained; current-head/independent-closure boundary explicit |
| `poster/13_reproducibility.md` | Historical cited source/metrics retained; current-head/independent-closure boundary explicit |
| `requirements.txt` | Preserved dependency/trigger text; read, not a passing runtime claim |
| `scanner/isolation/README.md` | Current guide/reference reconciled with actual source and explicit scope |

## Source relationships consulted

| Claim area | Actual source/test relationships |
|---|---|
| Versions, dependencies, CLI flags/exits/completeness/report fields | pyproject.toml; scanner/cli.py, models.py, config.py, formatters; tests/test_cli.py, test_completeness_invariant.py |
| Local API/worker and browser lifecycle | scanner/workbench/server.py, worker.py, app.js; tests/test_workbench.py; scripts/workbench_e2e.py |
| Remote auth/limits/allowlist/timeout | scanner/service.py; tests/test_service.py, test_service_security_hardening.py |
| Optional signatures/SBOM/baselines/runtime monitor | scanner/provenance.py, aibom_generator.py, temporal/monitor sources and corresponding tests |
| Webhook/precommit/Make/signing/publish contract | integrations/huggingface_webhook.py; .pre-commit-hooks.yaml; Makefile; current checked-in workflows |
| Historical/curated metrics and chronology | cited source/run IDs, committed fixture reports and dated provenance; external private/third-party assertions remain unverified |
| Portable executor versus actual local worker | scanner/isolation/executor.py, profiles and tests/test_executor.py; separate scanner/workbench implementation |

## Executed and unverified scope

### Hosted build follow-up

The original documentation-only head was `b392acc0dfe412c369500130c525e2618e4875e3`. Its hosted jobs exposed a drawsvg 2.5.0 import failure through the optional ATT&CK integration and a genuine poster-byte mismatch after unpinned renderer dependencies changed. The parent added `constraints-optional.txt` with the exercised drawsvg 2.4.2 version to CI/Production Gate and the optional-install instructions. Poster CI now pins Python 3.12/PyMuPDF 1.26.6 and uploads genuine generated artifacts with source/outcome/hashes. The strict PNG parity assertion, scanner rules, test assertions and security thresholds are preserved. These build/configuration changes extend the original documentation-author scope; they require fresh final-head checks and do not make the failed earlier jobs pass retroactively.

Actual checks and failed attempts are retained out of tree with commands/exits/source observations. Documentation checks distinguish Bash/JSON syntax from actual benign CLI/local-API invocation; a synthetic input is statically inspected, never loaded/imported/executed. Current local links/anchors and tracked-file/config parsing are checked. External HTTP 200 establishes reachability only, not linked claim truth, external fragments or historical chronology.

Poster outputs are real HTML→ChromiumPDF→hostPyMuPDF PNG artifacts. A build-only external wrapper supplies the exact trusted own generated HTML through normal Playwright set_content; no HOME, browser policy or product security control changes. Repeated PNGs compare byte-for-byte; PDF metadata may differ. This does not guarantee hosted Chrome/font parity; any hosted bot commit must be incorporated and the actual resulting head verified before promotion.

No live HF/cloud request, account/key creation, registry signing/publishing, notification, external security payload execution, namespace/cgroup/host-policy modification or provider credential validation was performed. Optional remote integrations, artifact signatures, general CLI containment and production image runtime are not made passing by this documentation update. Full frozen-head regression, browser, audit/build and hosted proofs belong to the parent's later generated source-scoped manifest.

All published historical data stays scoped to its date/source/corpus. Representative accuracy/throughput, customer adoption, external incident details/private lineage, clean-machine deployment and operational/privacy/recovery approval still require their original prerequisites and evidence. See [EVIDENCE.md](EVIDENCE.md) and [LIMITATIONS.md](../LIMITATIONS.md).
