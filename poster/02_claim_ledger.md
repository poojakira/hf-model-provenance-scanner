# Claim Ledger — Poster 03 (03-hf-model-provenance-scanner)

> Evidence status: This is a dated repository snapshot at the commit identified below. `VERIFIED_AT_SNAPSHOT` means verified for that commit and environment; it does not assert the same result on the latest `main`. Compare newer claims with the repository evidence before reuse.

Apache-2.0 • Python 3.12 • HEAD 13a5ae4 • verified 2026-09-26. Classification: VERIFIED_AT_SNAPSHOT / VERIFIED_HISTORICAL / PARTIAL / UNVERIFIED / UNSUPPORTED.

| # | Claim | Classification | Evidence |
|---|---|---|---|
| 1 | 33/33 committed fixtures detected; 0 actionable FP on 4 benign | VERIFIED_AT_SNAPSHOT | evidence/DETECTION_PROOF.md + tests/redteam/redteam_report.json; pinned by test_detection_counts.py. Fixture-only. |
| 2 | 5 binary format parsers; 5 analysis engines | VERIFIED_AT_SNAPSHOT | README/LIMITATIONS.md enumerate pickle/SafeTensors/GGUF/ONNX/Keras and AST/taint/symbolic/sandbox(disabled)/binary. |
| 3 | Fail-loud HFS-096 INDETERMINATE on unanalyzable pickle | VERIFIED_AT_SNAPSHOT | LIMITATIONS.md; elevates risk >=HIGH; --enforce nonzero exit. |
| 4 | 211 passed + 6 subtests; 66.9% coverage | VERIFIED_HISTORICAL | CI run 36043740861 (751a62a, 2026-09-24), Py 3.11/3.12. Not re-run at current HEAD. |
| 5 | General detection rate / 0% FP on arbitrary models | UNSUPPORTED (disclaimed) | README + DETECTION_PROOF scope note forbid generalizing fixture results; not claimed. |
| 6 | Neural weight backdoor detection | UNSUPPORTED (disclaimed) | LIMITATIONS.md lists as fundamental non-capability. |

## Policy applied
- Only VERIFIED_AT_SNAPSHOT figures appear as prominent current results.
- Historical/projected values are labeled (dashed box / explicit note).
- Unsupported production/accuracy claims are omitted or shown in the red "NOT ESTABLISHED" box.
