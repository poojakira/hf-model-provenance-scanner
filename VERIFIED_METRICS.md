# Verified Metrics

This file is the evidence anchor for quantitative résumé and portfolio claims about this repository.

## Verified baseline

**Audited code commit:** `751a62aeb7dbca97e2f4458dcc5be60086769ee3`
**Successful main CI run:** https://github.com/poojakira/hf-model-provenance-scanner/actions/runs/36043740861
**Verification date:** 2026-09-24

| Claim | Verified value | Evidence |
|---|---:|---|
| Automated tests | **211 passed** | Python 3.10/3.11/3.12 CI jobs `107782094870`, `107782094992`, `107782094737` |
| Additional pytest subtests | **6 passed** | Same CI jobs |
| Statement coverage | **66.90% on Python 3.11/3.12** | CI coverage reports; gate is 55% (Python 3.10: 68.14%) |
| Core incident fixtures | **12/12 detected** | `tests/redteam/redteam_report.json` + `evidence/DETECTION_PROOF.md` |
| Extended variants | **18/18 detected** | `tests/redteam/extended_report.json` + `evidence/DETECTION_PROOF.md` |
| Large-scale fixtures | **3/3 detected** | `tests/redteam/test_large_scale.py` |
| Actionable false positives in extended benign set | **0 across 4 benign samples** | `tests/redteam/extended_report.json` + `evidence/DETECTION_PROOF.md` |

## Claim boundary

The **33/33** aggregate is a committed internal fixture-suite result (12 core + 18 extended + 3 large-scale). It is **not** a general detection rate across arbitrary Hugging Face repositories.

Likewise, **0 actionable false positives across 4 benign samples** applies only to that small committed benign fixture set. It must not be restated as a universal 0% false-positive rate.

## Reproduce

Use the repository CI dependency set. Key checks are:

```bash
pytest tests/
python tests/redteam/simulate_attacks.py
python tests/redteam/extended_attacks.py
python tests/redteam/test_large_scale.py
```

The regression test `tests/redteam/test_detection_counts.py` pins the fixture counts so a change in the advertised detection totals fails tests.

When tests or fixture sets change, reconcile this file, `RUNBOOK.md`, the portfolio dashboard, and résumé wording together.
