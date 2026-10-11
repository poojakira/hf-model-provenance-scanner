# Resume Evidence

This file documents the quantitative claims used on Pooja Kiran's resume and distinguishes the frozen resume snapshot from later CI totals.

## Current portfolio resume snapshot (audited 2026-10-11)

The resume uses:

- **260 passing tests, 1 skipped, 6 additional pytest subtests passed**
- **75.67% statement coverage**
- **12/12 core incident reproductions detected**
- **18/18 extended variants detected**
- **0 actionable false positives across four committed benign samples**

### Historical 195 passing tests (not the current resume claim)

The **195** figure is an archived local-validation snapshot recorded in the committed `RUNBOOK.md` at commit:

`267618d3f7799d70c8c8d85b079f4a39d211aefa`

That runbook records:

```text
pytest tests/ is green: 195 passed, 2 skipped, 6 subtests passed
```

The documented environment was Windows 11 / PowerShell / Python 3.12.10.

Important reconciliation: the repository has continued to grow after this snapshot. Current main CI is tracked separately in `VERIFIED_METRICS.md`; that historical 195 figure is not the current resume test count, not a claim about the present test suite.

It should not be represented as the latest CI total or as the current resume total.

### 12/12 core and 18/18 extended fixtures

Committed sources:

- `tests/redteam/redteam_report.json`
- `tests/redteam/extended_report.json`
- `evidence/DETECTION_PROOF.md`
- `tests/redteam/test_detection_counts.py`

The committed evidence records:

- **12/12** core incident fixtures detected
- **18/18** extended variants detected
- **3/3** large-scale fixtures detected

### Zero actionable false positives across four benign samples

The extended fixture evidence records **0 actionable (non-INFO) false positives across four committed benign samples**.

This is deliberately narrow. It is **not** a claim of a universal 0% false-positive rate across arbitrary Hugging Face repositories or real-world model ecosystems.

## Repository state and evidence history

The latest quantified verification snapshot is stronger than the frozen resume snapshot and records **241 passed, 1 skipped, 6 additional pytest subtests passed, and 75.67% statement coverage**, as documented in `VERIFIED_METRICS.md`. This is a dated verification snapshot and should not be generalized beyond its cited code and environment. The resume's 195 figure remains a documented historical lower-bound snapshot.

The currently tracked portfolio resume source uses 260 passing tests and 1 skipped, consistent with the October 9, 2026 hosted CI result. Historical claims and fixture results remain scoped to their specific commits and samples.

## Current hosted verification reference

- Main commit: [`2f937ba51f31c678e43a064e95d6939e3feb9226`](https://github.com/poojakira/hf-model-provenance-scanner/commit/2f937ba51f31c678e43a064e95d6939e3feb9226)
- [GitHub Actions CI run 38002138828](https://github.com/poojakira/hf-model-provenance-scanner/actions/runs/38002138828), Python 3.12 job: **260 passed, 1 skipped, 6 subtests passed, 75.67% coverage**.
- These results are hosted test evidence, not a real-world detection rate or deployment claim.
