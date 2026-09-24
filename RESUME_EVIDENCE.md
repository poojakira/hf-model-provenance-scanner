# Resume Evidence

This file documents the quantitative claims used on Pooja Kiran's resume and distinguishes the frozen resume snapshot from later CI totals.

## Resume snapshot

The resume uses:

- **195 passing tests**
- **12/12 core incident reproductions detected**
- **18/18 extended variants detected**
- **0 actionable false positives across four committed benign samples**

### 195 passing tests

The **195** figure is a conservative historical local-validation snapshot recorded in the committed `RUNBOOK.md` at commit:

`267618d3f7799d70c8c8d85b079f4a39d211aefa`

That runbook records:

```text
pytest tests/ is green: 195 passed, 2 skipped, 6 subtests passed
```

The documented environment was Windows 11 / PowerShell / Python 3.12.10.

Important reconciliation: the repository has continued to grow after this snapshot. Current main CI is tracked separately in `VERIFIED_METRICS.md`; the resume's 195 figure remains a lower historical snapshot, not a claim about the present test suite.

It should not be represented as the latest CI total. The latest verified total is higher.

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

## Current repository state

Current main CI evidence is stronger than the frozen resume snapshot: **214 passed, 1 skipped, 6 subtests passed** and **66.16% statement coverage** at commit `c0fa6b18d1d2715f5d275d291021b3208d836dd9` (run `35808366562`).

The resume remains defensible because its 195 figure is a documented historical lower-bound snapshot and the fixture claims remain tied to committed evidence.
