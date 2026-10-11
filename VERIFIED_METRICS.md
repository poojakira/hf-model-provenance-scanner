# Verified Metrics

## Later hosted CI confirmation — 2026-10-09

The most recent independently inspected hosted Python 3.12 result as of this evidence review is [CI run 38002138828](https://github.com/poojakira/hf-model-provenance-scanner/actions/runs/38002138828) at main commit `2f937ba51f31c678e43a064e95d6939e3feb9226`: **260 passed, 1 skipped, 6 subtests passed, 75.67% statement coverage**. Lint, type checking, security audit and Docker-build jobs also passed. The older snapshot and its original evidence anchor below are retained for the historical poster. Fixture-level results do not imply population-wide performance.

## Archived cited snapshot

## Latest quantified verified snapshot

**Code commit:** `251a7b90fd60fa1884c643adda9d96cd7801abe6`  
**Successful CI:** https://github.com/poojakira/hf-model-provenance-scanner/actions/runs/37163168715

| Claim | Verified snapshot value | Evidence boundary |
|---|---:|---|
| Automated tests | **241 passed, 1 skipped** | Python 3.12 cited CI snapshot |
| Additional pytest subtests | **6 passed** | Same CI |
| Statement coverage | **75.67%** | Python 3.12 CI |
| Coverage gate | **75%** | Repository CI policy |

The cited CI snapshot also completed lint/format, type checks, Bandit, pip-audit, CodeQL, container scanning, unsafe-dynamic-execution rejection, and Docker build checks successfully.

## Fixture boundary

Detection proof files and curated red-team fixtures are regression evidence. They must not be stated as a universal detection rate or universal false-positive rate.

## Reproduce

```bash
git checkout 251a7b90fd60fa1884c643adda9d96cd7801abe6
python -m pip install -e ".[dev,service]"
pytest tests/ -q --cov=scanner --cov-report=term
```
