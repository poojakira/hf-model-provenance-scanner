# Verified Metrics

## Current verified snapshot

**Code commit:** `4501739a724a2a0a7de9173e51af535b192bf0e4`  
**Successful CI:** https://github.com/poojakira/hf-model-provenance-scanner/actions/runs/36782472264

| Claim | Current value | Evidence boundary |
|---|---:|---|
| Automated tests | **231 passed, 1 skipped** | Python 3.12 current-main CI |
| Additional pytest subtests | **6 passed** | Same CI |
| Statement coverage | **68.00%** | Python 3.12 CI |
| Coverage gate | **55%** | Repository CI policy |

Current CI also completed lint/format, type checks, Bandit, pip-audit, CodeQL, container scanning, unsafe-dynamic-execution rejection, and Docker build checks successfully.

## Fixture boundary

Detection proof files and curated red-team fixtures are regression evidence. They must not be stated as a universal detection rate or universal false-positive rate.

## Reproduce

```bash
git checkout 4501739a724a2a0a7de9173e51af535b192bf0e4
python -m pip install -e ".[dev,service]"
pytest tests/ -q --cov=scanner --cov-report=term
```
