# Verified Metrics

## Recent hosted CI references (distinct commit scopes)

- **October 13, 2026 — main push:** [successful run 38487400153](https://github.com/poojakira/hf-model-provenance-scanner/actions/runs/38487400153) at commit `ea9f1b3048a8eb84fc563b246ed008b360aafa24`. This records CI completion; do not infer unstated test totals from its status alone.
- **October 13, 2026 — pull-request check:** [successful run 38462464074](https://github.com/poojakira/hf-model-provenance-scanner/actions/runs/38462464074) at commit `4304853a76ba8a687c2ee29204ad45429de7c55d`; documented Python 3.12 result **260 passed, 1 skipped, 6 subtests, 75.67% statement coverage**. This is a PR event, not the current main commit.
- **October 9–10, 2026 — earlier main:** [successful run 38002138828](https://github.com/poojakira/hf-model-provenance-scanner/actions/runs/38002138828) at commit `2f937ba51f31c678e43a064e95d6939e3feb9226`; **260 passed, 1 skipped, 6 subtests, 75.67% statement coverage**, separately documented for that snapshot.

## Historical poster evidence — October 3, 2026

**Code commit:** `251a7b90fd60fa1884c643adda9d96cd7801abe6`  
**Successful CI:** https://github.com/poojakira/hf-model-provenance-scanner/actions/runs/37163168715

| Claim | Historical pinned poster snapshot | Evidence boundary |
|---|---:|---|
| Automated tests | **241 passed, 1 skipped** | October 3 CI, not the current main |
| Additional pytest subtests | **6 passed** | Same pinned snapshot |
| Statement coverage | **75.67%** | Python 3.12 snapshot |
| Coverage gate | **75%** | Repository CI policy |

## Fixture boundary

Curated committed malicious and benign fixtures are regression evidence only. A **33/33** curated fixture result is not a universal detector recall, and **0 actionable findings across 4 benign samples** is not a population-level false-positive rate.

## Reproduce the historical poster snapshot

```bash
git checkout 251a7b90fd60fa1884c643adda9d96cd7801abe6
python -m pip install -e ".[dev,service]"
pytest tests/ -q --cov=scanner --cov-report=term
```
