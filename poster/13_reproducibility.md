# Reproduce the Work — HF Provenance Scanner Poster 03

**Current code snapshot:** `09aaa224776b8de0e53315a63c260eb3229bf9ac`  
**Successful Python 3.12 main CI:** [run 38498005353](https://github.com/poojakira/hf-model-provenance-scanner/actions/runs/38498005353) (October 14, 2026 UTC)

```bash
git clone https://github.com/poojakira/hf-model-provenance-scanner.git
cd hf-model-provenance-scanner
git checkout 09aaa224776b8de0e53315a63c260eb3229bf9ac
python -m pip install -e ".[dev,service]"
pytest tests/ -q --cov=scanner --cov-report=term
```

Expected **260 passed, 1 skipped, 6 subtests passed, 75.67% coverage**. The 33/33 curated adversarial-fixture result is separate regression evidence, not population-level recall.

The archived original poster run [37163168715](https://github.com/poojakira/hf-model-provenance-scanner/actions/runs/37163168715) at `251a7b90fd60fa1884c643adda9d96cd7801abe6` recorded **241 passed**, 1 skipped, and is not the active poster run.
