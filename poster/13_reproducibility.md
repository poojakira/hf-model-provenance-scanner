> **Historical research poster, October 14, 2026 UTC.** Its measurements apply to source `09aaa224776b8de0e53315a63c260eb3229bf9ac` and the [associated GitHub Actions run](https://github.com/poojakira/hf-model-provenance-scanner/actions/runs/38498005353). See the [later candidate manifest](https://raw.githubusercontent.com/poojakira/hf-model-provenance-scanner/ed25d66b72e374f86e2975930b0ed83b9acf3c09/release-evidence/manifest.json) for separately scoped local verification.

# Reproduce the Work — HF Provenance Scanner Poster 03

**Poster code snapshot:** `09aaa224776b8de0e53315a63c260eb3229bf9ac`
**Successful Python 3.12 main CI:** [run 38498005353](https://github.com/poojakira/hf-model-provenance-scanner/actions/runs/38498005353) (October 14, 2026 UTC)

```bash
git clone https://github.com/poojakira/hf-model-provenance-scanner.git
cd hf-model-provenance-scanner
git checkout 09aaa224776b8de0e53315a63c260eb3229bf9ac
python -m pip install -e ".[dev,service]"
pytest tests/ -q --cov=scanner --cov-report=term
```

Expected **260 passed, 1 skipped, 6 subtests passed, 75.67% coverage**. The 33/33 curated adversarial-fixture result is separate regression evidence, not population-level recall.

The archived original poster run [37163168715](https://github.com/poojakira/hf-model-provenance-scanner/actions/runs/37163168715) at `251a7b90fd60fa1884c643adda9d96cd7801abe6` recorded **241 passed**, 1 skipped, and is not this poster's cited snapshot.

Use a clean checkout at the poster SHA when reproducing these figures. Record test failures and skips, tool versions, coverage configuration, and digests with any newly generated evidence.
