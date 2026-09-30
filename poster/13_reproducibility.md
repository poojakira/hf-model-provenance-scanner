# Reproduce the Work - Poster 03

**Repository:** `github.com/poojakira/hf-model-provenance-scanner`  
**Verified code snapshot:** `4501739a724a2a0a7de9173e51af535b192bf0e4`  
**CI run:** `36782472264`

```bash
git clone https://github.com/poojakira/hf-model-provenance-scanner.git
cd hf-model-provenance-scanner
git checkout 4501739a724a2a0a7de9173e51af535b192bf0e4
python -m pip install -e ".[dev,service]"
pytest tests/ -q --cov=scanner --cov-report=term
```

Expected current-main CI evidence:

- **231 passed**
- **1 skipped**
- **6 subtests passed**
- **68.00% statement coverage**
