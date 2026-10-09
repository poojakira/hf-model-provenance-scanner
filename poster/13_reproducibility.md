# Reproduce the Work - Poster 03

**Repository:** `github.com/poojakira/hf-model-provenance-scanner`
**Verified code snapshot:** `251a7b90fd60fa1884c643adda9d96cd7801abe6`
**CI run:** `37163168715`

```bash
git clone https://github.com/poojakira/hf-model-provenance-scanner.git
cd hf-model-provenance-scanner
git checkout 251a7b90fd60fa1884c643adda9d96cd7801abe6
python -m pip install -e ".[dev,service]"
pytest tests/ -q --cov=scanner --cov-report=term
```

Expected evidence at the cited CI snapshot:

- **241 passed**
- **1 skipped**
- **6 subtests passed**
- **75.67% statement coverage**
