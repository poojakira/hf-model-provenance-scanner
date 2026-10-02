# Reproduce the Work - Poster 03

**Repository:** `github.com/poojakira/hf-model-provenance-scanner`
**Verified code snapshot:** `d3907462284c12deb701210fa7fb7bd8ab109ba0`
**CI run:** `36944320100`

```bash
git clone https://github.com/poojakira/hf-model-provenance-scanner.git
cd hf-model-provenance-scanner
git checkout d3907462284c12deb701210fa7fb7bd8ab109ba0
python -m pip install -e ".[dev,service]"
pytest tests/ -q --cov=scanner --cov-report=term
```

Expected evidence at the cited CI snapshot:

- **241 passed**
- **1 skipped**
- **6 subtests passed**
- **75.81% statement coverage**
