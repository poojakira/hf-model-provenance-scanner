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


## Claim audit and rendered-source boundary, October 13, 2026 UTC

The reviewed printed claims, source and test commit anchors, CI dates and benchmark limitations are in `verified_claims.json`. The PDF is generated from that manifest and the PNG is rasterized from the same page by `render_poster.py`. Source inventory, dated CI and separate reported experiments must not be combined into one result. Earlier artifact versions remain in Git history; these corrections do not assert production readiness.

Offline poster rendering: `python -m pip install reportlab==4.4.9 PyMuPDF==1.26.6`, then `python poster/render_poster.py`. The font is bundled with the pinned ReportLab package; no browser or network fetch is used during rendering.
