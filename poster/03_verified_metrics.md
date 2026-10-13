# Verified Metrics - Poster 03

**Code snapshot:** `251a7b90fd60fa1884c643adda9d96cd7801abe6`
**CI run:** https://github.com/poojakira/hf-model-provenance-scanner/actions/runs/37163168715

| Metric | Cited 2026 snapshot |
|---|---:|
| Tests passed | **241** |
| Tests skipped | **1** |
| Additional pytest subtests passed | **6** |
| Statement coverage | **75.67%** |
| CI coverage gate | **75%** |

Curated malicious/benign fixture results are regression evidence only. They are not a population-level detection rate or universal false-positive estimate.


## Claim audit and rendered-source boundary, October 13, 2026 UTC

The reviewed printed claims, source and test commit anchors, CI dates and benchmark limitations are in `verified_claims.json`. The PDF is generated from that manifest and the PNG is rasterized from the same page by `render_poster.py`. Source inventory, dated CI and separate reported experiments must not be combined into one result. Earlier artifact versions remain in Git history; these corrections do not assert production readiness.

Offline poster rendering: `python -m pip install reportlab==4.4.9 PyMuPDF==1.26.6`, then `python poster/render_poster.py`. The font is bundled with the pinned ReportLab package; no browser or network fetch is used during rendering.
