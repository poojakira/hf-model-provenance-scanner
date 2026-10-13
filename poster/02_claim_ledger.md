# Claim Ledger - Poster 03

> Verified code snapshot: `251a7b90fd60fa1884c643adda9d96cd7801abe6`; successful CI run `37163168715`, run initiated 2026-10-03 UTC.

| # | Claim | Classification | Evidence |
|---|---|---|---|
| 1 | 241 passed, 1 skipped, 6 subtests passed | VERIFIED_AT_SNAPSHOT | Cited Python 3.12 CI snapshot. |
| 2 | 75.67% statement coverage | VERIFIED_AT_SNAPSHOT | Python 3.12 CI at the cited snapshot. |
| 3 | Curated malicious fixture suite is detected by the committed proof harness | VERIFIED_AT_SNAPSHOT | Fixture evidence and regression tests; fixture-only scope. |
| 4 | Supported binary/model formats and static analysis engines are implemented | VERIFIED_AT_SNAPSHOT | Scanner modules and tests at the cited snapshot. |
| 5 | Unsafe dynamic execution is rejected by scanner tests | VERIFIED_AT_SNAPSHOT | Cited CI Reject Unsafe Dynamic Execution job. |
| 6 | Universal detection rate / universal 0% false-positive rate | UNSUPPORTED | Curated fixtures cannot establish population performance. |
| 7 | General neural-weight backdoor detection | UNSUPPORTED | Outside established repository capability. |

Do not convert fixture evidence into a real-world detection-rate claim.


## Claim audit and rendered-source boundary, October 13, 2026 UTC

The reviewed printed claims, source and test commit anchors, CI dates and benchmark limitations are in `verified_claims.json`. The PDF is generated from that manifest and the PNG is rasterized from the same page by `render_poster.py`. Source inventory, dated CI and separate reported experiments must not be combined into one result. Earlier artifact versions remain in Git history; these corrections do not assert production readiness.

Offline poster rendering: `python -m pip install reportlab==4.4.9 PyMuPDF==1.26.6`, then `python poster/render_poster.py`. The font is bundled with the pinned ReportLab package; no browser or network fetch is used during rendering.
