> **Historical research poster, October 14, 2026 UTC.** Its measurements apply to source `09aaa224776b8de0e53315a63c260eb3229bf9ac` and the [associated GitHub Actions run](https://github.com/poojakira/hf-model-provenance-scanner/actions/runs/38498005353). See the [later candidate manifest](https://raw.githubusercontent.com/poojakira/hf-model-provenance-scanner/ed25d66b72e374f86e2975930b0ed83b9acf3c09/release-evidence/manifest.json) for separately scoped local verification.

# Claim Ledger - Poster 03

> Verified code snapshot: `09aaa224776b8de0e53315a63c260eb3229bf9ac`; successful CI run `38498005353`, run initiated 2026-10-14 UTC.

| # | Claim | Classification | Evidence |
|---|---|---|---|
| 1 | 260 passed, 1 skipped, 6 subtests passed | VERIFIED_AT_SNAPSHOT | Oct 14 2026 main CI run 38498005353, commit 09aaa224. |
| 2 | 75.67% statement coverage | VERIFIED_AT_SNAPSHOT | Python 3.12 CI at the cited snapshot. |
| 3 | Curated malicious fixture suite is detected by the committed proof harness | VERIFIED_AT_SNAPSHOT | Fixture evidence and regression tests; fixture-only scope. |
| 4 | Supported binary/model formats and static analysis engines are implemented | VERIFIED_AT_SNAPSHOT | Scanner modules and tests at the cited snapshot. |
| 5 | Unsafe dynamic execution is rejected by scanner tests | VERIFIED_AT_SNAPSHOT | Cited CI Reject Unsafe Dynamic Execution job. |
| 6 | Universal detection rate / universal 0% false-positive rate | UNSUPPORTED | Curated fixtures cannot establish population performance. |
| 7 | General neural-weight backdoor detection | UNSUPPORTED | Outside established repository capability. |

Do not convert fixture evidence into a real-world detection-rate claim.

## Interpretation

Curated benign and adversarial fixtures exercise configured static patterns and supported parsers. Their results establish regression behavior for that input set. Broader detection and false-positive rates require a representative evaluation.
