# Release assessment: hf-model-provenance-scanner

SOURCE: `ab26ad5cd6fe28ae1b0986e20da46be9ebb2f27a`  
BRANCH: `codex/local-workbench-20261116`  
ASSEMBLED UTC: 2026-11-19T00:50:25.128523+00:00  
DECISION: **PARTIAL**. No software release, main merge or public full-app deployment is approved by this assessment.

ML and supply-chain reviewers inspect one or two supported local artifacts through the actual sealed static worker. Hash, metadata, structure and concern evidence can be compared without loading a model.

## Working entry points

- [Current source README and exact local prerequisites/launch](https://github.com/poojakira/hf-model-provenance-scanner/blob/ab26ad5cd6fe28ae1b0986e20da46be9ebb2f27a/README.md)
- [Free CPU guided notebook](https://colab.research.google.com/github/poojakira/hf-model-provenance-scanner/blob/codex/local-workbench-20261116/notebooks/try_product.ipynb) — public page HTTP 200; actual committed cells passed locally from a fresh public checkout, **hosted Colab kernel NOT VERIFIED**.
- [Readable overview](https://github.com/poojakira/hf-model-provenance-scanner/blob/ab26ad5cd6fe28ae1b0986e20da46be9ebb2f27a/docs/architecture/overview.svg), [detailed source-mapped architecture](https://github.com/poojakira/hf-model-provenance-scanner/blob/ab26ad5cd6fe28ae1b0986e20da46be9ebb2f27a/docs/ARCHITECTURE.md), and locally served zoom/pan viewer in `docs/index.html`.

Actual tiny synthetic SafeTensors: identical bytes, changed weights and changed metadata. Hash/structure differences are computed, not model safety scores.

The full browser UI remains a local application with its own documented supported inputs. Notebook fixtures do not establish representative field detection, a public hosted full UI, continuous monitoring or multi-user isolation. GitHub Pages configuration failed with HTTP403 "Resource not accessible by integration"; no working Pages URL is asserted. No Render/HF compute resource, paid service, billable provider API call or new credential was used. Existing optional cloud/deployment templates can cost money if separately enabled; see `cost-and-access-audit.json`.

## Fresh execution evidence

The clean candidate has **317 passed, 3 skipped, 0 failed and 0 errors** across 320 individual testcases. Local statement/line coverage is **76.08318891%** (3073/4039); recorded gate 75. Native subtests: {'failed': 0, 'passed': 6, 'skipped': 0}. Separate Python3.10 focused execution: {'individual_cases': 57, 'passed': 57, 'failed': 0, 'skipped': 0}. Focused/optional/native/browser observations are not added to the individual full-suite total.

See `manifest.json`, `primary-run-manifest.json` where present, `tests-run.json` for Aegis, `executed-test-inventory.json`, original logs, and `browser/` for exact commands, execution times, clean source, environments, skip reasons and actual screenshots/exports. Required named local gates passed. No check threshold was reduced. Installed-wheel execution uses an unrelated Git project and verifies UNKNOWN instead of inheriting its HEAD.

Current hosted runs: 5 observed; all successful: True. `remote-ci/status.json` records actual URLs and statuses. The downloaded acceptance ZIP digest and every embedded artifact hash were independently recomputed locally; the manifest identifies this exact clean source. Hosted coverage is kept in remote-ci/hosted-manifest.json and is not substituted for local coverage. No publishing workflow or release was invoked.

Both earlier closing-review attempts stopped with the exact service error: "This content was flagged for possible cybersecurity risk." No retry, reviewer rerouting or bypass was used. Current regression, documentation and benign format checks do not replace that missing independent closure. Three primary skips and six passing native subtests are reported separately. Five optional mapping/reporter checks ran in a separate isolated prerequisite environment; they are not added to the primary total.

## File, documentation, branch and security audit

216 tracked files were inventoried with SHA256 and per-type validation; all current local documentation target checks, 6 SVG XML parses, notebook JSON/compiled cells and viewer JavaScript syntax passed. Actual viewer controls and every diagram loaded in desktop/mobile Chromium with no page errors. Four sequential product documentation reviewers inspected architecture symbols/enforcement/limits; the parent corrected remaining source mismatches and readability. Historical documents/artifacts retain their dated source bounds. This audit does not certify every external link's factual content, chronology, optional toolchain or cloud/deployment command.

Only `main` and `codex/local-workbench-20261116` remain as remote branches at recorded readback. Main remains `f4fe1da87755da3ed97f7f0faf09c17e40f545e9`. 5 additional tips were preserved in verified annotated recovery tags and a private verified bundle before exact-lease atomic deletion. 5 associated PRs are closed without merging their unreviewed changes. Unique security/cross-language work remains recoverable, not advertised as current functionality. Restore commands, tag/SHA pairs and final PR states are in `branch-disposition.json`. Tags are not extra branches. Future dependency automation may create branches; its protections were not disabled.

The reviewed offline Gitleaks scan covered all local Git refs/history, including recovery history, with redaction and default detectors. It produced 51 historical generic-rule occurrences, explicitly classified in `secret-history-triage.json`; no confirmed provider credential was found in that reviewed scope. Current tracked-file scanning found no new heuristic secret values. Hashes, public signing fingerprints and intentional synthetic/local test examples are distinguished from provider credentials. No live credential validation, suppression baseline or absolute secret-absence claim is made. Private raw history/author context, backups, product credentials, session tokens and real patient/user data are excluded from publication.

## Independent review boundary and remaining release gates

Historical focused independent security reviews remain attached to their real earlier source. Current whole-suite/browser/build/type/security checks were freshly executed by the parent. Documentation role separation is not a newly completed independent adversarial closing review at this candidate. HF's explicit blocked review remains blocked, with no bypass or reroute. No perfect/production-ready claim is justified.

- Independent closing security review remains BLOCKED; no current independent PASS is claimed.
- Publisher identity, training lineage, behavioral safety, semantic model equivalence and absence of backdoors cannot be established by these static checks.
- Large production artifacts, archive extraction, complete GGUF payload/quantization validation and exhaustive fuzz/mutation assurance remain unsupported or NOT VERIFIED.
- Authenticated public hosting, complete environment locks and deployment-specific privacy/operations/recovery approval are NOT VERIFIED.

`product-matrix.json` maps current implementation/evidence and gaps. `executed-test-inventory.json` identifies actual positive/negative/recovery cases and skipped checks. A new current-source independent review, the missing product-specific acceptance gates and deployment-specific signoff would be required to change this decision.

NEXT SAFE ACTION: review the existing draft PR and the source-scoped archive; complete the listed acceptance gates. Any later source change requires fresh applicable regression/browser/security evidence.
