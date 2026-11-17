# Read-only forensic baseline: poojakira/hf-model-provenance-scanner

UTC: 2026-11-17T02:26:33.787101+00:00. Audit role: independent forensic reviewer. Decision: PARTIAL baseline; product release NOT VERIFIED.

## Repository identity

Authoritative connected-account match: `poojakira/hf-model-provenance-scanner`; public; remote `https://github.com/poojakira/hf-model-provenance-scanner.git`; default `main`; HEAD `f4fe1da87755da3ed97f7f0faf09c17e40f545e9`. Full fetched reachable history contains 333 commits; no shallow clone, no source/remote mutation performed. No AGENTS.md found. Commit metadata and all reachable commit parents/dates/subjects: `git-baseline.json`, `history.txt`.

Initial checkout status: ''. MCP six trailing mixed-CRLF lines normalize on checkout under .gitattributes; preserved in normalization.patch. Do not attribute these to user edits. No reset or overwrite performed.

## Product baseline

Capabilities: Static local/remote CLI; dedicated pickle opcode, safetensors, GGUF and source analyzers; provenance and fingerprint/report utilities. Existing admission API calls real remote CLI and uses auth, size/rate/concurrency/time limits.

Gaps: Admission service accepts remote repository ID and requires API_KEY; it is not the required keyless local-artifact inspect/compare UI. Existing dashboards are not a local upload/compare workflow. Package version 0.2.0 versus service API version 1.0.0 needs scope explanation.

Risk: HIGH: hostile bytes must not be deserialized/executed; local upload path needs process resource/time/memory/byte limits and magic/extension agreement checks. Existing bounded remote thread timeout retains slot but does not terminate worker. Do not reuse --sandbox convenience runner (disabled for safety). Curated fixture results do not establish field detection accuracy.

Minimal complete journey: Select 1-2 bounded real local artifacts -> isolated static existing analyzers -> format/hash/metadata/findings -> comparison -> provenance/limitations export without network or deserialization.

Enforcement/source entrypoints: scanner/cli.py: scan_local, analyze_binary_file, analyze_source_file; scanner/analyzer/pickle_scanner.py static bytecode parser; scanner/analyzer/safetensors_scanner.py; scanner/analyzer/gguf_scanner.py; scanner/service.py: _authorize, _validate_target, _run_bounded, scan.

Recommended next milestone: Add independent local-only upload workbench preserving existing remote API auth. Reuse analyze_binary_file, fingerprint_file and format parsers in bounded isolated child. No HF download needed. Restore complete dependency environment before interpreting baseline CLI failures.

## Current CI and executable evidence

Main CI success run 39662892588 at f4fe1da8; dependency PR CI run 43909303205 SUCCESS at 6e52d20a. Retrieved historical metadata, not fresh release evidence.

Fresh local command (from repository root):

```sh
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=. /workspace/work/tooling/venv/bin/python -m pytest -p no:cacheprovider tests/test_pickle_scanner.py tests/test_safetensors_scanner.py tests/test_gguf_scanner.py -q --junitxml=/workspace/work/audit/hf-model-provenance-scanner/baseline-junit.xml
```

Result: 32 passed, 2 failed, 0 skipped. Both failing CLI subprocess checks produced empty JSON stdout; direct python -m scanner.cli --help confirms ModuleNotFoundError: psutil in generic audit venv. Environment prerequisite failure, not established engine defect. No coverage measured. Actual captured output: baseline-tests.log; JUnit: baseline-junit.xml. Tests were run from original main source in audit tooling venv; this is not a candidate release run. Python 3.12.14; Node 24.22.1; Linux. Generic tooling venv is not the complete pinned product dependency environment. Exact run timestamps/counts are in JUnit. Final candidate tests, full regression, browser E2E, supply-chain audit, container build and release validation are NOT VERIFIED. Do not treat retrieved historic CI as fresh evidence.

## File inventory and validation

Every tracked default-branch path inventoried: **177**. `inventory.json` records path, size, SHA256, type, symlink state, AST/JSON syntax validation; `tracked-files.txt` is complete path list. Python AST syntax and tracked JSON parsing completed with 0 errors. `configuration-validation.json` records safe TOML and shell syntax checks. `documentation-inventory.json` inventories 33 text documentation files and candidate broken local links; external URLs, anchors, all facts/examples and media visual accessibility remain NOT VERIFIED. `workflow-audit.json` records source workflow pin/permissions indicators; parser/trigger and gate semantics need final review. No arbitrary tracked binary/executable or model was executed. Binary fixture hashes are inventory evidence, not proof of safety. No submodules. Test classes inferred from source include unit, integration, negative/adversarial; exact taxonomy and coverage exclusions must be reviewed for candidate.

All tracked-file semantic/security review is NOT COMPLETE. All remote branch tips have diff-stat and changed-path evidence; only selected important source paths were reviewed semantically. This records the audit boundary rather than falsely claiming every historical branch file/claim was verified.

## Branch governance

All refs preserved. Ahead/behind are ancestry counts, not evidence that squash-merged content is missing. No branches merged/deleted; none is yet DELETE ELIGIBLE. Full unique commit lists are in git-baseline.json. PR metadata latest first-page stored in github-prs.json (max 100; older pagination not yet exhausted). Open PRs visible in first page retained. Tags: none. Releases: none returned. Rulesets: empty returned. Branch-protection inspection BLOCKED by GitHub integration 403; lack of visibility does not establish absent protection. Workflow collection endpoint was rejected; checked-in workflow sources and action-run endpoints were read.

| Ref | SHA | Ahead / behind main | Disposition | Related PR |
|---|---|---:|---|---|
| `refs/heads/main` | `f4fe1da87755da3ed97f7f0faf09c17e40f545e9` | 0 / 0 | KEEP |  |
| `refs/remotes/origin/HEAD` | `f4fe1da87755da3ed97f7f0faf09c17e40f545e9` | 0 / 0 | KEEP |  |
| `refs/remotes/origin/dependabot/github_actions/actions/setup-python-7.1.0` | `6e52d20aa40e85d1eb916549fef5390857fb6b53` | 1 / 0 | HOLD FOR REVIEW | #102 open |
| `refs/remotes/origin/dependabot/github_actions/docker/login-action-4.8.0` | `628f7aec82a05ecc634a14aefdcb73b59a64244e` | 1 / 0 | HOLD FOR REVIEW | #100 open |
| `refs/remotes/origin/dependabot/github_actions/github/codeql-action/analyze-4.39.3` | `82eaf883dfe598d97750fdd2acdb090795ecc7a0` | 1 / 0 | HOLD FOR REVIEW | #98 open |
| `refs/remotes/origin/dependabot/github_actions/github/codeql-action/upload-sarif-4.39.3` | `b6cc8ec099c35aebe80c3219536f4577f224d3f4` | 1 / 0 | HOLD FOR REVIEW | #99 open |
| `refs/remotes/origin/dependabot/github_actions/sigstore/cosign-installer-4.1.3` | `409d74500438842fb8e6f8813cab424db2e9c552` | 1 / 0 | HOLD FOR REVIEW | #101 open |
| `refs/remotes/origin/main` | `f4fe1da87755da3ed97f7f0faf09c17e40f545e9` | 0 / 0 | KEEP |  |

## Phase report

PRODUCT: poojakira/hf-model-provenance-scanner
SOURCE: f4fe1da87755da3ed97f7f0faf09c17e40f545e9 BRANCH: main UTC: 2026-11-17T02:26:33.787101+00:00
PHASE: 0 forensic baseline
DONE: complete default tracked-path/hash inventory; reachable refs/history; selected engine/UI/docs/workflow analysis; raw provider evidence.
EXECUTED: command above; safe Python AST/JSON/TOML/bash syntax checks; git read-only inventory; GitHub GET metadata.
RESULTS: 32 passed, 2 failed, 0 skipped. Both failing CLI subprocess checks produced empty JSON stdout; direct python -m scanner.cli --help confirms ModuleNotFoundError: psutil in generic audit venv. Environment prerequisite failure, not established engine defect. No coverage measured.
NEGATIVE / ADVERSARIAL TESTS: focused existing tests named by command; no new full acceptance attack matrix executed.
CLAIMS VERIFIED: source existence and selected behavior only; see checks above.
CLAIMS RETRACTED: no source changes during audit; unsupported/stale claims flagged above for implementation/docs reviewer.
BRANCH CHANGES: none; all KEEP or HOLD FOR REVIEW.
RISKS / BLOCKERS: incomplete release acceptance and provider protection visibility; product-specific items above.
DECISION: PARTIAL baseline; NOT VERIFIED release.
NEXT SAFE ACTION: Add independent local-only upload workbench preserving existing remote API auth. Reuse analyze_binary_file, fingerprint_file and format parsers in bounded isolated child. No HF download needed. Restore complete dependency environment before interpreting baseline CLI failures.
