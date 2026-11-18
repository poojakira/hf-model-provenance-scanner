# Executable verification

Run from a clean candidate checkout after the README install. These are required commands, not claimed results. Generated evidence belongs outside the source tree.

For the optional ATT&CK integration, apply the reviewed compatibility constraint when resolving that extra:

```sh
PIP_CONSTRAINT="$PWD/constraints-optional.txt" .venv/bin/python -m pip install -e '.[attack]'
```

The constraint retains drawsvg 2.4.2 because CI reproduced an import-time `SyncedAnimationConfig` error with 2.5.0. It is not a complete transitive dependency lock. The primary local-inspector lock and unchanged security/coverage checks remain separate. The poster workflow pins Python 3.12/PyMuPDF 1.26.6, enforces exact PNG parity and preserves generated files plus actual source/render-outcome/hashes for diagnosis.

```sh
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest tests -q -p pytest_cov --cov=scanner --cov-report=xml:/tmp/hf-coverage.xml --cov-fail-under=75 --junitxml=/tmp/hf-junit.xml
.venv/bin/ruff check . .github/scripts
.venv/bin/ruff format --check . .github/scripts
.venv/bin/python -m build --outdir /tmp/hf-dist
node --check scanner/workbench/app.js
bash -n install.sh
```

The existing 75% whole-scanner coverage gate is preserved. Subprocess/seccomp checks execute real containment, while direct pure-parser tests provide measured parser coverage without allowing coverage writes through the worker’s syscall filter. No global skip/coverage exclusion was added. Optional external ATT&CK package/data checks may skip if prerequisites are absent; report them separately. Existing unrelated network API tests use controlled fixtures/mocks where defined in their source. They do not prove a live remote integration.

`tests/test_workbench.py` covers actual existing rule results, nonexecution sentinels, supported structures/hash comparison, malformed/duplicate/non-finite headers, trailing polyglots, dimensions, archive rejection, GGUF truncation/nested arrays, API origin/token/path/schema/size/concurrency, real syscall denial (open/socket/exec/fork), actual stdout/stderr flooding, timeout/reaping and recovery. The bounded deterministic malformed corpus is not a field accuracy or comprehensive fuzzing claim.

Browser acceptance requires Playwright 1.65.2 or the verified environment’s exact pinned version and a Chromium binary. Use the version pinned in requirements-browser.lock, then:

```sh
.venv/bin/python -m pip install -r requirements-browser.lock
HF_BROWSER_EXECUTABLE=/usr/bin/chromium .venv/bin/python scripts/workbench_e2e.py --evidence /tmp/hf-browser
```

Without HF_BROWSER_EXECUTABLE, install the pinned Playwright Chromium (`.venv/bin/python -m playwright install chromium`); the script uses it by default. The script launches the real server with the active interpreter, selects actual files, compares/reruns, verifies downloaded report checksums, checks stale-read/response behavior, captures desktop/mobile and records browser failures. It stops its own server. Inspect screenshots visually; automated viewport checks are not a full accessibility audit.

Additional gates: Pyright 1.1.388 across scanner with actual optional dependency when available; Bandit 1.9.4 medium/high; pip-audit 2.10.1 against pinned requirements; actionlint 1.7.7; tracked-file inventory/type parsing and local documentation links; wheel installation/startup from a directory outside this Git tree. Record command, UTC, tool versions, exit status, test pass/fail/skip and artifact hashes. Container/CodeQL/hosted CI executions require their actual environments. The published16ff implementation run has its own five passing workflows and Docker build, without a product-container runtime claim. A later documentation head needs fresh records; never infer those passes from prior or local equivalents.


## Count outcomes and prerequisites honestly

At implementation source 16ff, the primary run recorded 312 passed, 3 skipped, 6 passing native subtests. JUnit's native subtest aggregation included321 suite outcomes while there were315 individual testcase nodes. Do not call that 321 independent cases or 318 passes. Count individual outcomes and native subtests separately. The three skips concern optional ATT&CK mapping/reporter prerequisites and Windows-specific behavior; they are not passing checks. Five optional mapping/reporter tests ran in another environment and must remain separate from the primary count. A TestClient deprecation warning was retained.

Optional ATT&CK tests need the actual reviewed attack-v19-core package and matching checksummed data. The implementation proof used exact core 76cf874cd6d8a012c20a76efc06b44907663751d and official v19.2 bundles; a nominal compatible package version alone is not that proof. Do not modify dependency source or override a managed read-only HOME. Where a tool requires a writable native HOME, use a separate isolated runtime with an ephemeral writable location at its existing HOME and record actual scope. No paid service/new provider key is needed.

Independent security closure is BLOCKED by the review service; this documentation pass must not retry or relabel it. Current engineering tests and source-bound independent historical results remain distinct. See [EVIDENCE.md](EVIDENCE.md). The document audit's shell syntax/JSON checks are not execution of external deployment or malformed-artifact operations. Unsafe/unavailable examples retain explicit prerequisites rather than fabricated green results.
