# Executable verification

Run from a clean candidate checkout after the README install. These are required commands, not claimed results. Generated evidence belongs outside the source tree.

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

Additional gates: Pyright 1.1.388 across scanner with actual optional dependency when available; Bandit 1.9.4 medium/high; pip-audit 2.10.1 against pinned requirements; actionlint 1.7.7; tracked-file inventory/type parsing and local documentation links; wheel installation/startup from a directory outside this Git tree. Record command, UTC, tool versions, exit status, test pass/fail/skip and artifact hashes. Container/CodeQL/hosted CI executions require their actual environments and must remain NOT VERIFIED when not run. Never infer those passes from local equivalents.
