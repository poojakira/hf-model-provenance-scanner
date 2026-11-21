# Verification report

**LOCAL ONLY.** Tested source: 42c5f029d186ff5d49ba088909e1f0dfc229d776. Fixing source at report time: 2e77d42939cb09bd2e3a9f66c45e12d056550f35. Hosted observations in [audit findings](AUDIT_FINDINGS.md) identify their separate source SHAs.

Docker Python 3.12.16. Install requirements-local.lock and requirements-browser.lock with editable service extras. Run python -m pytest -q --cov=scanner --cov-fail-under=75 --cov-report=term --cov-report=json:/tmp/coverage.json. Separate Chromium and containment proof remains open.

317 passed, 0 failed, 3 skipped, 6 separate subtests passed, one warning, 76.13270611537509% coverage. The prior archive-only run omitted Git and failed two source-provenance checks. The clean Git checkout rerun passed the 75% gate. Command log: hf-model-provenance-scanner.verified-check.log.

- TOTAL                                      4039    964    76%
- Required test coverage of 75% reached. Total coverage: 76.13%
- exit=0

The local workflow syntax check used actionlint 1.7.7. The Markdown lexical check inspected relative file targets. It does not establish heading fragments, external targets, or example commands. Logs and command wrappers are in the workspace audit directory.
