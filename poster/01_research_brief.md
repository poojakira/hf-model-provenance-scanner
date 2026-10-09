# Research Brief - Poster 03

> Evidence status: Refreshed against verified code snapshot `251a7b90fd60fa1884c643adda9d96cd7801abe6` and successful CI run `37163168715` (CI run initiated 2026-10-03 UTC).

## Repository

`github.com/poojakira/hf-model-provenance-scanner` - public, default branch `main`.

## Academic Project Title

**Non-Executing Security Analysis of AI Model Supply-Chain Artifacts**

### Subtitle

Provenance, Serialization, Impersonation, and Repository Risk Inspection

## One-Sentence Contribution

A primarily non-executing model-artifact security scanner combining static code analysis, symbolic and taint-style inspection, binary-format parsing, provenance checks, and fail-loud handling of incomplete analysis before model loading.

## Method

1. Enumerate repository and model artifacts.
2. Parse supported serialization/model formats.
3. Apply AST, pattern, symbolic, taint-style, metadata, and provenance checks.
4. Reject unsafe dynamic-execution paths in the scanner itself.
5. Emit findings and fail-loud states for incomplete or unsafe analysis.

## Verified Evidence at Poster Snapshot

The cited Python 3.12 CI snapshot reports:

- **241 passed, 1 skipped, 6 subtests passed**.
- **75.67% statement coverage**; CI gate is 75%.
- Lint/format, type checking, Bandit, pip-audit, CodeQL, Trivy container scanning, unsafe-dynamic-execution rejection, and Docker build jobs succeeded.
- The committed adversarial fixture evidence remains fixture-scoped; it must not be generalized to arbitrary model repositories.

## Limitations

- Static analysis cannot prove a model is safe.
- No claim is made that neural weight backdoors are generally detected.
- Fixture-level results do not establish population-level precision or recall.
- Unsupported or incomplete parsing must remain fail-loud rather than silently clean.

## Reproducibility

```bash
git clone https://github.com/poojakira/hf-model-provenance-scanner.git
cd hf-model-provenance-scanner
git checkout 251a7b90fd60fa1884c643adda9d96cd7801abe6
python -m pip install -e ".[dev,service]"
pytest tests/ -q --cov=scanner --cov-report=term
```

Expected evidence at the cited snapshot: **241 passed, 1 skipped, 6 subtests passed**, **75.67% coverage**.
