# Research Brief - Poster 03

> Evidence status: Refreshed against current code snapshot `4501739a724a2a0a7de9173e51af535b192bf0e4` and successful CI run `36782472264` on 2026-09-30.

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

## Current Verified Evidence

Current-main Python 3.12 CI reports:

- **231 passed, 1 skipped, 6 subtests passed**.
- **68.00% statement coverage**; CI gate is 55%.
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
git checkout 4501739a724a2a0a7de9173e51af535b192bf0e4
python -m pip install -e ".[dev,service]"
pytest tests/ -q --cov=scanner --cov-report=term
```

Expected current-main evidence: **231 passed, 1 skipped, 6 subtests passed**, **68.00% coverage**.
