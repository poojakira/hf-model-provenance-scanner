# Runbook

## What This Is

hf-model-provenance-scanner — a tool that scans HuggingFace model repositories for supply chain attacks.

## Build Commands

| Task | Command |
|------|---------|
| Install all deps | `make install` |
| Install attack-v19-core (local) | `make install-core` |
| Run linter (ruff) | `make lint` |
| Auto-format code | `make format` |
| Run tests | `make test` |
| Build wheel | `make build` |
| Run bandit + pip-audit | `make security` |
| Run everything (lint + test + build + security) | `make verify` |

## Dashboard

There's a 3D real-time dashboard at `dashboard/realtime/index.html`. Serve it locally:

```bash
make dashboard
# Opens on http://localhost:8080
```

## Dependencies

- Runtime: `psutil` only
- Dev: `pytest`, `pytest-cov`, `ruff`
- Optional: `attack-v19-core` for ATT&CK technique mapping

The `attack-v19-core` package is expected at `../attack-v19-core` for local development. CI installs it from the private repo.

## Last Validated

- Ruff lint and format: passing
- Pytest: 124 passed, 3 skipped
- Wheel build: passing
- Dashboard static checks: passing

## Known Limits

- Tests validated on Linux (GitHub Actions) and locally. Re-check CI after pushing changes.
- Dashboard scores are evidence indicators, not certifications.
- Sandbox execution is defense-in-depth, not a containment guarantee.
