# Runbook

## Engineering Update - 2026-07-27

Repository: hf-model-provenance-scanner
Purpose: Hugging Face model supply-chain scanner

## Build

- Install: make install
- Lint: make lint
- Format: make format
- Test: make test
- Package build: make build
- Security scan: make security
- Full local gate: make verify

## Dashboard

3D realtime dashboard: dashboard/realtime/index.html. Serve with make dashboard.

## Dependencies And Data

Package metadata now includes scanner and attack_mapping packages; CI installs private attack-v19-core.

## Validation Snapshot

Validated: Ruff and format passed; full pytest passed (124 passed, 3 skipped); wheel build passed; dashboard browser/static checks passed.

## Operating Limits

- Re-check Linux and GitHub Actions after pushing to main.
- Treat local dashboard scores as evidence indicators, not certifications.
- Do not cite production readiness until clean CI, dependency audit, license status, and runtime smoke tests are current.