# Incident-response template

This is an operator-adaptable procedure, not an operated service or a staffed response commitment. The project supplies no on-call rotation, SLA, fix deadline, prearranged platform-security coordination or automatic emergency release. Define contacts, impact criteria and timing in the operator's own environment.

## Triage and preserve

1. Identify the exact interface: local inspector, CLI, remote admission, webhook or optional executor/monitor. Distinguish a static pattern, failed inspection and an observed external effect.
2. Preserve source/version/clean state, non-secret configuration, actual errors, UTC times, hashes and a minimal authorized synthetic reproducer. Do not publish private artifacts, tokens, request headers or detailed payloads in an open issue.
3. Assess impact from observed facts. An inspection failure or zero findings is not evidence of model safety; a missed fixture is not automatically a real-world compromise.
4. Contain the integration through controls the operator owns. Keep failing/UNKNOWN outcomes and gates; do not disable auth, containment, quotas or security assertions to restore apparent green output.
5. Report repository vulnerabilities privately using [SECURITY.md](SECURITY.md). Any external disclosure or notification is a separate authorized action.

## Investigate the actual surface

The local inspector's health/readiness is `/api/health`; use its non-secret source/version/limits fields and actual report. Never log its temporary session nonce. UNKNOWN/crash/timeout does not authorize unrestricted parsing or loading the artifact. Stop/restart only the owned server; each worker is disposable and backend input is not persisted.

For the remote admission service, `/health` is liveness and `/ready` checks API-key configuration. It is not an authenticated-user/tenant or HF-availability certification. Per-process rate/concurrency limits and sanitized HTTP errors are distinct from the local worker's syscall containment. A timed-out thread may still be running; it retains the slot until completion. External-effects/notification reconciliation requires the authoritative destination, not a local hash.

For a suspected false positive or missed pattern, reproduce static inspection with benign/synthetic authorized bytes, add meaningful representative regressions and review the scoped correction. Rule IDs are defined in `scanner/rules/definitions.py`; adding an object alone does not wire a new detector. Avoid blanket allowlists or a test name/filter that accidentally collects no cases. Use [the actual test taxonomy](docs/TESTING.md); nonexistent `tests/rules/`/`test_HFS` release procedures are not a supported gate.

## Recovery and release

Preserve local changes/reports, select a previously reviewed source or immutable artifact in a separate environment, run its checks and bounded user journey, then restore an independently authorized integration. Code rollback does not revoke tokens, reverse notifications or remove a malicious model from another service. Provider-side credential rotation, affected consumers and evidence custody require operator-owned decisions.

A fix requires review, full relevant regression, source-scoped build/browser/security evidence and documentation alignment. Do not bypass checks or assume a tag automatically publishes to PyPI. No repository-wide recovery time, rollout percentage or release deadline is asserted. Production backup/restore and recovery must be exercised in the actual target environment.

Record observed impact, timeline, root cause, evidence, containment, recovery, residual risk and follow-up owners. Clearly mark hypotheses and synthetic reproductions. Third-party incident reports and curated fixtures in this repository are research context; verify original sources before relying on dates, affected-user counts or attribution.
