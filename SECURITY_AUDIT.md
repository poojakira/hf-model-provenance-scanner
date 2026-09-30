# Security Audit — hf-model-provenance-scanner

**Audit date:** 2026-09-29  
**Scope:** admission HTTP service, Hugging Face webhook integration, remote fetching, isolation executor, secrets, CI, containers, and error handling.

## Findings captured before this remediation pass

| ID | Severity | Finding | Status |
|---|---|---|---|
| HF-001 | High | `/scan` now enforces a bounded per-peer/API-key request rate before starting scanner work. | Fixed |
| HF-002 | Medium | HTTP middleware now enforces the configured raw request-body byte limit before request handling and rejects oversized or invalid declared lengths. | Fixed |
| HF-003 | Medium | Webhook processing and standalone startup now require `WEBHOOK_SECRET` to be at least 32 characters and fail closed otherwise. | Fixed |
| HF-004 | Medium | Scanner-internal failures are mapped to the generic public marker `scan_failed`; raw internal error text is not returned by the admission response. | Fixed |
| HF-005 | Info | Restricted subprocess execution is explicitly fail-closed unless the caller acknowledges its non-kernel isolation limitations. | Verified |

## Existing controls verified

- API key comparison uses constant-time comparison and requires 32+ characters.
- Repository/revision inputs are bounded and format validated.
- Scan timeout and concurrency semaphore.
- Webhook HMAC verification and payload-size cap.
- Hugging Face API host allowlisting/token-forwarding restrictions.
- Restricted subprocess environment scrubbing, output caps, timeouts, and POSIX resource limits.
- Non-root service container.
- Secret-hygiene CI.

## Verification plan

Run unit/security/production workflows after remediation and re-check rate limiting, body limits, webhook verification, response leakage, and remote host restrictions.
