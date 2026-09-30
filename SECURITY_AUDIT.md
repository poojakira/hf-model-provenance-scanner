# Security Audit — hf-model-provenance-scanner

**Audit date:** 2026-09-29  
**Scope:** admission HTTP service, Hugging Face webhook integration, remote fetching, isolation executor, secrets, CI, containers, and error handling.

## Findings captured before this remediation pass

| ID | Severity | Finding | Status |
|---|---|---|---|
| HF-001 | High | The authenticated `/scan` service has concurrency and execution time limits but no request-rate limiter. | Open |
| HF-002 | Medium | The service does not enforce a raw request-body byte limit before framework parsing. | Open |
| HF-003 | Medium | `WEBHOOK_SECRET` is mandatory but not required to meet a minimum strength in the standalone webhook adapter. | Open |
| HF-004 | Medium | Service responses can propagate scanner-internal `error` text to clients. | Open |
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
