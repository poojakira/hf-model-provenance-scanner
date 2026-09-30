# Security Audit — 2026-09-30

## Scope
Initial pre-remediation review of the current `main` branch.

## Runtime surface
Authenticated FastAPI admission service, Hugging Face webhook adapter, model-artifact scanner, sandbox/executor code, outbound Hugging Face requests.

## Verified controls
- Admission API requires a sufficiently strong API key and uses constant-time comparison.
- Repository/revision inputs are bounded and validated.
- Concurrency and execution timeouts are enforced.
- Webhook processing requires a configured HMAC secret and caps body size.
- Hugging Face HTTP utility contains destination restrictions and strips authorization on non-auth forwarding hosts.
- Scanner intentionally detects dangerous serialization/execution patterns rather than executing arbitrary model files by default.
- No confirmed live API key was found in the current main branch.

## Findings to remediate/verify
1. Add/verify request-rate limiting for the admission API, not only concurrency limiting.
2. Treat notification URLs as privileged configuration: HTTPS-only, explicit destinations, short timeout, no redirect-to-private-network behavior.
3. Verify every sandbox backend has resource limits and fails closed when stronger isolation is required.
4. Ensure all urllib/network paths use bounded timeouts and do not forward bearer tokens across redirects.
5. Confirm public error responses never return scanner stderr, local paths, or exception text.
6. Add health-gated rollback/blue-green deployment guidance for the service image.

## Not applicable
SQL tenant isolation and password reset.

<!-- repo-verification:start -->
## Verification update — 2026-09-30

- **Scope:** Account-wide `poojakira` repository pass covering source/configuration, CI/release workflows, security-hygiene gates, dependency/SAST controls, and documentation consistency.
- **Remediation:** Marked the inert webhook test secret as a test-only S105 exception instead of weakening the rule globally; CI then passed.
- **Verification state:** CI, Production Gate, Security Hygiene, Documentation Integrity, and Admission Service Container checks completed successfully after the fix.
- **Security note:** The exception is limited to the inert test fixture; production secret-handling rules remain enforced.
- **Evidence boundary:** This update records repository and GitHub Actions evidence observed during the pass. It is not a claim of independent penetration testing, production deployment, or zero residual risk.
<!-- repo-verification:end -->
