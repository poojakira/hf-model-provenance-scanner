# Security review, 2026-09-30

Reviewed checkout: `4de4ded268bf7f9b032f2040aaf92b4e97e8ed02`.

## Implemented controls

- The admission service bounds actual ASGI request bytes, including chunked requests, before JSON parsing. Declared lengths are also checked.
- Invalid request responses use a generic message and do not include Pydantic's rejected input. Scanner stderr is not copied into service logs. Unexpected scanner failures return a generic HTTP error.
- Timed-out work retains its concurrency slot until the worker completes. Saturated admission returns 503 instead of queuing unlimited workers. The HTTP timeout is not a thread kill mechanism.
- CLI stdout/stderr capture is serialized because redirection changes process-wide state. This also serializes the actual CLI scans within each service process.
- Requests using the service's `HF_TOKEN` require an explicit `SCAN_ALLOWED_REPOS` comma-separated allowlist. A configured list restricts public scans as well; unauthorized repository names return 403. Set, for example, `SCAN_ALLOWED_REPOS=your-org/model-a,your-org/model-b` alongside a narrowly scoped HF token.
- HF HTTP requests validate the initial HTTPS origin as well as redirects. Nonstandard ports and URL credentials are rejected; bearer authorization is stripped for CDN origins. Metadata and card reads now have the same default 10 MiB response limit as downloads. Retry-After cannot impose an unlimited delay.

## Authentication and authorization

`API_KEY` authenticates a caller into a shared service trust domain. The repository allowlist separately limits which models that caller may scan using service credentials. This does not implement identities, individual tenant policies, or tenant-specific results. Use separate deployments and restricted tokens for separate trust domains. Rate limits remain per process; deployments with multiple workers need an upstream shared limiter. Probe routes and interactive schema pages are public; restrict access at ingress if these should be private.

## Files, model execution, and secrets

The supported static scan path does not deserialize model pickles or execute repository loaders. This review did not establish that optional analysis/isolation modes are safe for hostile code on an ordinary host. Do not treat static findings or a clean scan as proof a model is safe to execute.

Full reachable Git history was scanned with Gitleaks by the account audit coordinator: zero detections. Additional historical path review found no project `.env`, private-key containers, or credential filenames outside formerly committed virtual environments. These checks cannot prove absence of all secrets, cover unreachable objects or GitHub artifacts, or revoke provider credentials. `.gitignore` excludes local secret material; placeholder example files may be committed after review.

## Validation and remaining work

`OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 python -m pytest -q`: **227 passed, 2 skipped, 6 subtests passed**. The live integration test was skipped; one other existing skip remains. A TestClient deprecation warning was emitted. Tests include private-model authorization, chunked body limits, input redaction, initial/redirect host restrictions, and capacity retention after timeouts.

Live HF integration, deployment/proxy limits, hard process termination, public network abuse testing, tenant identity integration, and exhaustive review of every binary/parser path remain outside the verified result. No security certification or claim that all possible vulnerabilities are fixed is made.

## Installed dependency advisory check

The combined isolated environment containing both projects and their service/development extras was checked with `pip-audit --format json`. The report lists 70 dependencies and zero known vulnerabilities; the two local editable project packages were skipped because they are not PyPI packages. This verifies the resolved installed versions at audit time, not every version allowed by dependency ranges, future advisories, or undeployed lockfiles. No paid provider APIs were used.
