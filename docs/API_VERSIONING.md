# API and version reference

Software/engine version is **0.3.0**, local inspector schema version is **1**, and separate remote admission API metadata declares **1.0.0**. They identify different contracts. This pre-1.0 project does not establish immutable Python imports, a multi-release deprecation/backport schedule or future schema guarantees merely by listing them.

## Local inspector API 1

Implementation: `scanner/workbench/server.py`, `worker.py` and `app.js`. Only the trusted local browser is supported; there is no public bind, URL/path/command target or remote-model download endpoint.

| Method | Path | Contract |
|---|---|---|
| GET | `/`, `/app.js`, `/style.css` | Packaged browser assets |
| GET | `/api/health` | Version/source/rule hashes/limits and process-local CSRF token; do not persist token or call readiness a containment proof |
| POST | `/api/inspect` | Exact local Origin/Host and X-Inspector-Token, JSON Content-Type, declared length, no Transfer-Encoding; bounded base64 file envelope |

The body accepts only a files array with one/two objects, each containing only ASCII basename name and base64 data. Each decoded file is 1 byte–4 MiB; envelope limit is 12 MiB. The source parses supported structures, not filenames alone. A synthetic raw-pickle NONE/STOP example is:

```json
{"files":[{"name":"synthetic.pkl","data":"gAROLg=="}]}
```

Success delivers the report schema, run/UTC/source/configuration/input hashes, limits, input manifest, result files/comparison and limitations. Each input includes name/size/SHA-256; parsed files add structure evidence/hash/findings, and unknown files add an error. Worker failure can produce an empty result.files with result.error while the input manifest still records selected hashes. Comparison fields may be null when inspection fails. HTTP200 is report delivery, not successful security validation. See [the user/format contract](INSPECTOR.md).

| HTTP status | Meaning |
|---|---|
| 400 | Malformed JSON/envelope/filename/base64 |
| 403 | Host/origin/process-token boundary rejected |
| 404 | Unknown route |
| 408 | Upload deadline |
| 413 | Invalid/absent/excessive length |
| 415 | Unsupported content type/transfer encoding |
| 429 | Existing scan or connection capacity occupied |

Other methods are unsupported. Download bundles contain report and a manifest.report_sha256 over UTF-8 JSON.stringify(report,null,2), without trailing newline. This checksum is not a signature or independent attestation. File edits/new scans cancel obsolete pending outputs; the temporary token stays in memory. Installed wheels report Git source UNKNOWN unless in their exact tracked source root.

## CLI reports and status

`hf-scanner` and `python -m scanner.cli` invoke `scanner.cli.main`. Current argparse supports local/remote/both modes, revision, severity, json/sarif/text/html, output/config, no-network, token, verbose/quiet, baseline/save-baseline, binary limits, AIBOM/runtime-policy and protect options. Use `--help` for exact flags. `--experimental-deep-scan` and `--experimental-heuristic` are not implemented. `--sandbox` is explicitly rejected. Parsed protect-daemon does not create a daemon implementation.

Native JSON actually uses scan_target, scan_mode, scanner_version, findings, org_check, risk, files_scanned/files_skipped, completeness, skipped_files_detail, artifact_revision, scan_duration_seconds and error. Findings use rule_id, severity, file_path, line_number, column, message, evidence, remediation, cwe and decoded_layer. The old invented schema_version/target/summary schema is not this formatter's output. Reports include variable run duration and supplied paths; byte-identical whole-report output is not promised.

SARIF formatter emits version 2.1.0 with tool.driver.name hf-scanner, tool version, rule records, results, locations and scanner properties. An emitted format identifier is not by itself official-schema validation or proof findings are security-correct. The local inspector downloads its own JSON bundle, not SARIF. The current Rule objects live in scanner/rules/definitions.py with additional rule IDs produced by helpers; a sparse ID range is not a contiguous count or future stability guarantee. Do not assume a rule is active merely because its ID exists in a registry.

Exit 0 means configured severity did not fail; enforce mode also rejects incomplete/indeterminate/unknown. Exit 1 covers threshold/enforce failure; 2 covers runtime/argument errors; 3 covers certain invalid local targets. COMPLETE refers to selected static scope, not safe execution. See [operations](../RUNBOOK.md#interpret-completeness-and-exit-status).

## Remote admission API 1.0.0

Install the service extra in a reviewed environment and launch `uvicorn scanner.service:app` on an operator-chosen reviewed local/ingress configuration. The FastAPI application declares 1.0.0. Routes `/health` and `/ready` are public probes; POST `/scan` requires a 32+ character configured API_KEY matched through X-API-Key. There is one shared trust domain, no user/tenant identity or tenant-specific policy store. When using HF_TOKEN, SCAN_ALLOWED_REPOS must explicitly authorize repository IDs; a configured allowlist restricts public requests too.

Request model fields are repo_id (3–256 characters), revision (1–200, default main), and fail_on (default high). Target/revision/severity validation adds semantic restrictions. Example shape only, not a performed remote request:

```json
{"repo_id":"authorized-org/authorized-model","revision":"main","fail_on":"high"}
```

Response fields are scan_id, decision, exit_code, duration_ms, artifact_revision, completeness, risk, findings and sanitized error. A code 0/COMPLETE result maps to ALLOW, code 1 to BLOCK, other combinations to ERROR. The caller must enforce the result before loading a model. Authentication/allowlist failures return 401/403, configured rate excess 429, saturation 503, timeout 504 and unexpected scanner failure 500; request validation can return 422 and body/framing limits 400/413. Health is liveness; ready checks configured key length and reports process settings, not HF connectivity/worker isolation.

SCAN_MAX_REQUEST_BYTES defaults to 16,384; SCAN_RATE_LIMIT_RPM to 60; MAX_CONCURRENT_SCANS to 4; SCAN_TIMEOUT_SECONDS to 120. Actual ASGI bytes are bounded before request parsing. Limits are per process. Timed-out threaded work retains its slot until completion; timeout does not terminate the underlying thread. Scanner stdout capture is serialized. Credentials/allowlists/ingress/TLS and shared-worker limits require environment-specific review. These controls are distinct from the local inspector's fresh seccomp-sealed child.

## Compatibility and unavailable APIs

There is no supported top-level `from scanner import scan_file, Scanner` facade, plugin stability contract or universal no-backward-breakage guarantee. Internal functions/classes are source entry points subject to change. Pin reviewed versions/commits, validate emitted reports and update consumer compatibility tests for changes. Proposal-style old API examples do not establish implemented behavior, official-schema validation or a maintenance commitment.
