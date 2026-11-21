# Security reporting and boundaries

Software0.3.0 is a **PARTIAL** candidate. No production-support, response/fix deadline, certification or vulnerability-free claim is made. Report suspected vulnerabilities privately through the repository owner's GitHub security/contact channel where available. Include affected source/version, prerequisites, minimal synthetic reproduction, expected/observed boundary and redacted logs. Never post private models, credentials, process tokens or executable payloads publicly.

## Actual trust boundaries

The Linux local inspector uses bounded input, exact loopback Host/Origin/process-token checks, inert rendering and a fresh syscall-contained static worker. It never imports/unpickles/executes uploaded files. Its origin token does not authenticate another OS user; local processes/extensions and the host remain trusted. Containment is not a VM or proof against kernel/CPython/library flaws. Report checksums are not signatures or tamper-proof audit anchors.

CLI, remote admission, webhook and portable executor are distinct surfaces. The local worker is not automatically wrapped around every CLI/remote operation. The remote service retains API-key/allowlist checks; a keyless local browser is not authorization to weaken them. The portable executor's acknowledgment flag and illustrative kernel profiles do not establish arbitrary-code isolation. `--sandbox` remains disabled.

## Source-scoped autopsy

Implementation work corrected destructive installer target handling/CRLF/Python-version drift, installed-wheel Git attribution, bounded worker/pipes and structural parsing, stale file/response/export races, and nonce persistence in saved health evidence. Actual negative/regression results are source-scoped in [EVIDENCE.md](docs/EVIDENCE.md). Independent review at an earlier source identified two export races and nonce hygiene; engineering regression confirmed the corrections at 16ff. Independent closing review remains **BLOCKED** by the review service, not VERIFIED. This documentation pass supplies no new independent security closure.

The old filename-sensitive hash concern is not an unresolved defect: structure fingerprinting excludes the display path and the identical-renamed-bytes comparison passed. No-result/UNKNOWN/no-pattern statuses must remain distinct. Heuristic rules can miss malicious content and flag benign files; broad safety/provenance conclusions require other evidence.

## Credentials, privacy and recovery

Use synthetic data for evaluation and operator-approved inputs in a trusted environment. Keep tokens, passwords, private keys and populated environment files out of source/logs/exports. Optional network paths need approved narrow runtime credentials and destinations. Reports can disclose artifact content, paths and metadata; review before sharing. If a credential is exposed, revoke/rotate at its provider first, then preserve evidence and remediate source/history/artifact exposure. Deleting a file or rewriting history does not revoke it. No live credential probing is needed to classify a scanner heuristic.

Backend input memory is reclaimed, not cryptographically erased; explicit downloads and source files persist under operator control. There is no local report database or secure-erasure promise. Follow [operations](RUNBOOK.md), [limitations](LIMITATIONS.md) and [incident-response template](INCIDENT_RUNBOOK.md); deployment-specific review and remaining acceptance gates stay explicit.
