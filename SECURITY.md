# Security reporting and local inspector autopsy

The 0.3.0 local inspector is a PARTIAL candidate, with no production-support or vulnerability-free claim. Report suspected vulnerabilities privately through the repository owner’s GitHub contact/security reporting channel where available. Do not post credentials, private models, personal data or executable payloads publicly. A minimal synthetic reproducer, affected source SHA, expected boundary, observed result and redacted logs help review. No response SLA is promised.

## Findings addressed in this candidate

| Finding / mechanism | Mitigation / regression | Remaining scope |
|---|---|---|
| Installer CRLF syntax, Python 3.9 misclaim and arbitrary-target `rm -rf` | LF script; Python 3.10+; install reviewed local checkout only into a new path; existing sentinel directory preserved by test | Operator must choose an authorized install location |
| Hostile artifact deserialization / uploaded source execution | Static parsers only; real worker source/pickle sentinel tests and open/socket/exec/fork denial | CPython/kernel/library bugs remain possible |
| Resource/pipe flooding or thread timeout retaining work | Process CPU/address-space/deadline quotas; nonblocking capped stdout/stderr; kill/reap group; one scan; bounded connections | Legitimate larger artifacts are rejected |
| Malformed/overlapping SafeTensors, duplicate/non-finite JSON, extreme dimensions or trailing polyglot | Strict structural prevalidation and actual worker negative tests | Supported dtype/size subset is conservative |
| GGUF zero-tensor trailing payload, truncated value/string, nested arrays, non-finite floats | Complete bounds/UTF-8/type checks and UNKNOWN on unsupported data | Tensor payload layout/quantization and complete content detection remain unverified |
| Cross-origin upload / DNS rebinding / path probing | Fixed loopback, Host/Origin/session token, no paths/URLs, inert text rendering and CSP | Same-account local processes/extensions are trusted boundary |
| Stale file read or scan response overwrites current selection | Selection revision invalidates old results; browser delayed-read/response tests | No persistent history/version control of user models |
| Filename-sensitive structure hash | Fingerprint excludes display path from structural comparison; equal-content regression | Static equality has no behavioral implication |

Existing `--sandbox` dynamic execution stays disabled. The remote admission service retains authorization; a keyless local upload UI is not a reason to weaken a different API. Local report checksums provide integrity checks, not an external attestation, digital signature or tamper-proof audit log.

Independent adversarial review and deployment-specific acceptance are still required. See [known limitations](docs/EVIDENCE.md) and the final out-of-tree evidence manifest for tested status.
