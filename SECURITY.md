# Security Policy — hf-model-provenance-scanner

## Reporting a Vulnerability

To report a security vulnerability **in this scanner tool**, do not open a public GitHub issue.

Use GitHub's private vulnerability reporting or security advisory workflow for this repository when available. If private reporting is not enabled, contact the repository owner directly through the GitHub profile before publishing details.

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested mitigations

No response-time SLA is currently committed. Critical issues such as scanner-host code execution from a crafted model file should be treated as urgent and fixed before any release promotion.

This project prefers coordinated disclosure. Reporter credit is optional and requires reporter consent.

## Scope — In Scope

- Vulnerabilities in the scanner that allow a crafted model file to achieve code execution on the scanner host
- Bypass techniques that allow malicious pickle opcodes to pass the allow-list check
- Vulnerabilities in the CLI argument parsing (e.g., path traversal via `--output`)
- False-negative bypasses that would allow a CRITICAL-severity finding to be suppressed
- Dependency vulnerabilities in direct dependencies that are exploitable via this tool's attack surface

## Scope — Out of Scope

- Detection rate debates (false positive / false negative rates) — open a regular issue
- Vulnerabilities in the Hugging Face API or platform itself
- Findings in transitive dependencies not exploitable via this tool
- Theoretical attacks with no practical exploitation path

## Security Assumptions

See `LIMITATIONS.md` for current boundaries and unsupported cases. A complete threat model is not yet published, so this repository must not be described as production-ready.
