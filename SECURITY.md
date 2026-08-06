# Security Policy — hf-model-provenance-scanner

## Reporting a Vulnerability

To report a security vulnerability **in this scanner tool**, do not open a public GitHub issue.

Email: **security@[your-email-here]**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested mitigations

**Expected response time:** Acknowledgement within 72 hours. CRITICAL issues (e.g., code execution via crafted model file) patched within 7 days.

This project follows coordinated disclosure. We will credit reporters in the CHANGELOG unless anonymity is preferred.

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

See [THREAT_MODEL.md](THREAT_MODEL.md) for the full threat model of this tool, including what it assumes about its environment and what it explicitly does not protect against.
