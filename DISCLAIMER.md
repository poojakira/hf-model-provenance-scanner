# Project Status & Disclaimer

## Maturity

This scanner is a working prototype that passes its test suite against crafted attack fixtures. It has not been:

- Deployed in a production CI/CD pipeline at scale
- Audited by an independent security firm
- Tested against a comprehensive corpus of real-world malicious models in the wild
- Published to PyPI

## What the test suite proves

The 262 passing tests verify that:
- The pickle opcode parser correctly identifies dangerous opcode sequences in crafted fixtures
- The taint engine traces data flow from sources to sinks in Python ASTs
- The symbolic resolver decodes multi-layer string obfuscation (chr(), base64, format strings)
- HTTP Range request logic correctly fetches partial file contents
- Output formatters produce valid SARIF 2.1 and CycloneDX 1.5 documents

## What the test suite does NOT prove

- That the scanner catches all real-world attacks (coverage against novel techniques is unknown)
- That the false positive rate is acceptable on a large corpus of legitimate models
- That the scanner performs reliably under production load
- That the bandwidth reduction claims hold across all model hosting configurations

## Intended use

Use this as one layer in a defense-in-depth approach. Combine with:
- Hugging Face's built-in malware scanning
- ModelScan or Fickling for additional coverage
- Manual review of model provenance before deploying to production
- Network-level controls (egress filtering, sandboxed model loading)

## CVE references

This project references the following real, verified CVEs and advisories:
- CVE-2024-5480: HuggingFace Hub RCE via pickle deserialization
- CVE-2024-25664: llama.cpp GGUF buffer overflow
- JFrog 2024 research: Malicious PyTorch models on HF Hub
- Sonatype 2024: Typosquatted model repositories

No fabricated or hypothetical CVE identifiers are used.
