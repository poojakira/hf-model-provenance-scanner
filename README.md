# hf-model-provenance-scanner

[![CI](https://github.com/poojakira/hf-model-provenance-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/poojakira/hf-model-provenance-scanner/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![SARIF](https://img.shields.io/badge/SARIF-GitHub%20Code%20Scanning-blueviolet)](https://docs.github.com/en/code-security/code-scanning)
[![SLSA Level 2](https://img.shields.io/badge/SLSA-Level%202%20Aligned-green)](https://slsa.dev/spec/v1.0/levels)

[Live Dashboard](https://poojakira.github.io/hf-model-provenance-scanner/)

---

## Model Signing (Ed25519)

PulseNet signs every model artifact with Ed25519 to prevent supply chain tampering (MITRE ATT&CK **T1683.001**).

### Generate keypair and sign a model

```python
from scanner.signing.ed25519 import ModelSigner

# Generate keypair (store private key securely — never commit it)
private_pem, public_pem = ModelSigner.generate_keypair()

# Sign a model artifact
sig = ModelSigner.sign_artifact(private_pem, 'model.safetensors')
print(sig)
# {
#   'artifact_path': 'model.safetensors',
#   'sha256': 'abc123...',
#   'signature_b64': 'BASE64...',
#   'algorithm': 'Ed25519',
#   'signed_at': '2026-08-05T00:00:00+00:00'
# }

# Verify before loading
ok = ModelSigner.verify_artifact(public_pem, 'model.safetensors', sig['signature_b64'])
assert ok, 'Model artifact tampered — refusing to load'
```


## Supply Chain Integrity — Signing, SBOM, and Release Verification

### Model Signing (Ed25519)

See the [Model Signing section](#model-signing-ed25519) below for usage.

### Production Signing: sigstore/cosign

For production supply chain use, Ed25519 with a repo-managed key is a starting point. The 2026 industry standard is **sigstore/cosign** with keyless signing via OIDC:

`ash
# Sign a model artifact with cosign (keyless, OIDC-based)
cosign sign-blob model.safetensors \
  --bundle model.safetensors.bundle

# Verify
cosign verify-blob model.safetensors \
  --bundle model.safetensors.bundle \
  --certificate-identity-regexp '.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
`

> **Why not just Ed25519?** Homebrew Ed25519 requires distributing and trusting the public key out-of-band. sigstore/cosign uses transparency logs (Rekor) so any signature can be independently verified without pre-distributing keys. For a supply chain security tool, using sigstore is the credible choice. This repo includes Ed25519 as an educational implementation; use cosign in production.

### SLSA Provenance

This tool targets **SLSA Level 2** for its own releases:
- Source: GitHub-hosted repository (SLSA L1)
- Build: GitHub Actions with SLSA provenance generator (target: L2)
- Artifact: Release tarball with SHA-256 manifest

See .github/workflows/ for the provenance generation workflow.

### CycloneDX SBOM

Scan output can include a **CycloneDX 1.5 SBOM** alongside SARIF:

`python
from scanner.sbom.cyclonedx_generator import generate_model_sbom, save_sbom

sbom = generate_model_sbom(
    model_path='model.safetensors',
    model_name='meta-llama/Llama-3-8B',
    findings=scan_results,
)
save_sbom(sbom, 'output/model.cdx.json')
`

### Verify This Tool's Own Release

`ash
bash verify_my_release.sh v1.0.0
`

This script downloads the release tarball, computes SHA-256, compares against the provenance manifest, and optionally runs cosign verification.

### Why this matters

A model file that passes SHA-256 checksum verification may still have been replaced if the attacker also updates the manifest. Ed25519 signing with a key stored outside the repo (e.g. AWS KMS, hardware key) makes manifest tampering cryptographically detectable without access to the private key.

### Sign a provenance manifest

```python
manifest = {'model': 'llama-3-8b', 'sha256': 'abc...', 'source': 'meta-llama'}
sig_b64 = ModelSigner.sign_manifest(private_pem, manifest)
ok = ModelSigner.verify_manifest(public_pem, manifest, sig_b64)
```

---

## Supply Chain Threat Model

This scanner was designed in response to real ML supply chain attacks — including the 2024–2025 wave of malicious Hugging Face model uploads documented by JFrog and Sonatype researchers, where pickle-serialized payloads executed arbitrary code on researcher and production machines upon `torch.load()` calls.

Three controls address the three most common attack vectors:

| Control | Attack It Defeats |
|---------|-----------------|
| **Pickle opcode AST-walk** | Malicious `REDUCE` / `GLOBAL` opcodes that call `os.system`, `subprocess.Popen`, or `eval` during deserialization |
| **SafeTensors enforcement** | Unsafe `torch.load()` calls in model code that bypass the pickle scanner by loading via Python file handles |
| **SHA-256 provenance chain** | Tampered artifacts that look clean on first scan but are modified after the baseline hash is established (rug-pull) |

Maps to: **MITRE T1195.001** (Supply Chain Compromise), **T1683/001** (Trusted Developer Utilities), **T1027/018** (Obfuscated Files or Information).

---

## What Gets Blocked

| Attack Vector | Detection Method | Scanner Action |
|--------------|-----------------|---------------|
| Pickle `REDUCE` opcode (RCE) | AST-walk opcode analysis | Rejects artifact, emits SARIF CRITICAL |
| Pickle `GLOBAL` opcode (arbitrary import) | Opcode allowlist enforcement | Rejects artifact, emits SARIF CRITICAL |
| `STACK_GLOBAL` gadget chain | Gadget chain pattern matching | Rejects artifact, emits SARIF CRITICAL |
| Unsafe `torch.load()` in model code | Static code analysis (AST) | Flags with remediation hint — use `weights_only=True` |
| Unsigned model artifact | Ed25519 / SHA-256 provenance check | Blocks load, fails CI gate |
| Tampered artifact (rug-pull) | SHA-256 provenance chain diff | Detects mismatch, emits SARIF HIGH |
| Obfuscated payload (base64, chr() chains) | Multi-layer decode + re-scan | Rejects artifact, emits SARIF CRITICAL |
| Credential theft via env var access | Static taint analysis | Flags with SARIF HIGH |
| SSL/TLS certificate verification bypass | `verify=False` pattern detection | Flags with SARIF MEDIUM |
| Shell injection in model metadata | Shell command pattern analysis | Flags with SARIF HIGH |
| Typosquatting (similar model names) | Levenshtein distance check | Warns with SARIF INFO |
| C2 network calls embedded in model code | Network endpoint extraction + reputation | Flags with SARIF CRITICAL |

---

## What It Detects (Full List)

- **Pickle exploits** — malicious opcodes, gadget chains, and known bypass techniques (copyreg, STACK_GLOBAL, corrupted headers) that evade PickleScan
- **Obfuscated payloads** — base64 encoding, chr() chains, string concatenation tricks hiding malicious code
- **Command & control calls** — network connections to suspicious endpoints embedded in model metadata or source
- **SSL/TLS bypass** — code that disables certificate verification to enable MITM attacks
- **Shell injection** — malicious commands in shell scripts or GGUF/SafeTensors metadata
- **Credential theft** — code that reads tokens, env vars, or credential files
- **Typosquatting** — model repos with names similar to popular models
- **Missing signatures** — repos without cryptographic signing or SBOM provenance
- **Rug-pull detection** — temporal analysis that flags suspicious changes between model versions

File formats scanned: `.pkl`, `.pt`, `.pth`, `.bin`, `.ckpt`, `.safetensors`, `.gguf`, `.onnx`, `.h5`, `.keras`, `.py`, `.sh`, `.bat`, `.ps1`, `.json`, `.toml`, `.yml`

---

## Install

```bash
pip install hf-scanner
```

Requires Python 3.10+. Only runtime dependency is `psutil`.

For development:
```bash
git clone https://github.com/poojakira/hf-model-provenance-scanner.git
cd hf-model-provenance-scanner
pip install -e ".[dev]"
```

---

## Usage

```bash
# Scan a HuggingFace repo
hf-scanner meta-llama/Llama-3-8B

# Scan a local directory
hf-scanner ./my-model-folder --mode local

# Fail CI if any HIGH or CRITICAL finding
hf-scanner some-org/model --fail-on high

# Generate SARIF for GitHub Code Scanning
hf-scanner some-org/model --format sarif --output results.sarif

# Enforce policy from policy.yaml
hf-scanner some-org/model --policy policy.yaml

# Save baseline for rug-pull detection
hf-scanner some-org/model --save-baseline baseline.json

# Detect changes from baseline
hf-scanner some-org/model --baseline baseline.json
```

---

## CI Integration

Add this to your GitHub Actions workflow to gate model downloads on every PR:

```yaml
name: ML Supply Chain Security

on:
  push:
    branches: ["main"]
  pull_request:
    branches: ["main"]
  schedule:
    - cron: "0 6 * * *"  # Daily re-scan against baselines

permissions:
  contents: read
  security-events: write

jobs:
  model-provenance-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.10"

      - name: Install hf-scanner
        run: pip install hf-scanner

      - name: Scan model artifact
        run: |
          hf-scanner ./models/ \
            --mode local \
            --policy policy.yaml \
            --format sarif \
            --output results.sarif \
            --fail-on high
        # Exit code 1 if CRITICAL or HIGH finding — blocks merge

      - name: Upload SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
          category: ml-supply-chain
```

This gate **rejects unsigned or malicious artifacts before they can be loaded** — not after.

---

## Signing Workflow

Make signing easy so developers actually do it. Sign a model artifact before publishing:

```bash
# Sign your model artifact (generates .sig sidecar file)
hf-scanner --sign ./my-model.pt --key-path ~/.ssh/model_signing_key

# Verify signature before loading
hf-scanner ./my-model.pt --verify-signature --key-path ~/.ssh/model_signing_key.pub

# Full paved-path workflow: scan + sign in one command
hf-scanner ./my-model.pt --scan --sign --key-path ~/.ssh/model_signing_key --output model_report.json
```

The `.sig` sidecar file contains:
```json
{
  "artifact": "my-model.pt",
  "sha256": "a3f2...",
  "signed_by": "model-author-key-id",
  "timestamp": "2026-08-05T17:00:00Z",
  "algorithm": "Ed25519"
}
```

---

## SLSA Alignment

This scanner enforces controls that align with SLSA Level 2 and partially Level 3:

| SLSA Requirement | Our Control | Level |
|-----------------|------------|-------|
| Build integrity: artifact hash | SHA-256 provenance chain | L2 |
| Source integrity: no tampering after baseline | Rug-pull temporal detection | L2 |
| Provenance: signed by trusted identity | Ed25519 signature enforcement | L2/L3 |
| Dependencies: no malicious transitive deps | Pickle opcode + taint analysis | L2 |
| Build service: reproducible | SafeTensors enforcement (format lock) | L2 |

Amazon ships millions of models internally. SLSA-aligned controls mean scan results integrate into existing supply chain security programs without custom tooling.

---

## Key Flags

| Flag | Description |
|------|-------------|
| `--mode local/remote/both` | What to scan (default: both) |
| `--fail-on SEVERITY` | Exit 1 threshold (default: high) |
| `--format json/sarif/text/html` | Output format |
| `--output FILE` | Write report to file |
| `--policy FILE` | Apply policy.yaml config |
| `--baseline FILE` | Compare against saved baseline |
| `--save-baseline FILE` | Save current scan as baseline |
| `--sign` | Sign the artifact after scanning |
| `--verify-signature` | Verify existing signature |
| `--sandbox` | Enable sandbox execution of Python files |
| `--aibom FILE` | Generate CycloneDX AI BOM |
| `--no-network` | Force local-only scan |
| `--token TOKEN` | HuggingFace API token |
| `-q, --quiet` | Suppress output, only set exit code |

---

## Test Results

Detection capability measured against the internal red-team fixture suite (see `evidence/DETECTION_PROOF.md`):

- 12/12 documented incident-reproduction fixtures detected (real-world attack patterns from 2025–2026 JFrog and Sonatype research, reproduced as test cases)
- 18/18 extended variant fixtures detected
- 0 false positives on clean GPT-2 and Llama-3-8B SafeTensors fixtures
- P99 scan latency < 200ms on GPT-2 SafeTensors metadata/header path (50 runs)
- Total red-team suite scan time: 116ms

**Scope note:** "12/12" and "18/18" refer to this specific internal fixture suite — not a general detection rate claim for arbitrary HuggingFace models.

```bash
python tests/redteam/simulate_attacks.py
```

---

## Project Structure

```
scanner/
  cli.py              — CLI entry point
  analyzer/           — Detection engines (pickle, safetensors, gguf, onnx, keras,
                        obfuscation, taint, shell, config, ast, sandbox, temporal)
  rules/              — Finding definitions and severity mappings
  formatters/         — Output formatters (json, sarif, html)
  attack_mapping/     — MITRE ATT&CK technique mapping
  utils/              — HF API client, Levenshtein distance, file filtering
tests/
  redteam/            — Attack simulations and extended test corpus
  fixtures/           — Benign and malicious test files
integrations/         — CI configs for GitHub Actions, GitLab, Jenkins, CircleCI, Azure
policy.yaml           — Policy-as-code secure defaults
```

---

## ATT&CK Mapping

Findings map to MITRE ATT&CK v19 techniques:

- T1195.001 — Supply Chain Compromise: Compromise Software Supply Chain
- T1683/001 — Trusted Developer Utilities
- T1027/018 — Obfuscated Files or Information
- T1685 — Disable or Modify Tools (DP bypass)

---

## License

Apache-2.0
