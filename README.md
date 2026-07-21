# HF Model Provenance Scanner

Zero-dependency ML supply chain security scanner for Hugging Face model repositories.

**30/30 real-world attacks detected | 0 false positives | 0 dependencies | Python 3.9+**

Tested against real GPT-2 and Llama-3-8B model structures. Validated against every documented HuggingFace supply chain attack from 2025-2026 including the May 2026 fake OpenAI incident (244K downloads).

## Quick Start

### Linux / macOS

```bash
# One-line install
curl -sSL https://raw.githubusercontent.com/poojakira/hf-model-provenance-scanner/main/install.sh | bash

# Or clone and run directly (no install needed)
git clone https://github.com/poojakira/hf-model-provenance-scanner.git
cd hf-model-provenance-scanner
python3 -m scanner.cli ./my-model --mode local --fail-on high
```

### Windows (PowerShell)

```powershell
# One-line install
iex ((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/poojakira/hf-model-provenance-scanner/main/install.ps1'))

# Or clone and run directly
git clone https://github.com/poojakira/hf-model-provenance-scanner.git
cd hf-model-provenance-scanner
py -m scanner.cli .\my-model --mode local --fail-on high
```

## What It Detects

| Category | Attacks | Detection Engine |
|----------|---------|-----------------|
| **Pickle RCE** | os.system, subprocess, eval in .pkl/.pt/.pth (incl. 7 PickleScan bypasses) | Binary Parser |
| **Source code attacks** | Base64 payloads, PowerShell C2, SSL bypass, credential theft | AST + Taint + Sandbox |
| **Obfuscation** | chr() chains, rot13, base85, getattr, ctypes, lambda+map, generators | Symbolic Resolver + Sandbox |
| **Format abuse** | SafeTensors metadata injection, GGUF shell commands, Keras Lambda layers | Format Parsers |
| **Org impersonation** | Typosquatting (Levenshtein + prefix), model card plagiarism, velocity anomaly | Org Checker |
| **Supply chain** | Missing signatures, SBOM hash mismatches, unpinned deps, unsafe Dockerfiles | Provenance Engine |
| **Rug-pull attacks** | New malicious files after trust, removed security artifacts | Temporal Baseline |
| **Environmental gating** | Payloads gated behind platform/CI/env checks | Multi-env Sandbox |

## Architecture: 5 Independent Detection Engines

```
Untrusted Code → [AST Patterns] → [Taint Tracking] → [Symbolic Resolver] → [Sandbox Execution] → [Binary Parsers]
                       ↓                  ↓                    ↓                     ↓                    ↓
                 Known patterns    Dataflow to sinks    Resolve obfuscation    Run & observe        Parse opcodes
```

An attacker must bypass ALL FIVE engines simultaneously. The sandbox is the backstop — it actually runs the code and captures every exec/eval/import attempt.

## Usage

```bash
# Scan local model directory
hf-scanner ./model --mode local --fail-on high

# Scan with sandbox (catches ALL obfuscation, slightly slower)
hf-scanner ./model --mode local --sandbox --fail-on critical

# Scan HuggingFace repo remotely (checks org identity too)
hf-scanner meta-llama/Llama-3-8B --mode remote --format json

# Generate SARIF for GitHub Code Scanning
hf-scanner . --mode local --format sarif --output results.sarif

# Temporal rug-pull detection
hf-scanner ./model --save-baseline baseline.json    # First scan
hf-scanner ./model --baseline baseline.json         # Later: detect changes

# Generate runtime sandbox policy
hf-scanner ./model --runtime-policy policy.json
```

## Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| Text | `--format text` | Terminal / human review |
| JSON | `--format json` | CI/CD pipelines |
| SARIF | `--format sarif` | GitHub/GitLab Code Scanning |
| HTML | `--format html` | Standalone reports |

## CI/CD Integration (2 minutes)

### GitHub Actions
```yaml
- run: pip install git+https://github.com/poojakira/hf-model-provenance-scanner.git
- run: hf-scanner . --mode local --format sarif --output results.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### GitLab CI
```yaml
scan:
  script:
    - pip install git+https://github.com/poojakira/hf-model-provenance-scanner.git
    - hf-scanner . --mode local --format json --fail-on high > report.json
  artifacts:
    reports:
      sast: report.json
```

### Docker
```bash
docker build -t hf-scanner .
docker run --rm -v $(pwd):/workspace hf-scanner /workspace --mode local --fail-on high
```

### Pre-commit Hook
```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/poojakira/hf-model-provenance-scanner
    rev: main
    hooks:
      - id: hf-scanner
```

See [INTEGRATION.md](INTEGRATION.md) for Jenkins, Azure Pipelines, CircleCI, and HuggingFace webhook setup.

## Verified Detection Results

| Test Suite | Attacks | Detected | FP |
|---|---|---|---|
| Core incidents (documented CVEs) | 12 | 12 (100%) | 0 |
| Extended variants (env gating, generators, decorators) | 18 | 18 (100%) | 0 |
| Large-scale (multi-MB pickle, 300-line code, 288-tensor SafeTensors) | 3 | 3 (100%) | 0 |
| Real HuggingFace models (GPT-2, Llama-3-8B structure) | 2 | 0 findings ✅ | 0 |

Run the proof yourself:
```bash
python3 tests/redteam/simulate_attacks.py      # 12/12 detected
python3 tests/redteam/extended_attacks.py      # 18/18 detected
python3 tests/redteam/test_large_scale.py      # Multi-MB files pass
```

## Requirements

- **Python 3.9+** (no external dependencies — stdlib only)
- **Works on**: Linux, macOS, Windows
- **Optional**: cosign/gpg/minisign (for signature verification)

## Documentation

- [INTEGRATION.md](INTEGRATION.md) — CI/CD setup for all platforms
- [LIMITATIONS.md](LIMITATIONS.md) — Honest capabilities and known gaps
- [RESEARCH_ASSESSMENT.md](RESEARCH_ASSESSMENT.md) — Independent security review
- [evidence/](evidence/) — Incident report and detection proof

## License

Apache-2.0

## Component Status

| Component | Status | Details |
|-----------|--------|---------|
| eBPF kernel module | Requires root + Linux kernel 4.14+ | Skeleton in `scanner/analyzer/runtime_monitor.py` |
| gVisor/Firecracker sandbox | Optional backend | Configured via `HF_SANDBOX_BACKEND` env var |
| SIEM integration | Webhook/fluentd forwarder | Stub in `_log_to_siem` in `runtime_monitor.py` |
| Model server integration | FastAPI/Triton wrapper | See `deploy_protection.py` |

## Advanced Detection Rules (v0.3+)

| Rule Range | Category | Count | Key Capabilities |
|------------|----------|-------|------------------|
| HFS-100 to HFS-119 | Runtime/Behavioral | 20 | Process injection, DLL hijack, container escape, GPU exploits, egress exfiltration, side-channels, memory dump, privilege escalation, anti-debug, self-modifying code, ROP chains, cryptominers, firmware access, syscall anomalies, supply-chain webhooks, model extraction, adversarial inputs, backdoor triggers, gradient leakage, speculative execution |
| HFS-120 to HFS-139 | ML Supply Chain | 20 | Dependency confusion, ML package typosquat, CI/CD compromise, registry poisoning, dataset poisoning, MLOps tampering, feature store injection, secret leakage, unverified base models, license violations, SLSA compliance, HF token compromise, model card XSS, framework CVEs, hardware trojans, ONNX/TensorRT/CoreML/TFLite/MLIR exploits |
| HFS-140 to HFS-159 | Zero-Day/Unknown | 20 | Unknown pickle opcodes, weight entropy anomalies, custom activation abuse, gradient masking, FL poisoning, model inversion, quantization backdoors, distillation extraction, prompt injection, jailbreak patterns, RAG poisoning, tool hijacking, multimodal steganography, constitutional AI bypass, watermark removal, speculative decoding hijack, KV cache poisoning, prefix tuning injection, LoRA adapter malicious, RLHF reward hacking |
| HFS-160 to HFS-170 | Hardware/Firmware | 11 | Rowhammer weight flips, GPU side-channels, TPU glitching, secure enclave bypass, firmware rootkits, DMA interposer attacks, power analysis, EM emanation, acoustic side-channels, thermal side-channels, quantum readiness |
| HFS-171 to HFS-189 | Compliance/Governance | 19 | EU AI Act, NIST AI RMF, GDPR Art.22, HIPAA PHI, export controls, copyright training data, bias discrimination, carbon footprint, insurance gaps, audit trails, incident response, shadow ML, model drift, explainability gaps, red-team gaps, SBOM completeness, attestation verification |

**Total: 151 rules** (was 61 in v0.2)

## Attacker and User Runbook

See [ATTACKER_AND_USER_RUNBOOK.md](ATTACKER_AND_USER_RUNBOOK.md) for normal user/operator commands and safe [TEST-ONLY] adversarial regression commands.
