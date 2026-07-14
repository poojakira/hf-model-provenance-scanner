# HF Model Provenance Scanner

Stdlib-only ML supply chain security scanner for Hugging Face model repositories.

**30/30 included attack reproductions detected | 0 false positives in the included proof suite | stdlib-only runtime | Python 3.9+**

Tested against GPT-2 and Llama-3-8B-style repository structures. Validated against selected documented Hugging Face supply-chain attack reproductions from 2025-2026, including the May 2026 fake OpenAI incident (reported 244K downloads).

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

The engines provide overlapping coverage, so an attacker may need to evade multiple checks. The sandbox can execute selected code paths and capture observed exec/eval/import attempts, subject to timeout and environment coverage.

## Usage

```bash
# Scan local model directory
hf-scanner ./model --mode local --fail-on high

# Scan with sandbox (adds runtime coverage for some obfuscation, slightly slower)
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

- [INTEGRATION.md](INTEGRATION.md) — CI/CD setup examples
- [LIMITATIONS.md](LIMITATIONS.md) — Honest capabilities and known gaps
- [RESEARCH_ASSESSMENT.md](RESEARCH_ASSESSMENT.md) — Skeptical security assessment
- [evidence/](evidence/) — Incident report and detection proof

## License

Apache-2.0
