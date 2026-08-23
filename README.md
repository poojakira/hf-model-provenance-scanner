# HF Model Provenance Scanner

Scans Hugging Face model repositories for pickle exploits, supply-chain signals, and provenance issues without downloading full model weights.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue)](https://www.python.org/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Tests](https://github.com/poojakira/hf-model-provenance-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/poojakira/hf-model-provenance-scanner/actions/workflows/ci.yml)

## Status

Alpha. This scanner is functional and passes 262 tests (7 skipped due to optional dependencies not installed: 4 require `attack-v19-core` for MITRE ATT&CK mapping, 3 require Linux for sandbox execution). It has scanned the top 100 most-downloaded HuggingFace models successfully. Use it as one signal among many in your model security workflow, not as a sole gatekeeper.

## Architecture

```
Hugging Face Model Repository
        │
        │  HTTP Range: first 512KB per file
        ▼
┌─────────────────────────────────────────────────────┐
│           FILE FORMAT ROUTER                         │
│  .pkl/.bin → Pickle analyzer                        │
│  .safetensors → Header inspector                    │
│  .gguf → Structural parser                          │
│  .onnx → Operator scanner                           │
│  .h5/.keras → Lambda layer detector                 │
│  config.json → Code injection scanner               │
└───────────────────────┬─────────────────────────────┘
                        ▼
┌─────────────────────────────────────────────────────┐
│           TAINT ENGINE                              │
│  • Opcode-level walk (Protocol 0-5)                 │
│  • REDUCE/GLOBAL/STACK_GLOBAL tracking              │
│  • Call-chain resolution to dangerous sinks:        │
│    os.system, subprocess.Popen, eval, exec,         │
│    importlib.import_module + getattr                 │
│  • Memoized-global exec detection                   │
│  • Multi-layer obfuscation decode:                  │
│    base64, chr(), string concat                     │
└───────────────────────┬─────────────────────────────┘
                        ▼
┌─────────────────────────────────────────────────────┐
│           SYMBOLIC RESOLVER                         │
│  • Gadget-chain matching                            │
│  • importlib bypass detection                       │
│  • Cross-reference with known CVE patterns          │
└───────────────────────┬─────────────────────────────┘
                        ▼
┌─────────────────────────────────────────────────────┐
│           SUPPLY-CHAIN SIGNALS                      │
│  • Typosquat detection (Levenshtein distance)       │
│  • Temporal baseline diffing (rug-pull detection)   │
│  • Author/org name similarity                       │
└───────────────────────┬─────────────────────────────┘
                        ▼
┌─────────────────────────────────────────────────────┐
│           OUTPUT                                    │
│  • SARIF 2.1                                        │
│  • CycloneDX 1.5 SBOM                              │
│  • MITRE ATT&CK v19 mapping                        │
│  • Text / JSON                                      │
└─────────────────────────────────────────────────────┘
```

## What It Detects

### Pickle Code Execution
- REDUCE/GLOBAL/STACK_GLOBAL gadget chains leading to `os.system`, `subprocess.Popen`, `eval`, `exec`
- Memoized-global exec patterns (GLOBAL pushing dangerous callables onto memo stack)
- `importlib.import_module` + `getattr` loader bypasses
- Multi-layer obfuscation: `base64.b64decode`, `chr()` concatenation, nested string decodes
- Full coverage of Protocols 0 through 5

### SafeTensors
- Oversized headers indicating embedded payloads
- Tensor names with path traversal sequences
- Size mismatches between header declaration and actual data

### GGUF
- Invalid magic bytes
- Metadata fields containing executable content

### Supply-Chain Signals
- Typosquatting via Levenshtein distance to popular model names
- Temporal baseline diffing for rug-pull detection (file hashes change after publication without version bump)
- Author/org name similarity to known publishers

## Quick Start

```bash
git clone https://github.com/poojakira/hf-model-provenance-scanner.git
cd hf-model-provenance-scanner
pip install -e .

# Scan bert-base-uncased
hf-scanner bert-base-uncased --format text

# SARIF output
hf-scanner bert-base-uncased --format sarif --output findings.sarif

# Fail CI on critical findings
hf-scanner bert-base-uncased --fail-on critical
```

## Sample Output

Clean scan:
```
Risk: LOW (0/100)


8 findings (0 critical, 0 high, 0 medium)
```

Malicious model detected (local scan on fixtures):
```
Risk: CRITICAL (100/100)
  - 6 critical findings
  - 3 high findings
  - 4 medium findings
  - High-signal active threat indicators detected

[CRITICAL] HFS-050 malicious_os_system.pkl:0 - Pickle file contains opcode invoking
  dangerous callable (os.system, subprocess, exec, eval, etc.)
[CRITICAL] HFS-001 privacy_filter_loader.py:0 - powershell-subprocess (decoded layer 0)
[HIGH] HFS-056 malicious_metadata.gguf:0 - GGUF metadata key-value contains suspicious
  content (URLs, scripts, shell commands)
```

SARIF output (`--format sarif`):
```json
{
  "ruleId": "HFS-001",
  "level": "error",
  "message": {
    "text": "powershell-subprocess (decoded layer 0)"
  },
  "locations": [{
    "physicalLocation": {
      "artifactLocation": {"uri": "malicious/privacy_filter_loader.py"},
      "region": {"startLine": 1, "startColumn": 1}
    }
  }],
  "properties": {
    "evidence": "[decoded] matches powershell"
  }
}
```

## CI Integration

```yaml
name: Model Supply-Chain Scan
on:
  pull_request:
    paths: ['models/**']

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install scanner
        run: pip install -e .

      - name: Scan model files
        run: |
          hf-scanner ${{ env.MODEL_REPO }} \
            --format sarif \
            --output findings.sarif \
            --fail-on critical
        env:
          HF_TOKEN: ${{ secrets.HF_TOKEN }}

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: findings.sarif
          category: model-provenance
```

## Performance

Uses HTTP Range requests to fetch only file headers (typically <1MB) instead of downloading full model weights.

## Standards Coverage

| Standard | Integration |
|----------|------------|
| SARIF 2.1 | Full findings output with physical locations |
| CycloneDX 1.5 | Software Bill of Materials generation (`--aibom`) |
| MITRE ATT&CK v19 | Technique ID mapping (requires `pip install -e ".[attack]"`) |
| CVE database | Cross-reference with known pickle CVEs (CVE-2024-5480, CVE-2024-25664) |

## Contributing

If you find a gadget-chain pattern this scanner misses, open an issue with a reproducer. Include a fixture file demonstrating detection with your PR.

## License

Apache 2.0
