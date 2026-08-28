# Runbook: hf-model-provenance-scanner

**Repository:** https://github.com/poojakira/hf-model-provenance-scanner  
**Description:** Scan Hugging Face model repos for provenance, impersonation, pickle-risk, and supply-chain signals  
**License:** Apache-2.0  
**Default Branch:** main

---

## Prerequisites

- Python 3.10+
- Git
- One runtime dependency (`psutil`); see `requirements.txt`

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/poojakira/hf-model-provenance-scanner.git
cd hf-model-provenance-scanner

# Install in development mode
pip install -e ".[dev]"

# Scan a local model directory or file
python -m scanner.cli <TARGET> -m local

# Scan a Hugging Face repo (remote)
python -m scanner.cli org/model-name -m remote
```

`<TARGET>` is a positional argument: a local path (with `-m local`) or a
HuggingFace repo id such as `org/model-name` (with `-m remote`).

---

## Detailed Setup

### 1. Environment Setup

```bash
# Create virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate  # Linux/macOS

# Install development dependencies
pip install --upgrade pip
pip install -e ".[dev]"
```

### 2. Verify Installation

```bash
# Print version (should report hf-scanner 0.2.0)
python -m scanner.cli --version

# Run tests
pytest tests/ -v

# Quick scan test
python -m scanner.cli <TARGET> -m local --format json
```

---

## Usage

### Scan a Local Model Directory or File

```bash
# Basic local scan
python -m scanner.cli ./model -m local

# Scan a single file
python -m scanner.cli ./model.pkl -m local

# With JSON output
python -m scanner.cli ./model -m local --format json --output results.json

# With SARIF output for CI
python -m scanner.cli ./model -m local --format sarif --output results.sarif

# Verbose output
python -m scanner.cli ./model -m local --verbose

# Strongest detection (runs each Python file in a sandbox subprocess)
python -m scanner.cli ./model -m local --sandbox
```

### Scan a Hugging Face Repository (remote)

```bash
python -m scanner.cli org/model-name -m remote
python -m scanner.cli org/model-name -m remote --format sarif --output results.sarif
```

### Command-line Entry Points

There are two equivalent ways to run the scanner:

- `python -m scanner.cli <TARGET> -m local`
- `hf-scanner <TARGET> -m local` (after `pip install -e .`)

The scanner is driven entirely through this CLI; there is no separate
top-level Python function API to import.

---

## Detection Capabilities

| Check | Description |
|-------|-------------|
| **Pickle Opcode Analysis** | Zero-execution parsing of pickle opcodes (REDUCE, GLOBAL, BUILD, INST) |
| **SafeTensors / GGUF / ONNX / Keras** | Binary format validation and metadata inspection |
| **Source Code Analysis** | AST patterns, taint tracking, symbolic string resolution, optional sandbox execution |
| **Org Impersonation** | Detects typosquatting and impersonation attempts |
| **Provenance / SBOM** | Missing signature, SBOM, and provenance markers are flagged as risk signals |
| **Temporal Baselining** | Compares scan snapshots over time to detect rug-pulls |

---

## Available Commands

### Using Makefile

```bash
# Install runtime + dev tooling
make install

# Install the ATT&CK core dependency
make install-core

# Download ATT&CK data
make data

# Lint
make lint

# Format code
make format

# Run tests
make test

# Build package
make build

# Security scan (bandit + pip-audit)
make security

# Serve the realtime dashboard
make dashboard

# Full verification (lint + test + build + security)
make verify
```

### Direct Commands

```bash
# Run tests with coverage gate
pytest tests/ -v --cov=scanner --cov-fail-under=80

# Run specific test
pytest tests/test_pickle_scanner.py -v

# Format code
ruff format .

# Lint
ruff check .
```

---

## Output Formats

### JSON Output
```json
{
  "target": "/path/to/model",
  "scan_timestamp": "2026-08-16T12:00:00Z",
  "findings": [],
  "summary": {
    "total_files": 5,
    "files_scanned": 5,
    "findings_count": 0,
    "max_severity": "NONE"
  }
}
```

### SARIF Output
Standards-compliant SARIF 2.1.0 for GitHub Advanced Security integration
(SARIF `tool.driver.name` is `hf-scanner`).

### Text Output
Human-readable summary with color-coded severity.

---

## CI/CD Integration

### GitHub Actions
```yaml
- name: Scan Model
  run: |
    python -m scanner.cli ${{ inputs.model }} -m remote \
      --format sarif --output results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### Pre-commit Hook
```yaml
# .pre-commit-config.yaml
- repo: local
  hooks:
    - id: hf-scan
      name: HF Model Scan
      entry: python -m scanner.cli
      language: system
      types: [file]
```

---

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=scanner --cov-report=html --cov-fail-under=80

# Run specific test modules
pytest tests/test_pickle_scanner.py -v
pytest tests/test_safetensors_scanner.py -v
pytest tests/test_integration_hf.py -v
pytest tests/test_cli.py -v
```

---

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| `ModuleNotFoundError: scanner` | Run `pip install -e .` from the repo root |
| Network timeout on HF API | Scan local files with `-m local` |
| Permission denied | Ensure read access to model files |
| Sandbox scan is slow | Each Python file runs in a subprocess (30s timeout); omit `--sandbox` for faster scans |

### Debug Mode

```bash
# Verbose output (includes info-level findings)
python -m scanner.cli <TARGET> -m local --verbose
```

---

## Repository Structure

```
hf-model-provenance-scanner/
├── .github/workflows/     # CI/CD pipelines
├── scanner/               # Main package
│   ├── __init__.py
│   ├── cli.py             # Command-line interface
│   ├── analyzer/          # Analysis engines (pickle_scanner.py, safetensors_scanner.py, ...)
│   ├── rules/
│   │   └── definitions.py # Rule() objects (HFS-XXX detections)
│   ├── formatters/        # sarif_formatter.py, json_formatter.py, html_formatter.py
│   ├── attack_mapping/    # ATT&CK enrichment
│   ├── utils/             # helpers (hf_api.py, entropy.py, levenshtein.py, ...)
│   ├── provenance.py
│   ├── risk.py
│   └── models.py
├── tests/                 # Test suite
├── benchmarks/            # scan_perf.py
├── pyproject.toml
├── requirements.txt
├── README.md
├── LICENSE
├── Makefile
└── CHANGELOG.md
```

---

## Links

- **Repository:** https://github.com/poojakira/hf-model-provenance-scanner
- **PyPI:** (if published)
- **Documentation:** See `README.md` and `docs/`

---

## Verification Checklist

- [ ] Repository clones successfully
- [ ] `pip install -e .` completes
- [ ] `python -m scanner.cli --version` reports `hf-scanner 0.2.0`
- [ ] `pytest tests/` passes with coverage ≥80% (`--cov=scanner`)
- [ ] Scan local target: `python -m scanner.cli <TARGET> -m local`
- [ ] Scan remote repo works
- [ ] JSON output valid
- [ ] SARIF output valid
- [ ] No false positives on known-good models
- [ ] Detects known-bad pickle payloads

---

*Last updated: 2026-08-27*  
*Tested on: Ubuntu 22.04, Python 3.10–3.12, macOS 14, Windows 11 (WSL2)*
