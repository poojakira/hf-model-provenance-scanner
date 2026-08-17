# Runbook: hf-model-provenance-scanner

**Repository:** https://github.com/poojakira/hf-model-provenance-scanner  
**Description:** Scan Hugging Face model repos for provenance, impersonation, pickle-risk, and supply-chain signals  
**License:** MIT  
**Default Branch:** main

---

## Prerequisites

- Python 3.11+
- Git
- No runtime dependencies (stdlib only)

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/poojakira/hf-model-provenance-scanner.git
cd hf-model-provenance-scanner

# Install in development mode
pip install -e ".[dev]"

# Scan a Hugging Face model
python -m hf_scanner scan --repo-id microsoft/phi-2

# Scan local model file
python -m hf_scanner scan --local-path ./model.safetensors
```

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

### 2. Configuration

The scanner works offline with zero runtime dependencies. Optional configuration:

```bash
# Copy example config
cp config.example.yaml config.yaml

# Edit config.yaml for custom rules:
# - Custom pickle opcodes to flag
# - Trusted organization list
# - Output format preferences
```

### 3. Verify Installation

```bash
# Run tests
pytest tests/ -v

# Run smoke test
./smoke_test.sh

# Quick scan test
python -m hf_scanner scan --repo-id microsoft/phi-2 --format json
```

---

## Usage

### Scan Hugging Face Repository

```bash
# Basic scan
python -m hf_scanner scan --repo-id <org/model-name>

# With JSON output
python -m hf_scanner scan --repo-id microsoft/phi-2 --format json --output results.json

# With SARIF output for CI
python -m hf_scanner scan --repo-id microsoft/phi-2 --format sarif --output results.sarif

# Verbose output
python -m hf_scanner scan --repo-id microsoft/phi-2 -v
```

### Scan Local Model Files

```bash
# Scan .safetensors file
python -m hf_scanner scan --local-path ./model.safetensors

# Scan .pkl/.pt file
python -m hf_scanner scan --local-path ./model.pkl

# Scan directory of models
python -m hf_scanner scan --local-path ./models/ --recursive
```

### Python API

```python
from hf_scanner import scan_repo, scan_local

# Scan HF repo
result = scan_repo("microsoft/phi-2")
print(result.summary)

# Scan local file
result = scan_local("./model.safetensors")
print(result.findings)

# Get detailed findings
for finding in result.findings:
    print(f"{finding.severity}: {finding.message}")
```

---

## Detection Capabilities

| Check | Description |
|-------|-------------|
| **Pickle Opcode Analysis** | AST-walk detection of dangerous opcodes (REDUCE, GLOBAL, BUILD) |
| **SafeTensors Validation** | Validates SafeTensors format integrity |
| **Org Impersonation** | Detects typosquatting and impersonation attempts |
| **Metadata Analysis** | Suspicious metadata, missing provenance |
| **Signature Verification** | Ed25519 signature verification |
| **SLSA Provenance** | Checks for SLSA v1.0 provenance attestation |

---

## Available Commands

### Using Makefile

```bash
# Show all targets
make help

# Run tests
make test

# Run linting
make lint

# Type checking
make typecheck

# Security scan
make security

# Build package
make build

# Clean
make clean
```

### Direct Commands

```bash
# Run tests
pytest tests/ -v --cov=hf_scanner --cov-fail-under=80

# Run specific test
pytest tests/test_pickle_scan.py -v

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
  "repo_id": "microsoft/phi-2",
  "scan_date": "2026-08-16T12:00:00Z",
  "summary": {
    "pickle_risk": "LOW",
    "impersonation_risk": "NONE",
    "provenance_verified": true,
    "safetensors_valid": true
  },
  "findings": []
}
```

### SARIF Output
Standards-compliant SARIF for GitHub Advanced Security integration.

### Text Output
Human-readable summary with color-coded severity.

---

## CI/CD Integration

### GitHub Actions
```yaml
- name: Scan Model
  run: |
    python -m hf_scanner scan --repo-id ${{ inputs.model }} \
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
      entry: python -m hf_scanner scan
      language: system
      types: [file]
      args: [--local-path, --format, sarif]
```

---

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=hf_scanner --cov-report=html --cov-fail-under=80

# Run specific test modules
pytest tests/test_pickle_scan.py -v
pytest tests/test_safetensors.py -v
pytest tests/test_impersonation.py -v
pytest tests/test_provenance.py -v
```

---

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| `ModuleNotFoundError: hf_scanner` | Run `pip install -e .` |
| Network timeout on HF API | Use `--offline` flag for local files only |
| Permission denied | Ensure read access to model files |
| Large model memory issues | Use streaming mode: `--streaming` |

### Debug Mode

```bash
# Enable debug logging
python -m hf_scanner scan --repo-id microsoft/phi-2 -vvv

# Dry run (no network calls)
python -m hf_scanner scan --repo-id microsoft/phi-2 --dry-run
```

---

## Repository Structure

```
hf-model-provenance-scanner/
├── .github/workflows/     # CI/CD pipelines
├── hf_scanner/            # Main package
│   ├── __init__.py
│   ├── cli.py             # Command-line interface
│   ├── pickle_scan.py     # Pickle opcode analysis
│   ├── safetensors.py     # SafeTensors validation
│   ├── impersonation.py   # Org impersonation detection
│   ├── provenance.py      # Provenance verification
│   └── output.py          # Output formatters
├── tests/                 # Test suite
├── config.example.yaml
├── pyproject.toml
├── README.md
├── LICENSE
├── Makefile
├── requirements-dev.txt
├── smoke_test.sh
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
- [ ] `pytest tests/` passes with coverage ≥80%
- [ ] Scan HF repo: `python -m hf_scanner scan --repo-id microsoft/phi-2`
- [ ] Scan local file works
- [ ] JSON output valid
- [ ] SARIF output valid
- [ ] No false positives on known-good models
- [ ] Detects known-bad pickle payloads

---

*Last updated: 2026-08-16*  
*Tested on: Ubuntu 22.04, Python 3.11, 3.12, macOS 14, Windows 11 (WSL2)*