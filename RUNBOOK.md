# RUNBOOK -- HF Model Provenance Scanner

## Prerequisites

- Python 3.10+
- Docker (optional, for container usage)
- Hugging Face token (optional, for private/gated models): `export HF_TOKEN=hf_...`

## Install

```bash
git clone https://github.com/poojakira/hf-model-provenance-scanner.git
cd hf-model-provenance-scanner
python -m venv .venv && source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Entry point defined in `pyproject.toml` under `[project.scripts]`:
- `hf-scanner` → `scanner.cli:main`

## Verify Installation

```bash
hf-scanner --version
hf-scanner --help
pytest tests/ --tb=short -q
```

## Scan a Model Repo

```bash
# Scan by repo ID (text output to terminal)
hf-scanner bert-base-uncased --format text

# SARIF output to file
hf-scanner bert-base-uncased --format sarif --output findings.sarif

# JSON output
hf-scanner bert-base-uncased --format json --output results.json

# HTML output
hf-scanner bert-base-uncased --format html --output report.html

# With severity threshold (exit code 1 if findings >= threshold; default is --fail-on high)
hf-scanner bert-base-uncased --fail-on critical

# With telemetry logging
hf-scanner bert-base-uncased --log-level INFO

# Generate CycloneDX AI BOM (writes to specified file)
hf-scanner bert-base-uncased --aibom bom.json
```

## Scan Modes

```bash
# Remote only (fetch from HuggingFace Hub via HTTP Range requests)
hf-scanner bert-base-uncased -m remote

# Local only (scan a local directory)
hf-scanner ./my-model-dir -m local

# Both local and remote (default)
hf-scanner bert-base-uncased -m both

# Disable network access entirely (forces local; fails if target requires network)
hf-scanner ./my-model-dir --no-network
```

## CLI Flags Reference

| Flag | Description |
|------|-------------|
| `--format {json,sarif,text,html}` | Output format (default: text for TTY, json for pipe) |
| `--output FILE` | Write report to file instead of stdout |
| `--fail-on {critical,high,medium,low,info,never}` | Exit 1 if findings >= severity (default: high) |
| `-m, --mode {local,remote,both}` | Scan mode (default: both) |
| `--no-network` | Force local mode |
| `--token TOKEN` | HF API token (overrides `HF_TOKEN` env var) |
| `--baseline FILE` | Baseline JSON for temporal/rug-pull detection |
| `--save-baseline FILE` | Save current scan state as baseline |
| `--aibom FILE` | Generate CycloneDX AI BOM to FILE |
| `--skip-binary` | Skip binary model scanning (pickle, safetensors, GGUF) |
| `--max-binary-mb N` | Max binary file size in MB (default: 100) |
| `--sandbox` | Enable sandbox execution for code analysis |
| `--protect` | Enable runtime protection checks |
| `--protect-config FILE` | Runtime protection config JSON |
| `--runtime-policy FILE` | Write hardened runtime sandbox policy JSON to FILE |
| `--config FILE` | Path to config file (default: .hf-scanner.toml) |
| `--log-file FILE` | Write structured JSON telemetry to FILE |
| `--log-level {DEBUG,INFO,WARNING,ERROR}` | Telemetry log level (default: WARNING) |
| `--no-telemetry` | Disable telemetry and structured logging |
| `--verbose` | Include INFO findings in output |
| `-q, --quiet` | Suppress all output except exit code |

## Runtime Inference Protection

Intercepts model loading calls and blocks malicious models before execution.

```python
# In your application code:
from scanner.runtime import enable_protection
enable_protection()

# Now torch.load() and AutoModel.from_pretrained() are guarded
import torch
model = torch.load("model.pt")  # Scanned before loading; blocked if malicious
```

Or via environment variable (no code changes needed):

```bash
export HF_SCANNER_PROTECT=1
python your_inference_script.py
```

Source: `scanner/runtime/__init__.py` → `scanner/runtime/interceptor.py`

## Provenance Ledger

Track who did what when with cryptographic proof:

```python
from scanner.provenance import ProvenanceLedger, verify_ledger
from scanner.signing.ed25519 import ModelSigner

# Generate keypair (or load existing)
private_pem, public_pem = ModelSigner.generate_keypair()

# Create ledger
ledger = ProvenanceLedger("audit.jsonl", private_key_pem=private_pem, public_key_pem=public_pem)

# Record events
ledger.append_event("model_uploaded", actor="alice", subject="bert-v2", details={"source": "training-run-42"})
ledger.append_event("model_scanned", actor="ci-bot", subject="bert-v2", details={"risk": "LOW"})
ledger.append_event("model_deployed", actor="deploy-bot", subject="bert-v2", details={"env": "prod"})

# Verify chain integrity (detects tampering)
result = verify_ledger("audit.jsonl", public_pem)
print(f"Valid: {result.valid}")

# Query history
from scanner.provenance import who_modified, full_history
actors = who_modified(ledger, "bert-v2")
events = full_history(ledger, "bert-v2")
```

Source: `scanner/provenance/ledger.py`, `scanner/provenance/verifier.py`, `scanner/provenance/query.py`
Signing: `scanner/signing/ed25519.py` (requires `pip install -e ".[signing]"`)

## Temporal / Rug-Pull Detection

```bash
# Save a baseline of current model state
hf-scanner bert-base-uncased --save-baseline baselines/bert.json

# Later: compare against baseline to detect silent changes
hf-scanner bert-base-uncased --baseline baselines/bert.json
```

Source: `scanner/analyzer/temporal_scanner.py`

## Batch Scanning

```bash
# Use the top-100 scan script
python scripts/scan_top100.py --limit 10 --delay 2

# Or loop over a model list
while IFS= read -r repo; do
  hf-scanner "$repo" --format json --output "results/${repo//\//_}.json" --fail-on critical
done < models.txt
```

## Red Team Testing

```bash
# Run the full attack simulation suite
python tests/redteam/simulate_attacks.py

# Run red-team pytest suite
pytest tests/redteam/ -v

# Run extended attack simulations
python tests/redteam/extended_attacks.py
```

Source: `tests/redteam/simulate_attacks.py`, `tests/redteam/extended_attacks.py`, `tests/redteam/conftest.py`

## Telemetry

```bash
# Enable structured JSON logging to stderr
hf-scanner bert-base-uncased --log-level INFO

# Log to a file
hf-scanner bert-base-uncased --log-file scan.log --log-level DEBUG

# Disable telemetry entirely
hf-scanner bert-base-uncased --no-telemetry
```

Source: `scanner/telemetry.py`

## Linting and Development

```bash
# Lint (uses Ruff, configured in pyproject.toml)
ruff check scanner tests

# Auto-format
ruff format scanner tests

# Run full test suite with coverage
pytest tests/ -v --cov=scanner --cov-report=term-missing

# Build package
python -m build

# Makefile shortcuts (require attack-v19-core sibling checkout):
make lint
make test
make build
make security
make verify   # lint + test + build + security
```

## CI Integration

```yaml
# GitHub Actions example
- name: Scan Model Provenance
  run: |
    pip install -e .
    hf-scanner ${{ env.MODEL_REPO }} --format sarif --output provenance.sarif --fail-on critical
  env:
    HF_TOKEN: ${{ secrets.HF_TOKEN }}
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: provenance.sarif
```

## Docker Usage

```bash
docker build -t hf-scanner:latest .

# Single scan
docker run --rm -e HF_TOKEN=$HF_TOKEN hf-scanner:latest bert-base-uncased

# Mount local models
docker run --rm -v /path/to/models:/models hf-scanner:latest /models/my-model
```

## Project Layout

```
scanner/
├── cli.py              # CLI entry point (hf-scanner command)
├── config.py           # Policy-as-code loading from policy.yaml
├── models.py           # Finding, ScanResult, Severity data models
├── risk.py             # Risk scoring (0-100 scale)
├── telemetry.py        # Structured logging
├── runtime_policy.py   # Runtime sandbox policy formatter
├── aibom_generator.py  # CycloneDX AI BOM generation
├── monitor.py          # Process monitoring
├── monitor_cli.py      # Monitor CLI interface
├── url_scanner.py      # URL scanning
├── analyzer/           # Format-specific file analyzers
│   ├── pickle_scanner.py
│   ├── safetensors_scanner.py
│   ├── gguf_scanner.py
│   ├── onnx_scanner.py
│   ├── keras_scanner.py
│   ├── taint_engine.py
│   ├── symbolic_resolver.py
│   ├── obfuscation_scanner.py
│   ├── temporal_scanner.py
│   ├── weight_fingerprint.py
│   ├── sandbox_executor.py
│   ├── runtime_monitor.py
│   ├── ioc_feed.py
│   ├── shell_scanner.py
│   ├── config_scanner.py
│   ├── dependency_scanner.py
│   ├── org_checker.py
│   └── ast_visitor.py
├── rules/              # Detection rule definitions
├── attack_mapping/     # MITRE ATT&CK v19 technique mapping
├── provenance/         # Hash-chained Ed25519-signed event ledger
├── signing/            # Ed25519 key generation and verification
├── quality/            # Model quality evaluation (experimental, optional)
├── runtime/            # Runtime interception of torch.load / from_pretrained
├── sbom/               # CycloneDX SBOM generation
├── formatters/         # SARIF, JSON, text, HTML output
├── utils/              # HTTP Range client, Levenshtein, helpers
└── data/               # IOC feeds, CVE signatures, protected orgs list
```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `401 Unauthorized` | Missing/invalid HF token | Set `HF_TOKEN` env var, or pass `--token <token>` |
| `Model not found` | Typo or private repo without token | Check repo ID on huggingface.co, ensure token has read access |
| `ConnectionError` | Network issues or HF Hub down | Check network, try `--no-network` for local scans |
| Pickle false positive | Custom serialization format | File an issue with reproducer |
| Rate limited by HF API | Too many requests in batch scanning | Add delay between scans in your batch script |
| Slow scan | Large binary files | Use `--skip-binary` or reduce `--max-binary-mb` |
