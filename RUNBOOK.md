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

## Verify Installation

```bash
hf-scanner --version
hf-scanner --help
pytest --tb=short -q
```

## Scan a Model Repo

```bash
# Scan by repo ID (text output to terminal)
hf-scanner bert-base-uncased --format text

# SARIF output to file
hf-scanner bert-base-uncased --format sarif --output findings.sarif

# JSON output
hf-scanner bert-base-uncased --format json --output results.json

# With severity threshold (exit code 1 if findings >= threshold)
hf-scanner bert-base-uncased --fail-on critical

# With telemetry logging
hf-scanner bert-base-uncased --format text --log-level INFO

# Generate CycloneDX AI BOM
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

# Disable network access entirely
hf-scanner ./my-model-dir --no-network
```

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

## Model Quality Evaluation

Check bias, drift, and accuracy:

```python
from scanner.quality import ModelQualityEvaluator

evaluator = ModelQualityEvaluator()
report = evaluator.evaluate(
    predictions=[1, 0, 1, 1, 0, 1, 0, 0],
    labels=[1, 0, 1, 0, 0, 1, 0, 1],
    groups=["A", "A", "A", "A", "B", "B", "B", "B"],
    reference_dist=[0.5, 0.6, 0.4, 0.55, 0.45, 0.5, 0.6, 0.4]
)
print(f"Overall pass: {report.overall_pass}")
print(f"Bias passed: {report.bias_report.passed}")
print(f"Drift severity: {report.drift_report.severity}")
print(f"Accuracy passed: {report.accuracy_report.passed}")
print(report.to_json())
```

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

## Temporal / Rug-Pull Detection

```bash
# Save a baseline of current model state
hf-scanner bert-base-uncased --save-baseline baselines/bert.json

# Later: compare against baseline to detect silent changes
hf-scanner bert-base-uncased --baseline baselines/bert.json
```

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
# Run the full attack simulation suite (12 real-world attack reproductions)
python tests/redteam/simulate_attacks.py

# Run red-team pytest suite
pytest tests/redteam/ -v
```

## Telemetry

```bash
# Enable structured JSON logging to stderr
hf-scanner bert-base-uncased --log-level INFO

# Log to a file
hf-scanner bert-base-uncased --log-file scan.log --log-level DEBUG

# Disable telemetry entirely
hf-scanner bert-base-uncased --no-telemetry
```

## CI Integration

```yaml
# GitHub Actions
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

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `401 Unauthorized` | Missing/invalid HF token | Set `HF_TOKEN` env var, or pass `--token <token>` |
| `Model not found` | Typo or private repo without token | Check repo ID on huggingface.co, ensure token has read access |
| `ConnectionError` | Network issues or HF Hub down | Check network, try `--no-network` for local scans |
| Pickle false positive | Custom serialization format | File an issue with reproducer |
| Rate limited by HF API | Too many requests in batch scanning | Add delay between scans in your batch script |
| Slow scan | Large binary files | Use `--skip-binary` or reduce `--max-binary-mb` |
