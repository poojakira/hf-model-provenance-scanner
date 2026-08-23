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
hf-scanner microsoft/phi-2 --fail-on critical

# With telemetry logging
hf-scanner bert-base-uncased --format text --log-level INFO

# Generate CycloneDX AI BOM
hf-scanner bert-base-uncased --aibom bom.json
```

Checks performed: pickle exploit detection, safetensors header inspection, GGUF structural validation, typosquat detection, config injection scanning.

## Batch Scanning

The scanner processes one model at a time. For batch scanning, use a shell loop:

```bash
# From a file (one repo ID per line)
while IFS= read -r repo; do
  hf-scanner "$repo" --format json --output "results/${repo//\//_}.json" --fail-on critical
done < models.txt
```

Or use the top-100 scan script:

```bash
python scripts/scan_top100.py --limit 10 --delay 2
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

## Temporal / Rug-Pull Detection

```bash
# Save a baseline of current model state
hf-scanner bert-base-uncased --save-baseline baselines/bert.json

# Later: compare against baseline to detect silent changes
hf-scanner bert-base-uncased --baseline baselines/bert.json
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

## Red Team Testing

```bash
# Run the full attack simulation suite
python tests/redteam/simulate_attacks.py

# Run red-team pytest suite
pytest tests/redteam/ -v

# See docs/RED_TEAM_GUIDE.md for writing new attack fixtures
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

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `401 Unauthorized` | Missing/invalid HF token | Set `HF_TOKEN` env var, or pass `--token <token>` |
| `Model not found` | Typo or private repo without token | Check repo ID on huggingface.co, ensure token has read access |
| `ConnectionError` | Network issues or HF Hub down | Check network, try `--no-network` for local scans |
| Pickle false positive | Custom serialization format | File an issue with reproducer |
| Rate limited by HF API | Too many requests in batch scanning | Add delay between scans in your batch script |
| Slow scan | Large binary files | Use `--skip-binary` or reduce `--max-binary-mb` |
