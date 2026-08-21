# RUNBOOK  --  HF Model Provenance Scanner

## Prerequisites

- Python 3.10+
- Docker (optional, for container usage)
- Hugging Face token (optional, for private/gated models): `export HF_TOKEN=hf_...`

## Install

```bash
git clone <repo-url> && cd hf-model-provenance-scanner
python -m venv .venv && source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Scan a Model Repo

```bash
# Scan by repo ID
hf-scanner bert-base-uncased

# Scan with specific output format
hf-scanner bert-base-uncased --format sarif --output findings.sarif

# With severity threshold
hf-scanner microsoft/phi-2 --fail-on critical
```

Checks performed: pickle exploit detection, unsigned weights, missing model cards, suspicious commit history, dependency confusion in configs.

## Batch Scanning

```bash
# From a file (one repo ID per line)
hf-scanner --manifest manifest.txt --format json --output results/

# Fail CI on critical findings
hf-scanner --manifest manifest.txt --fail-on critical
```

## CI Integration

```yaml
# GitHub Actions
- name: Scan Model Provenance
  run: |
    pip install hf-model-provenance-scanner
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
| `401 Unauthorized` | Missing/invalid HF token | Set `HF_TOKEN`, verify with `huggingface-cli whoami` |
| `Model not found` | Typo or private repo without token | Check repo ID on huggingface.co, ensure token has read access |
| Scan hangs on large model | Downloading full weights | Use `--metadata-only` to skip weight analysis |
| Pickle false positive | Custom serialization format | Add to `.hf-provenance-ignore` or use `--ignore-rules` |
| Rate limited by HF API | Too many requests | Reduce `--workers`, add `--delay 2` between requests |
