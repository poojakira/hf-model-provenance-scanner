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

# CI gate: fail on incomplete/indeterminate scans too (fail closed).
# Returns exit 1 if any file was skipped (PARTIAL) or a stream was
# unanalyzable (INDETERMINATE), in addition to the severity threshold.
python -m scanner.cli ./model -m local --enforce
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
# Run tests with the same coverage gate CI enforces (line coverage is
# currently ~64%; the CI gate is --cov-fail-under=55, not 80).
pytest tests/ -v --cov=scanner --cov-fail-under=55

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
  "scan_target": "/path/to/model",
  "scan_mode": "local",
  "scanner_version": "0.2.0",
  "findings": [],
  "org_check": null,
  "risk": {
    "score": 0,
    "level": "LOW",
    "reasons": []
  },
  "files_scanned": 5,
  "files_skipped": 0,
  "completeness": "COMPLETE",
  "skipped_files_detail": [],
  "artifact_revision": null,
  "scan_duration_seconds": 0.09,
  "error": null
}
```

The top-level keys are `scan_target`, `scan_mode`, `scanner_version`,
`findings` (array), `org_check`, `risk` (`{score, level, reasons}`),
`files_scanned`, `files_skipped`, `completeness`, `skipped_files_detail`,
`artifact_revision`, `scan_duration_seconds`, and `error`.

#### `completeness` — machine-readable "INCOMPLETE != CLEAN" signal

`completeness` is the single most important field for a CI gate. It is one of:

| Value | Meaning | Consumer action |
|-------|---------|-----------------|
| `COMPLETE` | Every in-scope file was scanned within limits. | A clean result is trustworthy. |
| `PARTIAL` | One or more files were skipped (oversized / unreadable / non-UTF-8). Skipped files are listed in `skipped_files_detail` and as `HFS-098` findings. | Do **not** treat a clean verdict as safe — a skipped file may hide a threat. Risk is auto-elevated (LOW→MEDIUM, MEDIUM/HIGH→HIGH). |
| `INDETERMINATE` | A scan error or an **unanalyzable stream** (e.g. a truncated/corrupt pickle, or an unknown pickle opcode → `HFS-096`) prevented full inspection. | Fail closed. A truncated pickle can execute code before deserialization finishes; it is unknown-risk, never clean. Risk is auto-elevated to at least HIGH. |
| `UNKNOWN` | Nothing was scanned / completeness could not be determined. | Investigate; treat as not-yet-verified. |

Use `--enforce` to make `PARTIAL`, `INDETERMINATE`, or `UNKNOWN` return a
non-zero exit code in addition to the severity threshold. This is the
recommended flag for deployment gates.

### Exit Codes

| Code | Condition |
|------|-----------|
| `0` | No finding at or above `--fail-on` threshold (and, under `--enforce`, completeness is `COMPLETE`). |
| `1` | A finding met/exceeded the `--fail-on` severity, **or** `--enforce` was set and completeness was not `COMPLETE`. |
| `2` | The scanner hit an unrecoverable exception (`error` is populated in the report). |
| `3` | Invalid invocation (e.g. `-m local` on a path that is not a local directory). |

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

### HF Hub Webhook Scan (`.github/workflows/hf-webhook-scan.yml`) — manual setup required

This workflow scans a repo automatically when Hugging Face fires a model-push
webhook. It is **manual-only** and does not run in this repository's default CI
because it requires configuration you must provide:

- `secrets.HF_TOKEN` — an HF token (used to read the target repo and,
  best-effort, post a discussion comment via `.github/scripts/post_hf_discussion.py`).
- A `repository_dispatch` event of type `hf_model_push` (wired from your HF
  webhook), **or** a manual `workflow_dispatch` run where you type the `repo_id`.
- gVisor (`runsc`) is downloaded at job start for stronger sandbox isolation.

The `notify-hf` job posts a summary back to the HF repo's discussions only on
`repository_dispatch`; if `HF_TOKEN` is unset or lacks discussion-write scope,
the post step logs a non-fatal message and the job still succeeds. The scan job
exposes `risk_level`, `risk_score`, `findings_count`, `critical_count`, and
`high_count` as job outputs for downstream steps.

To try it manually: Actions → "HF Hub Webhook Scan" → Run workflow → enter a
`repo_id` (requires `HF_TOKEN` to be configured in repo secrets).

---

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage (CI gate is 55%; actual line coverage ~64%)
pytest tests/ --cov=scanner --cov-report=html --cov-fail-under=55

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

Every item below was run end-to-end on Windows 11 / PowerShell with
Python 3.12.10 during the last docs pass. Exact numbers are current as of
that run; re-run to confirm on your platform.

- [x] Repository clones successfully
- [x] `pip install -e ".[dev]"` completes
- [x] `python -m scanner.cli --version` reports `hf-scanner 0.2.0`
- [x] `pytest tests/` is green: **195 passed, 2 skipped, 6 subtests passed**
- [x] Coverage gate: `pytest tests/ --cov=scanner --cov-fail-under=55` passes (line coverage **~64%**)
- [x] Scan a local target: `python -m scanner.cli <TARGET> -m local`
- [x] JSON output is valid and includes `completeness` / `skipped_files_detail`
- [x] SARIF output is valid (`tool.driver.name = hf-scanner`)
- [x] Detects known-bad pickle payloads (12/12 core red-team incidents, 18/18 extended variants)
- [x] Truncated / corrupt pickle fails **loud** as `INDETERMINATE` (never silently clean)
- [x] Benign ML-code samples produce **0 actionable false positives** in the extended red-team suite
- [x] Remote scan (`-m remote`): verified against the public `gpt2` repo — resolved to immutable SHA `607a30d…`, scanned 13 small files (config/tokenizer/code), and correctly marked the scan `PARTIAL` because 6 weight files (`model.safetensors`, `*.onnx`, `pytorch_model.bin`, `tf_model.h5`) exceed the 10 MB remote-download safety cap. PARTIAL surfaces "weights not inspected" rather than a false clean verdict.

### Remote scanning: what it does and doesn't cover

Remote (`-m remote`) mode pins the repo to an immutable commit SHA, then
downloads and scans files up to `MAX_DOWNLOAD_BYTES` (10 MB). Large weight
files above that cap are **not** downloaded; they are recorded as `HFS-098`
skips and the scan is reported `PARTIAL`. Redirects are restricted to
HF-owned hosts (`huggingface.co`, `hf.co`, and `*.cdn.hf.co` / `*.aws.cdn.hf.co`
Xet CDN); the bearer token is stripped on any CDN/cross-origin hop.

### False positives — what is and isn't claimed

We do **not** claim a "0% false-positive rate" against the space of real-world
models — no broad clean-model benchmark is committed. What is verified: the
committed benign samples in the extended red-team suite
(`tests/redteam/extended_attacks.py`) produce **zero actionable (non-INFO)
findings**. INFO-level capability notices (e.g. `HFS-SANDBOX-BACKEND`) are not
detections and are excluded from that count.

### Commands that cannot run in this environment (documented, not faked)

| Command | Why it can't run here | Expected behavior |
|---------|-----------------------|-------------------|
| `make dashboard` | Starts a blocking local HTTP server. | Serves `dashboard/realtime/index.html` on `http://localhost:8080`; Ctrl-C to stop. |
| `--sandbox` on a GPU/OS-gated payload | Sandbox cannot emulate all hardware. | Documented residual risk in `LIMITATIONS.md`. |
| `.github/workflows/hf-webhook-scan.yml` | Needs `secrets.HF_TOKEN`, gVisor, and the `repository_dispatch` trigger. | Manual-only; see "HF Hub Webhook Scan" above. |
| `make install-core` / `make data` / ATT&CK Navigator export | Require the sibling `attack-v19-core` package (the `attack` extra). | Without it, `scanner.attack_mapping.*` raises `ModuleNotFoundError: attack_v19_core`. Core scanning does not need it. |

> `-m remote` **does** work here: it was run end-to-end against `gpt2` (see the checklist above). It only needs outbound HTTPS to `huggingface.co`.

---

*Last updated: 2026-09-02*
*Verified on: Windows 11, PowerShell, Python 3.12.10 (end-to-end). CI matrix also runs Ubuntu + Python 3.10–3.12.*
