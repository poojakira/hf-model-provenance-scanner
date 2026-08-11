# Runbook — HF Model Provenance Scanner v0.2.0

**Last updated:** 2026-08-08  
**Audience:** SREs, ML Platform Engineers, Security Engineers  
**Severity:** This tool detects supply chain attacks in ML models. If a flagged model reaches production, arbitrary code execution is possible.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Installation](#2-installation)
3. [Configuration (policy.yaml)](#3-configuration-policyyaml)
4. [Usage — Scanning Models](#4-usage--scanning-models)
5. [Output Formats](#5-output-formats)
6. [Fail Thresholds (CI Gating)](#6-fail-thresholds-ci-gating)
7. [Integration with Model Registries](#7-integration-with-model-registries)
8. [n8n Workflow Setup](#8-n8n-workflow-setup)
9. [Incident Response — Model Flagged](#9-incident-response--model-flagged)
10. [False Positive Handling](#10-false-positive-handling)
11. [Troubleshooting](#11-troubleshooting)
12. [Maintenance](#12-maintenance)

---

## 1. Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.10+ | Verify with `python --version` or `py --version` (Windows) |
| pip | Latest | Upgrade: `python -m pip install --upgrade pip` |
| psutil | ≥5.9 | Installed automatically as dependency |
| make | Any | Optional — convenience targets in Makefile |
| Git | Any | Only for install from source |

### Optional Dependencies

| Package | Purpose | Install |
|---------|---------|---------|
| attack-v19-core | ATT&CK technique mapping in findings | `pip install "hf-scanner[attack]"` |
| pytest, pytest-cov, ruff | Development and testing | `pip install "hf-scanner[dev]"` |

### Verify Prerequisites

**Windows (PowerShell):**
```powershell
py --version
# Expected: Python 3.10.x or higher

py -m pip --version
# Expected: pip 24.x from ...
```

**Linux / macOS (bash):**
```bash
python3 --version
# Expected: Python 3.10.x or higher

python3 -m pip --version
# Expected: pip 24.x from ...
```

---

## 2. Installation

### Option A: Install from Source (primary method)

**Windows (PowerShell):**
```powershell
git clone https://github.com/poojakira/hf-model-provenance-scanner.git
cd hf-model-provenance-scanner
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install --upgrade pip
py -m pip install -e .

# Verify installation
hf-scanner --version
# Expected: hf-scanner 0.2.0
```

**Linux / macOS (bash):**
```bash
git clone https://github.com/poojakira/hf-model-provenance-scanner.git
cd hf-model-provenance-scanner
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .

# Verify installation
hf-scanner --version
# Expected: hf-scanner 0.2.0
```

### Option B: Using the Install Scripts

**Windows (PowerShell):**
```powershell
.\install.ps1
```

**Linux / macOS (bash):**
```bash
chmod +x install.sh
./install.sh
```

### Option C: Using Make (Linux / macOS)

```bash
make install
# Installs all deps including dev tools

hf-scanner --version
# Expected: hf-scanner 0.2.0
```

### Option D: Docker

```bash
docker build -t hf-scanner .
docker run --rm -v $(pwd)/models:/scan hf-scanner /scan --format json
```

> **Note:** If PowerShell blocks venv activation, run `Set-ExecutionPolicy -Scope Process Bypass` first.

---

## 3. Configuration (policy.yaml)

The scanner ships with a secure-by-default `policy.yaml`. This file controls:

- **Pickle opcode allow-list** — Only safe, data-only opcodes are permitted. Dangerous opcodes (REDUCE, GLOBAL, STACK_GLOBAL, INST, OBJ, NEWOBJ) are implicitly denied.
- **Scan modes** — Which analyzers are active.
- **Severity thresholds** — What triggers blocking vs warning.

### Location

The scanner looks for `policy.yaml` in this order:
1. Path specified via `--config` flag
2. `./policy.yaml` (current working directory)
3. Built-in defaults (most restrictive)

### Customizing Rules

```yaml
# policy.yaml excerpt — add opcodes ONLY if you understand the security implications
allowed_opcodes:
  - MARK
  - STOP
  - EMPTY_DICT
  - EMPTY_LIST
  # ... see full file for complete list

# Scan mode configuration
scan_modes:
  pickle_analysis: true
  safetensors_validation: true
  gguf_inspection: true
  temporal_analysis: true
  obfuscation_detection: true
```

> **WARNING:** Adding REDUCE, GLOBAL, or STACK_GLOBAL to allowed_opcodes disables the primary defense against pickle deserialization attacks. Never do this in production.

---

## 4. Usage — Scanning Models

### Scan a Local Directory

```bash
hf-scanner ./models/ --mode local
```

**Expected output:**
```
Scanning: ./models/
Analyzers: pickle, safetensors, gguf, obfuscation, temporal
─────────────────────────────────────────────────
[CRITICAL] model.pkl: REDUCE opcode at offset 0x1A — arbitrary code execution possible
[HIGH]     config.json: Suspicious exec() reference in model_type field
─────────────────────────────────────────────────
2 findings (1 critical, 1 high)
Exit code: 1
```

### Scan a HuggingFace Hub Model

```bash
hf-scanner meta-llama/Llama-3.1-8B --mode hub
```

This downloads metadata and scans serialized artifacts from the HuggingFace Hub.

### Scan a Specific File

```bash
hf-scanner ./models/weights.pkl --mode local
```

### Scan with Custom Policy

```bash
hf-scanner ./models/ --mode local --config /path/to/.hf-scanner.toml
```

---

## 5. Output Formats

### JSON (for CI pipelines and programmatic use)

```bash
hf-scanner ./models/ --mode local --format json
```

**Expected output:**
```json
{
  "scan_target": "./models/",
  "scan_mode": "local",
  "findings": [
    {
      "severity": "CRITICAL",
      "file": "model.pkl",
      "rule": "pickle_dangerous_opcode",
      "message": "REDUCE opcode at offset 0x1A",
      "attack_technique": "T1059.006"
    }
  ],
  "summary": {"critical": 1, "high": 0, "medium": 0, "total": 1}
}
```

### SARIF (for GitHub Advanced Security)

```bash
hf-scanner ./models/ --mode local --format sarif > model-scan.sarif
```

Upload to GitHub Code Scanning or any SARIF viewer.

### HTML (for human-readable reports)

```bash
hf-scanner ./models/ --mode local --format html > report.html
```

Open in a browser for a styled, shareable report.

---

## 6. Fail Thresholds (CI Gating)

Control which severity levels cause a non-zero exit code:

```bash
# Fail only on critical findings (exit code 1)
hf-scanner ./models/ --mode local --fail-on critical

# Fail on high OR critical findings (default behavior)
hf-scanner ./models/ --mode local --fail-on high

# Fail on any finding (medium and above)
hf-scanner ./models/ --mode local --fail-on medium
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No findings at or above the `--fail-on` threshold |
| `1` | At least one finding at or above threshold |
| `2` | Runtime error (file not found, invalid policy, etc.) |

---

## 7. Integration with Model Registries

### Pre-deployment Gate

Add the scanner as a pre-deployment check in your model registry pipeline:

```bash
# Before promoting model from staging to production
hf-scanner s3://model-registry/my-model/v2.1/ --mode local --fail-on high --format json > scan-report.json

# If exit code is 0, proceed with deployment
# If exit code is 1, block and alert
```

### GitHub Actions Integration

```yaml
name: Model Security Scan

on:
  push:
    paths:
      - 'models/**'

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install scanner
        run: |
          git clone https://github.com/poojakira/hf-model-provenance-scanner.git /tmp/scanner
          pip install -e /tmp/scanner

      - name: Scan models
        run: |
          hf-scanner ./models/ --mode local --format sarif > model-scan.sarif
          hf-scanner ./models/ --mode local --fail-on high

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: model-scan.sarif
```

### GitLab CI Integration

```yaml
model-security-scan:
  stage: security
  image: python:3.12-slim
  before_script:
    - pip install git+https://github.com/poojakira/hf-model-provenance-scanner.git
  script:
    - hf-scanner ./models/ --mode local --format json > scan-results.json
    - hf-scanner ./models/ --mode local --fail-on high
  artifacts:
    reports:
      security: scan-results.json
    when: always
```

### HuggingFace Webhook Integration

Use `integrations/huggingface_webhook.py` to trigger scans on model upload events. See `INTEGRATION.md` for full setup.

---

## 8. n8n Workflow Setup

Full documentation: `integrations/N8N_WORKFLOW.md`

### Quick Setup

1. **Start n8n:**
```bash
docker run -d --name n8n \
  -p 5678:5678 \
  -v n8n_data:/home/node/.n8n \
  -e N8N_SECURE_COOKIE=false \
  n8nio/n8n
```

2. **Import the workflow:**
```bash
n8n import:workflow --input integrations/n8n-model-scan-pipeline.json
```
Or: n8n UI → Settings → Import from File → select `integrations/n8n-model-scan-pipeline.json`

3. **Configure credentials in n8n UI:**

| Credential | Environment Variable | Purpose |
|-----------|---------------------|---------|
| Slack webhook | `SLACK_WEBHOOK_URL` | Alert to `#ml-security-alerts` |
| Jira API | `JIRA_BASE_URL`, `JIRA_PROJECT_KEY` | Auto-create incident tickets |
| Quarantine API | `QUARANTINE_API_URL` | Isolate flagged models |
| Scanner URL | `SCANNER_DASHBOARD_URL` | Link in alert messages |

4. **Start the scanner API (required by the workflow):**
```bash
uvicorn scanner.api:app --host 0.0.0.0 --port 8000
```

5. **Test the pipeline:**
```bash
curl -X POST http://localhost:5678/webhook/model-scan \
  -H "Content-Type: application/json" \
  -d '{"repo_id": "organization/model-name", "revision": "abc123"}'
```

### Pipeline Flow

```
Model Upload Event → Webhook → Scanner API → Risk Assessment
                                                    ├── LOW/MEDIUM → Notify success
                                                    └── HIGH/CRITICAL → Slack alert
                                                                      → Quarantine model
                                                                      → Create Jira ticket
```

---

## 9. Incident Response — Model Flagged

### When a CRITICAL Finding Is Detected

**Do this immediately (within 15 minutes):**

1. **Block the model from deployment.**
   ```bash
   # If using a model registry with quarantine API:
   curl -X POST https://registry.internal/api/quarantine \
     -H "Content-Type: application/json" \
     -d '{"model_id": "org/model-name", "version": "v2.1", "reason": "supply-chain-scan-critical"}'
   ```

2. **Determine if the model was already deployed.**
   - Check deployment logs for the model version
   - If deployed: escalate to SEV-1, initiate containment

3. **Analyze the finding.**
   ```bash
   # Re-run with verbose output for investigation
   hf-scanner ./flagged-model/ --mode local --format json > incident-evidence.json
   ```

4. **Determine intent.**
   - REDUCE/GLOBAL opcodes in pickle = **likely malicious** (arbitrary code execution)
   - Obfuscated imports = **likely malicious** (hiding payload)
   - Unusual metadata = **investigate further** (could be benign misconfiguration)

5. **Notify security team.**
   - Post to `#ml-security-alerts` with:
     - Model identifier
     - Finding details (rule, severity, file)
     - Whether model was deployed
     - Link to scan evidence JSON

6. **If deployed and confirmed malicious:**
   - Rollback to last known-good model version
   - Rotate any credentials the model runtime had access to
   - Check for lateral movement from the model execution environment
   - Preserve all artifacts for forensics

### Escalation Matrix

| Scenario | Escalate To | SLA |
|----------|-------------|-----|
| CRITICAL in pre-deploy scan | ML Platform + Security | Block deploy, fix within 24h |
| CRITICAL already in production | Security On-Call → Incident Commander | 30 minutes to contain |
| HIGH in pre-deploy | ML Platform team | Fix before next deploy |
| Model from unknown uploader | Security + Legal | Investigate provenance |

---

## 10. False Positive Handling

**Current false positive evidence:** fixture-level only. Do not publish a false-positive rate without the exact benchmark command, dataset/artifact hashes, scanner commit, dependency versions, and raw output.

### Identifying False Positives

Signs a finding may be a false positive:
- The model is from a **verified, trusted publisher** (e.g., official org accounts)
- The flagged opcode is in a **well-known framework pattern** (e.g., PyTorch's standard serialization)
- The finding is MEDIUM severity and relates to metadata, not executable content

### Confirming a False Positive

1. **Re-scan with verbose output:**
   ```bash
   hf-scanner ./model/ --mode local --format json > detailed-scan.json
   ```

2. **Manually inspect the flagged file:**
   ```bash
   # For pickle files — examine the opcode stream
   python3 -c "import pickletools; pickletools.dis(open('model.pkl', 'rb'))"
   ```

3. **Check against known-good baseline:**
   - Compare the model's opcode stream against a known-safe version of the same architecture

### Suppressing Confirmed False Positives

Add exceptions to your `policy.yaml`:

```yaml
# Suppress specific false positives (use sparingly)
suppressions:
  - file_pattern: "tokenizer.pkl"
    rule: "pickle_dangerous_opcode"
    reason: "Known HuggingFace tokenizer serialization pattern"
    approved_by: "security-team"
    expires: "2027-01-01"
```

> **WARNING:** Every suppression must have an `approved_by` and `expires` field. Review suppressions quarterly.

### Reporting False Positives

File an issue at https://github.com/poojakira/hf-model-provenance-scanner/issues with:
- The scan output JSON
- The model identifier
- Why you believe it's a false positive

---

## 11. Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `command not found: hf-scanner` | Not installed or not in PATH | Verify: `pip show hf-scanner`. Use `python -m scanner.cli` as fallback. |
| `ModuleNotFoundError: psutil` | Dependency not installed | `pip install psutil>=5.9` or reinstall: `pip install -e .` |
| `FileNotFoundError` on scan | Path doesn't exist or is relative | Use absolute path or verify CWD |
| Scanner hangs on large model | Memory/CPU constrained | Check `psutil` resource limits. Scan individual files instead of directories. |
| `--mode hub` connection timeout | Network issue or Hub rate limit | Retry with `--timeout 120`. Check HuggingFace Hub status. |
| Exit code 2 with no output | Bad policy.yaml or runtime crash | Run with `--verbose` flag. Check stderr. |
| Findings differ between runs | Config file changed or scanner updated | Pin scanner version and use explicit `--config` path |
| Docker build fails | Missing build deps | Ensure Dockerfile base image matches Python 3.10+ |
| `PermissionError` reading model files | File permissions | `chmod -R 644 models/` (Linux) or run PowerShell as admin (Windows) |
| ATT&CK mapping missing | attack-v19-core not installed | `pip install "hf-scanner[attack]"` |

---

## 12. Maintenance

### Updating the Scanner

```bash
cd hf-model-provenance-scanner
git pull origin main
pip install -e .
hf-scanner --version
```

### Running the Test Suite

```bash
# Quick validation
make test
# Expected: 199 passed, 3 skipped

# Full verification (lint + test + build + security audit)
make verify
```

### Updating Policy Rules

1. Edit `policy.yaml` — never add dangerous opcodes to the allow-list
2. Run the test suite to confirm no regressions: `make test`
3. Run the false positive benchmark: `python benchmark/measure_false_positive_rate.py`
4. If FP rate increases above 10%, review changes

### Monitoring Scanner Health

```bash
# Check scanner latency
python benchmark/run_real_artifact_benchmark.py

# Expected: p99 < 5s for typical model repos
```

---

## Quick Reference Card

```bash
# Scan local directory
hf-scanner ./models/ --mode local

# Scan HuggingFace Hub model
hf-scanner meta-llama/Llama-3.1-8B --mode hub

# JSON output for CI
hf-scanner ./models/ --mode local --format json

# SARIF for GitHub Security
hf-scanner ./models/ --mode local --format sarif > results.sarif

# HTML report
hf-scanner ./models/ --mode local --format html > report.html

# Fail only on critical
hf-scanner ./models/ --mode local --fail-on critical

# Fail on high or critical (default)
hf-scanner ./models/ --mode local --fail-on high

# Custom policy
hf-scanner ./models/ --mode local --config ./.hf-scanner.toml

# Verbose output for debugging
hf-scanner ./models/ --mode local --verbose
```
