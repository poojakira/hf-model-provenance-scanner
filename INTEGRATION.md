# Integration Guide

Get the HF Model Provenance Scanner into your workflow in under 2 minutes.

## One-Line Install

### Linux / macOS
```bash
curl -sSL https://raw.githubusercontent.com/poojakira/hf-model-provenance-scanner/main/install.sh | bash
```

### Windows (PowerShell)
```powershell
iex ((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/poojakira/hf-model-provenance-scanner/main/install.ps1'))
```

---

## GitHub Actions (2 lines)

Add to `.github/workflows/model-scan.yml`:

```yaml
name: Model Security
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7.0.0
      - uses: actions/setup-python@v6.3.0
        with:
          python-version: '3.11'
      - run: pip install git+https://github.com/poojakira/hf-model-provenance-scanner.git
      - run: hf-scanner . --mode local --format sarif --output results.sarif --fail-on high
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

Results appear in your repo's **Security → Code Scanning** tab.

---

## GitLab CI

Add to `.gitlab-ci.yml`:

```yaml
model-scan:
  stage: test
  image: python:3.11-slim
  script:
    - pip install git+https://github.com/poojakira/hf-model-provenance-scanner.git
    - hf-scanner . --mode local --format json --output report.json --fail-on high
  artifacts:
    reports:
      sast: report.json
```

---

## Azure Pipelines

```yaml
steps:
  - script: pip install git+https://github.com/poojakira/hf-model-provenance-scanner.git
  - script: hf-scanner . --mode local --format sarif --output results.sarif --fail-on high
```

---

## Jenkins

```groovy
pipeline {
    agent any
    stages {
        stage('Scan') {
            steps {
                sh 'pip install git+https://github.com/poojakira/hf-model-provenance-scanner.git'
                sh 'hf-scanner . --mode local --format json --output report.json --fail-on high'
            }
        }
    }
}
```

---

## CircleCI

```yaml
jobs:
  scan:
    docker:
      - image: cimg/python:3.11
    steps:
      - checkout
      - run: pip install git+https://github.com/poojakira/hf-model-provenance-scanner.git
      - run: hf-scanner . --mode local --fail-on high
```

---

## Docker

```bash
# Build
docker build -t hf-scanner https://github.com/poojakira/hf-model-provenance-scanner.git

# Scan a local directory
docker run --rm -v $(pwd):/workspace hf-scanner /workspace --mode local --fail-on high

# Scan a remote HuggingFace repo
docker run --rm hf-scanner meta-llama/Llama-3-8B --mode remote --fail-on high
```

---

## Pre-commit Hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/poojakira/hf-model-provenance-scanner
    rev: main
    hooks:
      - id: hf-scanner
```

Then: `pre-commit install`

Every commit will now be scanned automatically.

---

## HuggingFace Platform Integration (Webhook)

Deploy `integrations/huggingface_webhook.py` as a serverless function:

1. **Configure webhook on HuggingFace:**
   - Go to https://huggingface.co/settings/webhooks
   - URL: `https://your-endpoint.com/scan`
   - Events: "Repo update"
   - Set a webhook secret

2. **Deploy the handler:**
   ```bash
   # AWS Lambda / Google Cloud Functions / Cloudflare Workers
   # Or run standalone:
   export HF_TOKEN=hf_xxxxx
   export WEBHOOK_SECRET=your-secret
   export NOTIFY_URL=https://hooks.slack.com/services/xxx  # Optional
   python integrations/huggingface_webhook.py
   ```

3. **Every model push is now auto-scanned.** Alerts fire to Slack/Teams/Discord.

---

## Temporal Monitoring (Rug-Pull Detection)

Set up a cron job or scheduled CI to detect supply-chain rug-pulls:

```bash
# Daily scan comparing against trusted baseline
# GitHub Actions scheduled workflow:
name: Daily Model Monitor
on:
  schedule:
    - cron: '0 6 * * *'  # 6 AM UTC daily
jobs:
  monitor:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7.0.0
      - run: pip install git+https://github.com/poojakira/hf-model-provenance-scanner.git
      - run: hf-scanner your-org/your-model --mode remote --baseline baseline.json --fail-on high
```

---

## Exit Codes for CI/CD

| Code | Meaning | CI Action |
|------|---------|-----------|
| 0 | Clean (no findings above threshold) | Continue pipeline |
| 1 | Findings at or above `--fail-on` severity | Block deployment |
| 2 | Scanner error (network, config) | Retry or alert |
| 3 | Invalid arguments | Fix configuration |

---

## Recommended Deployment Strategy

1. **Immediate** — Add to CI/CD pipeline (catches attacks before deployment)
2. **Next** — Add pre-commit hook (catches during development)
3. **Then** — Deploy webhook for all HuggingFace repos in your org
4. **Ongoing** — Enable temporal monitoring for rug-pull detection
