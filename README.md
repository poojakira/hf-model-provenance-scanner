# hf-model-provenance-scanner

[![CI](https://github.com/poojakira/hf-model-provenance-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/poojakira/hf-model-provenance-scanner/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![SARIF](https://img.shields.io/badge/output-SARIF%20%2B%20GitHub%20Code%20Scanning-blueviolet)](https://docs.github.com/en/code-security/code-scanning)

**Models on HuggingFace Hub are executing arbitrary code when you load them. This tool catches it.**

A single `torch.load()` call deserializes attacker-controlled pickle bytecode. Malicious `REDUCE` and `STACK_GLOBAL` opcodes execute `os.system`, `subprocess.Popen`, or `eval`, giving full shell access on your machine or CI runner. SafeTensors was supposed to fix this, but Wiz demonstrated header injection that embeds C2 callbacks in metadata. GGUF metadata fields overflow into shell commands. Typosquatted orgs impersonate `meta-llama` and `mistralai` to distribute weaponized weights.

`hf-scanner` is a static analysis tool that detects these attacks **before** model weights are loaded into memory. It combines a taint engine, symbolic resolver, and temporal scanner. These capabilities don't exist in ModelScan or PickleScan.

## Verified head-to-head vs Protect AI ModelScan 0.8.8

We benchmark against the actual installed competitor (`pip install modelscan==0.8.8`), not a description of it. Both scanners run as subprocesses against the same files; numbers come straight from each tool's JSON output. Reproduce with `python benchmark/modelscan_headtohead.py`.

| Payload | Technique | ModelScan 0.8.8 | hf-scanner |
|---------|-----------|-----------------|------------|
| `os.system` | direct denylist | ✅ caught | ✅ caught |
| `subprocess.Popen` | direct denylist | ✅ caught | ✅ caught |
| `runpy.run_path` | indirect exec | ✅ caught | ✅ caught |
| `bdb.Bdb().run` | debugger exec | ✅ caught | ✅ caught |
| `builtins.exec` via getattr | obfuscated ref | ✅ caught | ✅ caught |
| `webbrowser.open` | platform trigger | ✅ caught | ✅ caught |
| **`timeit.timeit(code)`** | **memoized-global exec** | ❌ **MISSED** | ✅ caught |
| **`importlib.import_module('os')`** | **gadget-chain import** | ❌ **MISSED** | ✅ caught |

**Detection: hf-scanner 8/8 (100%) vs ModelScan 6/8 (75%).** ModelScan misses `timeit` and `importlib` because its scanner does not treat those stdlib entry points as unsafe. `timeit.timeit()` compiles and runs an arbitrary code string; `importlib.import_module` is the first link in a getattr→call gadget chain. Our memo-aware opcode parser reconstructs globals even when the pickle reuses a single memoized string across module and qualname (the exact trick that hides `timeit.timeit`).

**False positives: 0/5 for both** on legitimate sklearn/PyTorch/numpy/tokenizer pickles. We add recall without adding noise. Evidence: [`evidence/generated/modelscan_headtohead.json`](evidence/generated/modelscan_headtohead.json), [`evidence/generated/modelscan_false_positive.json`](evidence/generated/modelscan_false_positive.json). Regression-locked in [`tests/test_modelscan_bypass_regression.py`](tests/test_modelscan_bypass_regression.py).

---

## Scan a link before you download it (real-time)

Paste a HuggingFace URL and get a verdict **before** the weights ever touch your
disk. The scanner lists the repo's files over the API, then uses HTTP Range
requests to pull only the pickle opcode header and safetensors metadata header
(a few hundred KB) instead of downloading the multi-gigabyte tensor payload.

```bash
hf-scanner https://huggingface.co/openai-community/gpt2 --format json
```
```json
{
  "repo_id": "openai-community/gpt2",
  "files_listed": 26,
  "files_scanned": 8,
  "megabytes_fetched": 0.516,
  "verdict": "clean",
  "findings": []
}
```

That real run scanned 8 security-relevant files while fetching **0.5 MB**. The
full GPT-2 repo is ~500 MB. A malicious `pytorch_model.bin` is caught from its
header opcodes alone, before `torch.load` or `from_pretrained` runs. Bare ids
(`org/model`) and `.../tree/main` URLs work too.

---

## Install and Scan in 20 Seconds

```bash
pip install hf-scanner

# Scan a HuggingFace model repo
hf-scanner meta-llama/Llama-3-8B
# Scan local model files
hf-scanner ./models/ --mode local --fail-on high

# Output SARIF for GitHub Code Scanning
hf-scanner ./models/ --format sarif --output results.sarif
```

Zero runtime dependencies beyond `psutil`. Python 3.10+.

---

## What It Catches

| Attack Vector | Real-World Example | Detection Method |
|---|---|---|
| **Pickle RCE** (`REDUCE`/`GLOBAL`/`STACK_GLOBAL`) | CVE-2024-5480, CVE-2026-4372, JFrog 2025 bypasses | Deep opcode walk + gadget chain matching |
| **PickleScan bypass** (corrupted headers, copyreg, Protocol 4) | JFrog + Sonatype confirmed bypasses | Full protocol parse, not regex |
| **SafeTensors header injection** | Wiz 2025 research, C2 in metadata | Header-only scan, metadata taint analysis |
| **GGUF metadata overflow** | Shell commands in metadata fields | Structural parse + shell pattern detection |
| **Typosquatted organizations** | `meta-Ilama`, `mistral-ai`, `0penai` | Levenshtein distance against verified org list |
| **Obfuscated payloads** | base64, `chr()` chains, string concat | Multi-layer decode + re-scan |
| **Credential theft** | `os.environ['HF_TOKEN']`, AWS creds | Static taint analysis across files |
| **C2 network calls** | Embedded URLs in model code/metadata | Endpoint extraction + reputation check |
| **Rug-pull (model swap)** | Clean upload → malicious update | Temporal baseline diffing |

---

## Why This Exists: What ModelScan Misses

ModelScan (Protect AI) scans individual files for known-bad patterns. It does not have:

| Capability | ModelScan | hf-scanner |
|---|:---:|:---:|
| Cross-file taint tracking | ❌ | ✅ |
| Symbolic resolution (indirect calls) | ❌ | ✅ |
| Temporal analysis (rug-pull detection) | ❌ | ✅ |
| Typosquat detection | ❌ | ✅ |
| SafeTensors metadata injection | ❌ | ✅ |
| GGUF structural scanning | ❌ | ✅ |
| PickleScan bypass coverage (all 7) | Partial | ✅ |
| Source code + config + shell analysis | ❌ | ✅ |
| SARIF output for GitHub Security tab | ❌ | ✅ |

The taint engine traces data flow across Python files. If `config.json` sets a URL and `model.py` calls `requests.get()` with it, the connection is flagged. ModelScan sees each file in isolation.

---

## Real CVE Detection

Tested against 12 reproduced real-world attacks from 2025–2026. **12/12 detected.** Full results in [`evidence/DETECTION_PROOF.md`](evidence/DETECTION_PROOF.md).

| Attack | CVE | Detected | Time |
|---|---|:---:|---|
| HF Transformers RCE | CVE-2026-4372 | ✅ | 18ms |
| LMDeploy trust_remote_code | CVE-2026-46517 | ✅ | 18ms |
| JFrog PickleScan bypass (corrupted header) | — | ✅ | <1ms |
| JFrog PickleScan bypass (builtins.eval) | — | ✅ | <1ms |
| Sonatype copyreg gadget chain | — | ✅ | <1ms |
| SafeTensors metadata C2 injection | — | ✅ | <1ms |
| GGUF metadata shell injection | — | ✅ | <1ms |
| Multi-layer chr() obfuscation | — | ✅ | 18ms |
| Open-OSS/privacy-filter credential stealer | — | ✅ | 22ms |
| LiteLLM supply chain compromise | — | ✅ | 18ms |
| Protocol 4 STACK_GLOBAL | — | ✅ | <1ms |
| Acronis TRU credential stealer | — | ✅ | 21ms |

Total scan time for all 12: **116ms**.

---

## CI Integration

Block malicious models before they reach your pipeline:

```yaml
# .github/workflows/model-security.yml
name: ML Supply Chain Gate

on: [push, pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.10"

      - run: pip install hf-scanner

      - name: Scan model artifacts
        run: |
          hf-scanner ./models/ \
            --mode local \
            --format sarif \
            --output results.sarif \
            --fail-on high

      - name: Upload to GitHub Security
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
          category: ml-supply-chain
```

Exit code 1 on HIGH or CRITICAL findings. Merge blocked.

Also available: [GitLab CI](integrations/gitlab-ci.yml) · [Jenkins](integrations/Jenkinsfile) · [CircleCI](integrations/circleci.yml) · [Azure Pipelines](integrations/azure-pipelines.yml)

---

## n8n Automation

Import a ready-made workflow that triggers on model upload → scans → routes by severity → alerts Slack → quarantines → creates Jira ticket:

```bash
n8n import:workflow --input integrations/n8n-model-scan-pipeline.json
```

See [`integrations/N8N_WORKFLOW.md`](integrations/N8N_WORKFLOW.md) for credentials and configuration.

---

## Detection Evidence

All claims are backed by reproducible artifacts committed to this repository.

| Evidence | Location |
|---|---|
| Red-team attack reproductions (12/12) | [`tests/redteam/simulate_attacks.py`](tests/redteam/simulate_attacks.py) |
| Machine-readable detection report | [`tests/redteam/redteam_report.json`](tests/redteam/redteam_report.json) |
| Extended variant coverage (18/18) | [`tests/redteam/extended_attacks.py`](tests/redteam/extended_attacks.py) |
| False-positive measurement | [`evidence/generated/false_positive_rate.json`](evidence/generated/false_positive_rate.json) |
| CVE signature database | [`scanner/data/real_cve_signatures.py`](scanner/data/real_cve_signatures.py) |
| SafeTensors header evidence | [`evidence/generated/gpt2_607a30d_header_evidence.json`](evidence/generated/gpt2_607a30d_header_evidence.json) |

Reproduce locally:

```bash
git clone https://github.com/poojakira/hf-model-provenance-scanner.git
cd hf-model-provenance-scanner
pip install -e ".[dev]"
python tests/redteam/simulate_attacks.py
```

---

## Architecture

```
scanner/
  cli.py                 — CLI entry point
  analyzer/
    pickle_scanner.py    — Opcode-level pickle analysis (Protocol 0–5)
    safetensors_scanner.py — Header-only metadata inspection
    gguf_scanner.py      — Structural GGUF metadata scanning
    taint_engine.py      — Cross-file data flow tracking
    symbolic_resolver.py — Indirect call resolution
    temporal_scanner.py  — Baseline diffing for rug-pull detection
    obfuscation_scanner.py — Multi-layer decode (base64, chr, concat)
    org_checker.py       — Typosquat detection via Levenshtein
    ast_visitor.py       — Python AST analysis
    sandbox_executor.py  — Isolated execution environment
  rules/definitions.py   — 40+ finding definitions with severity
  formatters/            — SARIF, JSON, HTML output
  attack_mapping/        — MITRE ATT&CK v19 technique mapping
  signing/               — Ed25519 artifact signing
  sbom/                  — CycloneDX 1.5 BOM generation
```

---

## Key Flags

| Flag | Description |
|---|---|
| `--mode local/remote/both` | Scan source (default: both) |
| `--fail-on SEVERITY` | Exit code 1 threshold (default: high) |
| `--format json/sarif/text/html` | Output format |
| `--output FILE` | Write report to file |
| `--policy FILE` | Apply policy-as-code config |
| `--baseline FILE` | Compare against saved baseline |
| `--save-baseline FILE` | Save current state for rug-pull detection |
| `--sign` | Sign artifact after scanning (Ed25519) |
| `--verify-signature` | Verify existing signature |
| `--aibom FILE` | Generate CycloneDX AI BOM |
| `--no-network` | Force local-only scan |
| `-q, --quiet` | Suppress output, exit code only |

---

## Supported Formats

`.pkl` · `.pt` · `.pth` · `.bin` · `.ckpt` · `.safetensors` · `.gguf` · `.onnx` · `.h5` · `.keras` · `.py` · `.sh` · `.bat` · `.ps1` · `.json` · `.toml` · `.yml`

---

## MITRE ATT&CK Mapping

Every finding maps to ATT&CK v19:

- **T1195.001**: Supply Chain Compromise: Software Supply Chain
- **T1683/001**: Trusted Developer Utilities Proxy Execution
- **T1027/018**: Obfuscated Files or Information
- **T1685**: Disable or Modify Tools

---

## License

Apache-2.0
