# hf-model-provenance-scanner

A security scanner that checks HuggingFace model repositories for supply chain attacks. It inspects model files (pickle, SafeTensors, GGUF, ONNX, Keras), Python source, shell scripts, configs, and dependency files for malicious payloads.

## What It Detects

- **Pickle exploits** — malicious opcodes, gadget chains, and known bypass techniques (copyreg, STACK_GLOBAL, corrupted headers) that evade PickleScan
- **Obfuscated payloads** — base64 encoding, chr() chains, string concatenation tricks hiding malicious code
- **Command & control calls** — network connections to suspicious endpoints embedded in model metadata or source
- **SSL/TLS bypass** — code that disables certificate verification to enable MITM attacks
- **Shell injection** — malicious commands in shell scripts or GGUF/SafeTensors metadata
- **Credential theft** — code that reads tokens, env vars, or credential files
- **Typosquatting** — model repos with names similar to popular models
- **Missing signatures** — repos without cryptographic signing or SBOM provenance
- **Rug-pull detection** — temporal analysis that flags suspicious changes between model versions

File formats scanned: `.pkl`, `.pt`, `.pth`, `.bin`, `.ckpt`, `.safetensors`, `.gguf`, `.onnx`, `.h5`, `.keras`, `.py`, `.sh`, `.bat`, `.ps1`, `.json`, `.toml`, `.yml`

## Install

```bash
pip install hf-scanner
```

Requires Python 3.10+. Only runtime dependency is `psutil`.

For development:
```bash
git clone https://github.com/poojakira/hf-model-provenance-scanner.git
cd hf-model-provenance-scanner
pip install -e ".[dev]"
```

## Usage

Scan a HuggingFace repo (fetches files via API):
```bash
hf-scanner meta-llama/Llama-3-8B
```

Scan a local directory:
```bash
hf-scanner ./my-model-folder --mode local
```

Scan both remote metadata and local files (default):
```bash
hf-scanner some-org/some-model --mode both
```

### Output Formats

```bash
# Human-readable (default in terminal)
hf-scanner some-org/model

# JSON (default when piped)
hf-scanner some-org/model --format json > report.json

# SARIF (for GitHub Code Scanning)
hf-scanner some-org/model --format sarif --output results.sarif

# HTML report
hf-scanner some-org/model --format html --output report.html
```

### CI Integration

Exit code 1 if any finding meets the severity threshold:
```bash
# Fail on high or critical (default)
hf-scanner some-org/model --fail-on high

# Fail only on critical
hf-scanner some-org/model --fail-on critical

# Never fail (always exit 0)
hf-scanner some-org/model --fail-on never
```

### Temporal / Rug-Pull Detection

Save a baseline, then compare future scans against it:
```bash
# Save baseline
hf-scanner some-org/model --save-baseline baseline.json

# Later: detect changes
hf-scanner some-org/model --baseline baseline.json
```

### Sandbox Execution

Run Python files in a restricted subprocess to detect runtime behavior:
```bash
hf-scanner ./model-folder --sandbox
```

### Runtime Protection (experimental)

Monitor a running model-serving process for suspicious behavior:
```bash
hf-scanner ./model-folder --protect --protect-config config.json
```

## Key Flags

| Flag | Description |
|------|-------------|
| `--mode local/remote/both` | What to scan (default: both) |
| `--fail-on SEVERITY` | Exit 1 threshold (default: high) |
| `--format json/sarif/text/html` | Output format |
| `--output FILE` | Write report to file |
| `--baseline FILE` | Compare against saved baseline |
| `--save-baseline FILE` | Save current scan as baseline |
| `--max-binary-mb N` | Max binary file size in MB (default: 100) |
| `--skip-binary` | Skip binary model file scanning |
| `--sandbox` | Enable sandbox execution of Python files |
| `--aibom FILE` | Generate CycloneDX AI BOM |
| `--no-network` | Force local-only scan |
| `--token TOKEN` | HuggingFace API token (or set `HF_TOKEN` env var) |
| `-q, --quiet` | Suppress output, only set exit code |
| `--verbose` | Include INFO-level findings |

## Test Results

Tested against 12 documented real-world attacks from 2025-2026 (see `evidence/DETECTION_PROOF.md`):

- 12/12 attacks detected in the included red-team suite
- 0 false positives on clean GPT-2 and Llama-3-8B SafeTensors files
- P99 scan latency < 200ms on GPT-2 (12-layer) and Llama-3-8B (32-layer) over 50 runs
- Total red-team suite scan time: 116ms

The test suite includes pickle bypass techniques from JFrog and Sonatype research, SafeTensors metadata injection, GGUF shell injection, and source-level attacks (credential theft, obfuscated loaders).

To reproduce:
```bash
python tests/redteam/simulate_attacks.py
```

## Project Structure

```
scanner/
  cli.py              — CLI entry point
  analyzer/           — Detection engines (pickle, safetensors, gguf, onnx, keras,
                        obfuscation, taint, shell, config, ast, sandbox, temporal)
  rules/              — Finding definitions and severity mappings
  formatters/         — Output formatters (json, sarif, html)
  attack_mapping/     — MITRE ATT&CK technique mapping
  utils/              — HF API client, Levenshtein distance, file filtering
tests/
  redteam/            — Attack simulations and extended test corpus
  fixtures/           — Benign and malicious test files
integrations/         — CI configs for GitHub Actions, GitLab, Jenkins, CircleCI, Azure
```

## ATT&CK Mapping

Findings map to MITRE ATT&CK v19 techniques. Requires the optional `attack-v19-core` package:

```bash
pip install hf-scanner[attack]
```

Key technique mappings:
- T1195.001 — Supply Chain Compromise: Compromise Software Supply Chain
- T1683/001 — Trusted Developer Utilities
- T1027/018 — Obfuscated Files or Information

## License

Apache-2.0
