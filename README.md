# HF Model Provenance Scanner

Supply-chain security scanner for Hugging Face model repositories. Analyzes pickle opcodes, SafeTensors headers, GGUF structures, and ONNX graphs to detect code-execution gadgets and suspicious provenance signals. Uses HTTP Range requests to fetch only the bytes needed for analysis (kilobytes instead of gigabytes).

**Status:** Prototype / research project. Useful for exploring ML supply-chain threats. Not production-hardened.

## Install

```bash
git clone https://github.com/poojakira/hf-model-provenance-scanner.git
cd hf-model-provenance-scanner
pip install -e .
```

## Usage

```bash
# Scan a model repository
hf-scanner bert-base-uncased --format text

# SARIF output for CI integration
hf-scanner bert-base-uncased --format sarif --output findings.sarif

# Fail CI on critical findings
hf-scanner --manifest models/requirements.txt --fail-on critical
```

## Example Output

```
Scanning: bert-base-uncased
Files analyzed: 6
Time: 89 ms

✓ No findings. All files pass provenance checks.
```

```
CRITICAL  pickle_gadget_chain
  File: model.pkl
  Opcode: REDUCE at offset 0x1a4
  Call chain: builtins.exec -> os.system(...)

1 finding (1 critical). Exit code: 1
```

## What It Checks

### Pickle Analysis
- REDUCE/GLOBAL/STACK_GLOBAL gadget chains leading to `os.system`, `subprocess.Popen`, `eval`, `exec`
- Memoized-global exec patterns (GLOBAL pushing dangerous callables onto memo stack)
- `importlib.import_module` + `getattr` loader bypasses
- Protocols 0-5

### Obfuscation Detection
- Multi-layer encoding (`base64.b64decode`, `chr()` concatenation, nested decodes)

### SafeTensors Inspection
- Oversized headers, tensor names with path traversal, size mismatches

### GGUF Parsing
- Invalid magic bytes, metadata with embedded executable content

### ONNX / Keras / Config Scanning
- Suspicious operators, lambda layers, code in config files

### Supply-Chain Signals
- Typosquatting (Levenshtein distance to popular model names)
- Temporal diffing (file hashes change after publication without version bump)
- Author/org name similarity to known publishers

## Output Formats

- Text (terminal)
- JSON
- SARIF 2.1 (GitHub Code Scanning)
- CycloneDX SBOM

## CI Integration

```yaml
name: Model Supply-Chain Scan
on:
  pull_request:
    paths: ['models/**']

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install hf-model-provenance-scanner
      - run: hf-scanner --manifest models/requirements.txt --format sarif --output findings.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: findings.sarif
```

## Limitations

- HTTP Range requests depend on hub server support; some mirrors may not support them
- Pickle taint engine uses heuristic opcode matching, not full symbolic execution — sophisticated obfuscation may evade detection
- Typosquat detection is string-distance based and will produce false positives on legitimately similar names
- Temporal diffing requires multiple scans over time to establish baselines
- GGUF and ONNX analysis is basic structural validation, not full format parsing
- No guarantee of catching all attack patterns — this is a research tool, not a security boundary

## Contributing

If you find a gadget-chain pattern this scanner misses, open an issue with a reproducer. Include a fixture file demonstrating detection with your PR.

## License

Apache 2.0
