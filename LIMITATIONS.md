# Capabilities & Limitations (v0.2.0 — Current)

## Fixture Evidence Only

The values below are fixture-suite results, not real-world detection-rate or false-positive-rate claims. They must not be quoted without the exact commit, command, fixture hash, environment, and raw result artifact.

Regenerate locally with:
`python tests/redteam/simulate_attacks.py` and `python tests/redteam/extended_attacks.py`
(guarded in CI by `tests/redteam/test_detection_counts.py`).

| Suite | Attacks | Detected | False Positives |
|---|---|---|---|
| Core real-world incidents | 12 | 12 (100%) | 0 |
| Extended variants (env gating, decorators, generators, DNS exfil) | 18 | 18 (100%) | 0 |
| Large-scale (multi-MB files, 300+ line code) | 3 | 3 (100%) | 0 |
| Real models (GPT-2 downloaded, Llama-3-8B 288-tensor structure) | — | 0 findings | 0 |

**How "detected" and "false positive" are counted:** only *actionable*
(non-INFO) findings count. INFO-level capability notices such as
`HFS-SANDBOX-BACKEND` (which merely reports the legacy subprocess sandbox
backend is in use) are **not** detections and are excluded from both the
detection and false-positive tallies. Counting them would both inflate the
detection rate on real attacks and inflate the false-positive rate on benign
code; excluding them gives the honest number in the table above.

## Fail-Loud on Unanalyzable Streams

A truncated or corrupt pickle, or one containing an unknown opcode, is reported
as `HFS-096` and drives the scan `completeness` to `INDETERMINATE` — it is
**never** silently reported as clean. INDETERMINATE elevates risk to at least
HIGH, and `--enforce` turns it into a non-zero exit code. This closes the
classic "malware executes before deserialization completes" bypass, where a
truncated payload could otherwise slip through as a zero-finding scan.

## What Each Engine Catches

### Engine 1: AST Pattern Matching
| Catches | Misses |
|---|---|
| exec/eval/subprocess calls | Deeply nested decorator chains |
| SSL bypass (verify=False) | Meta-programming via type() |
| base64 decode + execute | Reflection-heavy code |
| getattr on dangerous modules | — |
| ctypes FFI usage | — |
| codecs.decode(rot_13) | — |
| __import__ with dynamic arg | — |
| compile() + exec() | — |
| raw socket / DNS primitives (socket.socket, getaddrinfo, create_connection) in any file → HFS-095 | — |

### Engine 2: Taint Tracking
| Catches | Misses |
|---|---|
| Variable indirection (x = os; x.system) | Cross-file taint (imports from other modules) |
| Container lookups (__builtins__["exec"]) | Complex OOP inheritance chains |
| Decode function output → exec | Closure-captured variables from outer scope |
| __import__ return value propagation | — |
| lambda + map + exec patterns | — |

### Engine 3: Symbolic String Resolver
| Catches | Misses |
|---|---|
| chr(111)+chr(115) → "os" | Runtime-computed values (API responses) |
| ''.join([chr(x) for x in [...]]) | Dictionary lookups as encoders |
| bytes([...]).decode() | Custom codec implementations |
| Reversed string construction | — |

### Engine 4: Sandbox Execution (Multi-Environment)
| Catches | Misses |
|---|---|
| ANY exec/eval/compile call at runtime | Code requiring specific Python packages to init |
| ANY blocked module import (os, subprocess, socket...) | Payloads that take >30s to reach |
| Environmental gating (platform checks, CI detection) | Attacks gated on specific hardware (GPU checks) |
| Decorator/generator/metaclass execution flows | — |
| DNS exfiltration attempts | — |

**Environment configurations tested per file:**
1. Minimal (default)
2. Windows-like (OS=Windows_NT, SYSTEMROOT, COMSPEC)
3. CI-like (CI=true, GITHUB_ACTIONS=true)

### Engine 5: Binary Format Parsers
| Format | What's Caught |
|---|---|
| Pickle (.pkl/.pt/.pth/.bin/.ckpt) | All REDUCE/BUILD/GLOBAL/STACK_GLOBAL calling dangerous functions. All 7 PickleScan bypasses. |
| SafeTensors (.safetensors) | Metadata injection (URLs, scripts), oversized headers, malformed structure |
| GGUF (.gguf) | Metadata shell injection, encoded commands, invalid format |
| ONNX (.onnx) | Custom operators (native code loading), suspicious strings |
| Keras (.h5/.keras) | Lambda layers (arbitrary code execution), custom_objects |

## Real Model Testing Boundaries

| Model | Size | Tensors | Scan Time | Findings | Result |
|---|---|---|---|---|---|
| GPT-2 metadata/tokenizer path | 2.4MB configs + tokenizer | 147 | Historical local result | 0 | Fixture/local result only |
| Llama-3-8B structure simulation | 4 shards | 288 | Historical local result | 0 | Simulation, not full model scan |
| Malicious PyTorch fixture | 2.9MB | — | Historical local result | 1 CRITICAL | Fixture/local result only |
| Malicious SafeTensors fixture | 1.9MB, 60 tensors | 60 | Historical local result | 2 HIGH | Fixture/local result only |

## Known Limitations (Cannot Fix — Fundamental)

| Limitation | Reason | Workaround |
|---|---|---|
| Pure social engineering | No scanner can stop humans voluntarily running commands | Use runtime sandbox policy |
| Neural backdoors in weights | Requires inference-time behavioral testing | Different tool class needed |
| Attacks gated on specific GPU/hardware | Sandbox can't emulate all hardware configs | Accept as residual risk |
| Cross-file taint (malicious import from another package) | Would require whole-program analysis | Scan all files in repo together |
| Payloads that take >30s to initialize | Sandbox timeout (configurable via `HF_SCANNER_SANDBOX_TIMEOUT`) | Increase timeout for thorough scans |

## What This Tool IS

- A defensive static + dynamic analysis scanner
- A provenance and identity verification engine
- A CI/CD signal that can block deployments when wired into a policy gate
- An evidence helper for SBOM/provenance-oriented review workflows

## What This Tool IS NOT

- Not a neural network behavior analyzer
- Not a replacement for human security review
- Not a network monitoring tool
- Not a guarantee against all future novel attacks
- Not effective unless deployed in the user's workflow
- Not a compliance certification tool
- Not proof that an artifact is benign
