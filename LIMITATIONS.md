# Limitations & Capabilities (Accurate as of v0.2.0)

This document honestly describes what `hf-scanner` does and does not catch.

## Detection Capabilities (Verified)

### Python Source Code — 5-Engine Analysis
| Attack Technique | Engine That Catches It | Verified |
|---|---|---|
| base64/b85/b32 decode → exec/eval | AST + Taint | ✅ |
| String concatenation ("sub"+"process") | AST | ✅ |
| subprocess/os.system with powershell | AST + Sandbox | ✅ |
| SSL verification bypass (verify=False) | AST | ✅ |
| getattr() on dangerous modules | AST (hardened) | ✅ |
| compile() + exec() | AST + Taint + Sandbox | ✅ |
| ctypes FFI calls (CDLL) | AST (hardened) | ✅ |
| codecs.decode with rot_13 | AST + Taint | ✅ |
| __import__ with dynamic argument | AST + Taint | ✅ |
| chr() concatenation building module names | Symbolic Resolver + Sandbox | ✅ |
| lambda + map + __builtins__["exec"] | Sandbox | ✅ |
| Nested function with network calls | Sandbox | ✅ |
| Decorator-based code execution | Sandbox | ✅ |
| Generator-based lazy evaluation | Sandbox + Taint | ✅ |
| globals()/locals() manipulation | Sandbox + Taint | ✅ |
| type() dynamic class construction | Sandbox | ✅ |
| Hex bytes decode → exec | Taint + Sandbox | ✅ |
| Environmental gating (platform/env checks) | Sandbox | ✅ |

### Binary Model Formats
| Format | Attacks Detected | Verified |
|---|---|---|
| Pickle (.pkl/.pt/.pth/.bin/.ckpt) | All GLOBAL/REDUCE/STACK_GLOBAL RCE, 7 PickleScan bypasses | ✅ |
| SafeTensors (.safetensors) | Metadata injection, oversized headers, malformed structure | ✅ |
| GGUF (.gguf) | Metadata shell injection, oversized entries, invalid format | ✅ |
| ONNX (.onnx) | Custom operators, suspicious strings, malformed structure | ✅ |
| Keras (.h5/.keras) | Lambda layers, custom_objects, embedded pickle | ✅ |

### Provenance & Identity
| Check | Verified |
|---|---|
| Org typosquatting (Levenshtein distance ≤ 4) | ✅ |
| Org substring/prefix matching (catches "Open-OSS" → "openai") | ✅ |
| Model card plagiarism (cosine similarity ≥ 0.90) | ✅ |
| Download velocity anomaly (age < 72h, downloads > 10K) | ✅ |
| Missing SBOM/signatures/attestations | ✅ |
| SBOM hash mismatch against actual files | ✅ |

## Known Limitations (Honest)

### Cannot Detect
| Gap | Reason | Mitigation |
|---|---|---|
| Pure social engineering (README instructions) | No scanner can prevent humans choosing to run commands | Runtime sandbox policy limits damage |
| Neural backdoors in weight values | Requires inference-time behavioral testing, not file scanning | Outside scope; use red-teaming tools |
| DNS-based exfiltration via socket.getaddrinfo with novel domains | Only caught if socket module access + known patterns present | Network monitoring needed |
| Attacks that take >30s to reach payload | Sandbox timeout (configurable via HF_SCANNER_SANDBOX_TIMEOUT env var) | Increase timeout for thorough scans |

### Operational Constraints
| Constraint | Detail |
|---|---|
| Sandbox timeout | Default 30 seconds (configurable). Complex model init may not complete. |
| Large binary files | Tested up to 200KB fixtures. Untested on multi-GB real model weights. Performance on 7B+ parameter models unknown. |
| Network required for remote scanning | HuggingFace API calls for org checks, model card, file listing |
| Signature verification | Requires cosign/gpg/minisign installed externally |

### False Positive Rate
- **Tested: 0 false positives** on 4 legitimate code samples (PyTorch model, data pipeline, config loading, logging)
- Bare `import os` in data-loading scripts does NOT trigger (sandbox only flags if dangerous methods are called)
- `from_pretrained` with 7+ char hex revision does NOT trigger HFS-030

## Detection Rate Summary

| Test Suite | Attacks | Detected | Rate | False Positives |
|---|---|---|---|---|
| Core incidents (12 attacks) | 12 | 12 | 100% | 0 |
| Extended variants (18 attacks) | 18 | 17-18 | 94-100% | 0 |
| Legitimate code samples | — | — | — | 0 |

## What This Tool IS NOT

- Not a replacement for human code review on high-value models
- Not a neural network behavioral analyzer
- Not a network intrusion detection system
- Not a guarantee against all future attack techniques
- Not effective if not deployed (adoption required)
