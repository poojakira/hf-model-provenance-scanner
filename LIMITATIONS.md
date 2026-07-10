# Limitations & Honest Assessment

This document describes what `hf-scanner` **does and does not** catch. A security tool that overpromises is more dangerous than no tool at all.

## What the Scanner IS

A **static analysis and provenance verification** tool that:
- Detects **known malicious patterns** in model repository code
- Verifies **binary model file integrity** (pickle opcode scanning, format validation)
- Checks **organizational identity** (typosquatting, impersonation)
- Validates **supply chain artifacts** (signatures, SBOMs, attestations)
- Generates **runtime hardening policies** (Docker, Kubernetes)

## What the Scanner IS NOT

- ❌ **Not a sandbox/dynamic analyzer** — it never executes code
- ❌ **Not a neural backdoor detector** — cannot analyze model behavior
- ❌ **Not a complete defense** — sophisticated attackers can bypass static analysis
- ❌ **Not a replacement for code review** — it assists humans, doesn't replace them

## Detection Rates (Honest)

### Python Source Code Analysis
| Attack Technique | Detected? | Notes |
|---|---|---|
| base64 decode → exec/eval | ✅ Yes | Multi-layer recursive decoding |
| String concatenation (e.g., "sub"+"process") | ✅ Yes | AST-level constant folding |
| subprocess/os.system with powershell | ✅ Yes | Direct pattern match |
| SSL verification bypass | ✅ Yes | verify=False, CERT_NONE |
| getattr() on dangerous modules | ✅ Yes | Module-aware detection |
| compile() + exec() | ✅ Yes | Pattern detection |
| ctypes FFI calls | ✅ Yes | Module name detection |
| codecs.decode with rot_13 | ✅ Yes | Encoding trick detection |
| __import__ with dynamic arg | ✅ Yes | Non-literal argument check |
| chr() concatenation for module names | ⚠️ Partial | Detected if passed to getattr/__import__ |
| lambda + map + __builtins__ | ❌ No | Too indirect for static analysis |
| f-string runtime construction | ❌ No | Requires symbolic execution |
| Nested function with network calls | ❌ No | Only flagged in loader filenames |
| Custom class __reduce__ payloads | ❌ No | Caught at pickle level, not source |
| Obfuscated decorator chains | ❌ No | Requires taint tracking |

**Estimated catch rate against adversarial attacker: ~70%**
**Catch rate against unsophisticated copy-paste malware: ~95%**

### Pickle Binary Scanning
| Attack Technique | Detected? | Notes |
|---|---|---|
| GLOBAL opcode with dangerous callable | ✅ Yes | 50+ callables in blocklist |
| STACK_GLOBAL bypass | ✅ Yes | Protocol 2+ support |
| Corrupted pickle (PickleScan bypass) | ✅ Yes | Detects globals before crash |
| Gadget chains (copyreg, etc.) | ✅ Yes | Chained REDUCE detection |
| PyTorch ZIP with embedded pkl | ✅ Yes | Extracts and scans inner files |
| io.BytesIO indirect execution | ❌ No | Not in critical callables list |
| Novel gadgets in application code | ❌ No | Only stdlib gadgets covered |
| Extremely large files (>100MB) | ⚠️ Untested | May hit iteration limits |

### Format-Specific Scanning
| Format | Detection | Real-World Value |
|---|---|---|
| SafeTensors metadata injection | ✅ Working | Low (format is safe by design) |
| SafeTensors oversized header | ✅ Working | Low (theoretical attack) |
| GGUF metadata URLs/commands | ✅ Working | Low (no known real attacks) |
| GGUF malformed header | ✅ Working | Integrity check |
| ONNX/CoreML/TFLite | ❌ Not supported | Future work |

## Known Limitations

### Cross-Platform
- **Windows baselines**: Path separators are normalized to `/` for cross-platform compatibility
- **IOC cache**: Stored in `~/.cache/hf-scanner/` (Linux/Mac) or `%LOCALAPPDATA%\hf-scanner\` (Windows)
- **Signature verification**: Requires cosign/gpg/minisign to be installed separately

### Temporal Analysis
- Only works if you **save and reuse baselines** — requires CI workflow integration
- Does NOT monitor repositories continuously (it's a point-in-time scanner)
- Baseline format may change between scanner versions

### IOC Feeds
- No remote feeds are configured by default
- Users must add feed URLs to `.hf-scanner.toml` or wait for community feeds
- Local IOC list is static and may go stale

### Weight Fingerprinting
- Provides **integrity verification** only (did the weights change?)
- Cannot detect:
  - Neural backdoors (trojaned neurons)
  - Adversarial weight perturbations
  - Steganographic data hidden in weight values
  - Semantic drift from fine-tuning

## Comparison to Alternatives

| Capability | PickleScan | ModelScan | hf-scanner |
|---|---|---|---|
| Pickle deserialization attacks | Yes (bypassed 7+ times) | Yes | Yes + bypass detection |
| Source code analysis | No | No | Yes (70% adversarial) |
| Org impersonation | No | No | Yes |
| Provenance/SBOM | No | No | Yes |
| Runtime policy | No | No | Yes |
| Binary format variety | Pickle only | Pickle, H5, SavedModel | Pickle, SafeTensors, GGUF |
| Zero dependencies | No (Python pkg) | No (many deps) | Yes |
| Neural backdoor detection | No | No | No |

## When to Use This Tool

✅ **Good for:**
- CI/CD gate to catch known malicious patterns
- Compliance evidence for EU AI Act / CISA AIBOM requirements
- Quick triage of untrusted model repositories
- Detecting the "low-hanging fruit" malware (copy-paste attacks)
- Generating security policies for model sandboxing

❌ **Not sufficient for:**
- Defense against state-level or APT-grade attacks
- Replacing human security review of high-value models
- Detecting novel zero-day obfuscation techniques
- Guaranteeing a model is safe to deploy
- Behavioral analysis of model outputs

## Responsible Disclosure

If you find a bypass that this scanner should detect, please report it.
The goal is to continuously improve detection, not to claim perfection.
