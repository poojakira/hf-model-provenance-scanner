# Red Team Guide

This document explains how to contribute adversarial test cases ("attack fixtures") to the HF Model Provenance Scanner's red-team suite. Our goal is to ensure the scanner detects **every known evasion technique** for ML model supply-chain attacks.

## Bypass Categories We're Looking For

| Category | File Formats | Example Techniques |
|----------|-------------|-------------------|
| **Pickle deserialization** | `.pkl`, `.pt`, `.pth`, `.bin` | `REDUCE` gadgets, `STACK_GLOBAL` chains, corrupted streams, protocol-5 `BYTEARRAY8`, `copyreg` abuse, `__reduce_ex__` |
| **SafeTensors metadata** | `.safetensors` | C2 URLs in `__metadata__`, `eval()` in post-load hooks, encoded payloads in tensor names |
| **GGUF metadata/shell** | `.gguf` | Shell commands in custom KV pairs, encoded PowerShell, `on_load` triggers |
| **Supply-chain** | `.py`, `config.json` | `trust_remote_code=True`, compromised dependencies, API key exfiltration, webhook beacons |
| **Obfuscation** | `.py` | `chr()` lists, `reversed()`, `base64` + `exec`, `compile()`, `__import__` hiding, f-string assembly |

## How to Write New Attack Fixtures

### 1. Choose Your Attack Vector

Pick a technique from the categories above, or invent a novel one. The best contributions are:
- Techniques seen in real-world incidents (cite your source)
- Novel evasion ideas that exploit gaps in AST/taint/sandbox analysis
- Variants of known bypasses (e.g., different pickle protocol versions)

### 2. Create an INERT Payload

**Critical:** All payloads MUST be inert. They should trigger scanner detection rules without being weaponizable.

```python
# GOOD: Uses real opcode patterns but targets a harmless command marker
PAYLOAD = (
    b"\x80\x02"
    b"\x8c\x02os"
    b"\x8c\x06system"
    b"\x93"
    b"\x8c\x0eecho REDTEAM"  # Inert marker
    b"\x85R."
)

# BAD: Actually downloads and executes something
# DO NOT submit payloads that work as real exploits
```

### 3. Add to the Test Suite

Place your fixture in `tests/redteam/`. You have two options:

**Option A: Add to `conftest.py` fixtures**

Add your attack technique to the `ATTACK_TECHNIQUES` list in `tests/redteam/conftest.py`:

```python
ATTACK_TECHNIQUES = [
    # ... existing techniques ...
    AttackTechnique(
        id="your-technique-id",
        name="Description of your technique",
        category="pickle",  # or: safetensors, gguf, source, supply_chain
        create_payload=lambda: your_payload_bytes,
        expected_rule="HFS-050",  # Rule that should fire
    ),
]
```

**Option B: Add a standalone test file**

Create `tests/redteam/test_your_technique.py`:

```python
"""Tests for [your technique description]."""
from tests.redteam.conftest import run_detection

def test_your_technique():
    payload = b"..."  # Your inert payload
    findings = run_detection("pickle", payload)
    assert len(findings) > 0, "Scanner should detect [technique]"
    assert findings[0].rule_id == "HFS-050"
```

### 4. Add to `simulate_attacks.py` (Optional)

For high-fidelity incident reproductions, add a new `AttackSimulation` entry in `tests/redteam/simulate_attacks.py` following the existing pattern.

## How to Run the Red-Team Suite

### Full simulation (standalone script)

```bash
# From the project root
python tests/redteam/simulate_attacks.py
```

This runs all 12+ attack simulations and prints a detection report.

### Pytest suite (with fixtures and parametrization)

```bash
# Run all red-team tests
pytest tests/redteam/ -v

# Run only pickle bypass tests
pytest tests/redteam/ -v -k "pickle"

# Run only a specific category
pytest tests/redteam/ -v -k "safetensors"
```

### Extended attacks (30+ variants)

```bash
python tests/redteam/extended_attacks.py
```

### In CI (GitHub Actions)

The red-team suite runs automatically:
- **Weekly** (every Monday at 3 AM UTC)
- **On every PR** that touches `scanner/` or `tests/redteam/`

See `.github/workflows/redteam.yml` for the workflow definition.

## How to Report Bypasses Responsibly

### If the bypass is LOW/MEDIUM severity:

1. Verify it works against the latest `main` branch
2. File a GitHub issue using the **Scanner Bypass Report** template
3. Include an INERT minimal reproducer
4. Wait for triage (typically within 48 hours)

### If the bypass is HIGH/CRITICAL severity:

1. **Do NOT file a public issue**
2. Email the details to the maintainer following the process in [SECURITY.md](../SECURITY.md)
3. Include:
   - Technique description
   - Inert reproducer
   - Which detection rules are evaded
   - Potential real-world impact
4. Allow 7 days for initial response before public disclosure

### What NOT to do:

- Do not submit weaponizable payloads (payloads that actually execute malicious actions)
- Do not test bypasses against other people's infrastructure
- Do not disclose critical bypasses publicly before a fix is available

## Reward & Recognition

We believe in recognizing security contributions:

- **CHANGELOG acknowledgment**: Every confirmed bypass gets a credit entry in [CHANGELOG.md](../CHANGELOG.md) with the finder's name/handle
- **README Hall of Fame**: Repeat contributors are listed in the Security Contributors section
- **Co-authorship**: If your bypass leads to a significant scanner improvement, you'll be offered co-authorship on the corresponding commit

### Recognition format in CHANGELOG:

```markdown
## [1.x.x] - YYYY-MM-DD
### Security
- Fixed bypass: [technique description] (reported by @username)
```

## Architecture Reference

Understanding the scanner's detection pipeline helps write better bypasses:

```
Input → Format Detection → Format-Specific Parser → Detection Engines → Findings
                                                          │
                              ┌────────────────────────────┼────────────────────┐
                              │                            │                    │
                        AST Visitor              Taint Engine          Sandbox Executor
                     (pattern matching)      (data flow tracking)   (symbolic execution)
                              │                            │                    │
                              └────────────────────────────┼────────────────────┘
                                                          │
                                                  Symbolic Resolver
                                              (string reconstruction)
```

### Detection engines:

| Engine | What it catches | Potential gaps |
|--------|----------------|---------------|
| `ast_visitor` | Known dangerous patterns (imports, calls, attributes) | Novel obfuscation, dynamic construction |
| `taint_engine` | Data flow from sources to sinks | Indirect flows, cross-function taint |
| `sandbox_executor` | Runtime behavior simulation | Complex control flow, environmental gating |
| `symbolic_resolver` | String reconstruction from `chr()`, `base64`, etc. | Multi-layer encoding, custom codecs |
| `pickle_scanner` | Dangerous opcodes and callable chains | Novel gadgets, protocol-specific tricks |
| `safetensors_scanner` | Suspicious metadata patterns | Subtle encoding in tensor names |
| `gguf_scanner` | Shell commands in KV metadata | Obfuscated values, custom key patterns |

## Questions?

Open a discussion on GitHub or reach out to the maintainers. We welcome all skill levels  -  from first-time contributors to experienced security researchers.
