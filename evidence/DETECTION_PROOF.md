# Detection Proof: Real-World Attack Verification

## Summary

The HF Model Provenance Scanner was tested against **12 documented real-world attacks** from 2025-2026. All 12 included reproductions were detected; false-positive results apply only to this suite.

## Test Results

| # | Attack | Source | CVE | Detected | Findings | Time |
|---|--------|--------|-----|----------|----------|------|
| 1 | May 2026 Open-OSS/privacy-filter | MLHive, CSO Online | — | ✅ | 9 | 22ms |
| 2 | HF Transformers RCE | DigitalWarfare | CVE-2026-4372 | ✅ | 4 | 18ms |
| 3 | LiteLLM Supply Chain | StartupFortune | — | ✅ | 1 | 18ms |
| 4 | LMDeploy trust_remote_code | SentinelOne | CVE-2026-46432 | ✅ | 2 | 18ms |
| 5 | Acronis TRU Credential Stealer | Acronis | — | ✅ | 4 | 21ms |
| 6 | Multi-layer chr() obfuscation | HF malware campaigns | — | ✅ | 1 | 18ms |
| 7 | JFrog PickleScan Bypass (corrupted) | JFrog Research | — | ✅ | 1 | <1ms |
| 8 | JFrog PickleScan Bypass (eval) | JFrog Research | — | ✅ | 1 | <1ms |
| 9 | Sonatype PickleScan Bypass (copyreg) | Sonatype | — | ✅ | 2 | <1ms |
| 10 | Protocol 4 STACK_GLOBAL | JFrog/SANS | — | ✅ | 1 | <1ms |
| 11 | SafeTensors metadata C2 injection | Novel technique | — | ✅ | 2 | <1ms |
| 12 | GGUF metadata shell injection | Novel technique | — | ✅ | 1 | <1ms |

**Included red-team suite: 12 fixtures detected**
**False positives: 0 in this suite only**
**Total Scan Time: 116ms**

## How to Reproduce

```bash
git clone https://github.com/poojakira/hf-model-provenance-scanner.git
cd hf-model-provenance-scanner
python3 tests/redteam/simulate_attacks.py
```

## Machine-Readable Report

See `tests/redteam/redteam_report.json` for the full structured output.

## Comparison with Existing Tools

| Attack | PickleScan | ModelScan | Protect AI Guardian | **This Scanner** |
|--------|:---:|:---:|:---:|:---:|
| #1 Privacy Filter (source code) | ❌ | ❌ | ❌ | ✅ |
| #2 CVE-2026-4372 | ❌ | ❌ | ❌ | ✅ |
| #3 LiteLLM supply chain | ❌ | ❌ | ❌ | ✅ |
| #7 Corrupted pickle bypass | ❌ | ❌ | ❌ | ✅ |
| #8 builtins.eval bypass | ❌ | Partial | Partial | ✅ |
| #9 copyreg gadget chain | ❌ | Partial | Partial | ✅ |
| #11 SafeTensors injection | ❌ | ❌ | ❌ | ✅ |
| #12 GGUF injection | ❌ | ❌ | ❌ | ✅ |

PickleScan has 7+ confirmed bypass vulnerabilities (JFrog + Sonatype research).
This scanner catches the committed bypass fixtures because it parses pickle opcodes directly. It also analyzes selected Python source, config, and shell-script patterns covered by the tracked regression suite.
