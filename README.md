# hf-model-provenance-scanner

[![CI](https://github.com/poojakira/hf-model-provenance-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/poojakira/hf-model-provenance-scanner/actions/workflows/ci.yml)
[![Python >=3.10](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## MITRE ATT&CK v19 Coverage

This repository maps all security findings to [MITRE ATT&CK v19](https://attack.mitre.org/).

| Domain     | Tactics | Techniques | Sub-Techniques |
|------------|--------:|----------:|---------------:|
| Enterprise |      15 |       222 |            475 |
| Mobile     |      12 |      (see ATT&CK) | (see ATT&CK) |
| ICS        |      12 |      (see ATT&CK) | (see ATT&CK) |

**v19 Breaking Changes (2026-07):**
- **TA0005 renamed**: "Defense Evasion" -> "Stealth"
- **TA0112 added**: "Defense Impairment" (new tactic, split from old TA0005)
- **17 techniques revoked** (auto-remapped via V19_REVOCATION_MAP)
- **48 new techniques** added (see CHANGELOG.md)

### Evidence Status

| Claim Area | Current Evidence |
|------------|------------------|
| Static and artifact scanning | Unit tests cover CLI, pickle, SafeTensors, GGUF, obfuscation, sandbox, IOC, and security-rejection paths. |
| Detection-rate claims | Only cite detection percentages with the exact committed test corpus or evidence file that produced them. |
| Latency claims | `tests/test_latency_p99.py` measures P99 < 200 ms over 50 runs using in-memory fixtures shaped like GPT-2 and Llama-3-8B metadata. It does not download or scan full model weights. |
| False-positive rate | The same test reports 0 findings for its clean in-memory SafeTensors/config fixtures. This is not a false-positive measurement on published Hugging Face model files. |
| Deployment posture | This is a security scanner/library. Treat runtime sandboxing as defense-in-depth, not a complete containment guarantee. |
### Migration from v18

See [MIGRATION_GUIDE.md](../attack-v19-core/MIGRATION_GUIDE.md) in attack-v19-core for full migration steps.

Key remappings:
- T1562, T1562.001, T1089, T1054 -> T1685 (Disable or Modify Tools)
- T1070.001 -> T1685.005 (Clear Windows Event Logs)
- T1070.002 -> T1685.006 (Clear Linux/Mac Logs)
- T1534 -> T1684.001 (Social Engineering: Impersonation)
- T1566.003 -> T1684.002 (Social Engineering: Email Spoofing)
