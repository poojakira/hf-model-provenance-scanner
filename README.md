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

### Measurable Claims

| Metric | Value | Evidence |
|--------|-------|----------|
| **Scan latency (P99)** | < 200 ms / model | `benchmark/scan_latency.py` — 50MB SafeTensors |
| **Test coverage** | 88%+ | `pytest --cov --cov-fail-under=85` |
| **ATT&CK v19 techniques mapped** | 10 unique | 10 finding types → 10 techniques (T1683/001, T1027/018) |
| **Detection rate (core CVEs)** | 12/12 (100%) | `tests/redteam/simulate_attacks.py` |
| **Detection rate (extended variants)** | 18/18 (100%) | `tests/redteam/extended_attacks.py` |
| **Large-scale scan (multi-MB)** | 3/3 passed | `tests/redteam/test_large_scale.py` |
| **False positive rate** | 0% on clean models | GPT-2, Llama-3-8B structure tests |

### Export ATT&CK Navigator Layer

```bash
python -m attack_mapping.reporter --output navigator_layer.json
```

Open in [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to visualize coverage. Layers generated with Navigator v4.9 format (attack: "19").

### Finding Schema

Every finding object includes:
```json
{
  "attack_mappings": [
    {
      "tactic_id":         "TA0001",
      "tactic_name":       "Initial Access",
      "technique_id":      "T1195",
      "technique_name":    "Supply Chain Compromise",
      "subtechnique_id":   "T1195.001",
      "subtechnique_name": "Compromise Software Dependencies and Development Tools",
      "domain":            "enterprise",
      "confidence":        0.85,
      "data_sources":      ["..."],
      "platforms":         ["..."],
      "url":               "https://attack.mitre.org/techniques/T1195/001/"
    }
  ]
}
```

### HF Model Provenance Specific Mappings (v19)

| Finding Type | Techniques (v19) |
|--------------|------------------|
| unsigned_model_weights | T1195.001, T1553.002 |
| pickle_deserialization | T1059.006, T1203 |
| typosquatted_model_name | T1036.005, T1195 |
| modified_model_card | T1565.001, T1027, **T1683/001** |
| unauthorized_fine_tune | T1565, T1190 |
| huggingface_token_exposure | T1552.001, T1078 |
| trojanized_tokenizer | T1195.002, T1027.002, **T1027/018** |
| model_weight_exfiltration | T1041, T1048 |
| dependency_confusion | T1195.001 |
| malicious_model_repo | T1583.001, T1608.001 |

**New v19 additions in bold.** T1027/018 (Invisible Unicode) maps to trojanized_tokenizer for obfuscated tokenizer code. T1683/001 (Generate Content: Written) maps to modified_model_card for AI-generated model card manipulation.

### Migration from v18

See [MIGRATION_GUIDE.md](../attack-v19-core/MIGRATION_GUIDE.md) in attack-v19-core for full migration steps.

Key remappings:
- T1562, T1562.001, T1089, T1054 -> T1685 (Disable or Modify Tools)
- T1070.001 -> T1685.005 (Clear Windows Event Logs)
- T1070.002 -> T1685.006 (Clear Linux/Mac Logs)
- T1534 -> T1684.001 (Social Engineering: Impersonation)
- T1566.003 -> T1684.002 (Social Engineering: Email Spoofing)