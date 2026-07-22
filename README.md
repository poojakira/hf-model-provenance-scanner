## MITRE ATT&CK v19 Coverage

This repository maps all security findings to [MITRE ATT&CK v19](https://attack.mitre.org/).

| Domain     | Tactics | Techniques | Sub-Techniques |
|------------|--------:|----------:|---------------:|
| Enterprise |      15 |       222 |            475 |
| Mobile     |      12 |      (see ATT&CK) | (see ATT&CK) |
| ICS        |      12 |      (see ATT&CK) | (see ATT&CK) |

### Export ATT&CK Navigator Layer

```bash
python -m attack_mapping.reporter --output navigator_layer.json
```

Open in [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to visualize coverage.

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

### HF Model Provenance Specific Mappings

| Finding Type | Techniques |
|--------------|------------|
| unsigned_model_weights | T1195.001, T1553.002 |
| pickle_deserialization | T1059.006, T1203 |
| typosquatted_model_name | T1036.005, T1195 |
| modified_model_card | T1565.001, T1027 |
| unauthorized_fine_tune | T1565, T1190 |
| huggingface_token_exposure | T1552.001, T1078 |
| trojanized_tokenizer | T1195.002, T1027.002 |
| model_weight_exfiltration | T1041, T1048 |
| dependency_confusion | T1195.001 |
| malicious_model_repo | T1583.001, T1608.001 |