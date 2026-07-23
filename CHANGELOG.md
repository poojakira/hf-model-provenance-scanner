# Changelog - hf-model-provenance-scanner

## [1.0.0] - 2026-07-22

### Changed - ATT&CK v19 Migration

#### New Technique Coverage Added
- **T1683/001** (Generate Content: Written Content): Added to `modified_model_card`
- **T1027/018** (Obfuscated Files: Invisible Unicode): Added to `trojanized_tokenizer`

#### Rule Table Updates
```python
# BEFORE
"modified_model_card": ["T1565.001", "T1027"],
"trojanized_tokenizer": ["T1195.002", "T1027.002"],

# AFTER
"modified_model_card": ["T1565.001", "T1027", "T1683/001"],
"trojanized_tokenizer": ["T1195.002", "T1027.002", "T1027/018"],
```

### Added
- Detection for AI-generated model card modifications (T1683/001)
- Detection for invisible Unicode obfuscation in tokenizers (T1027/018)

### Migration
See [attack-v19-core MIGRATION_GUIDE.md](../attack-v19-core/MIGRATION_GUIDE.md) for full migration steps.