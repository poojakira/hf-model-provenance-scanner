# Changelog - hf-model-provenance-scanner

## [Unreleased] - Reliability & fail-loud hardening

### Security / correctness
- **Fail-loud on unanalyzable pickles.** Truncated, corrupt, or unknown-opcode
  pickle streams now emit `HFS-096` and drive scan `completeness` to
  `INDETERMINATE` instead of silently reporting a clean scan. A length-prefixed
  opcode that claims more bytes than the file contains is now detected as
  truncation. Closes the "malware executes before deserialization completes"
  bypass class. (Previously a truncated pickle with no parsed globals produced
  zero findings.)
- **Completeness propagation in the CLI.** A file-level `INDETERMINATE` finding
  now elevates the whole-scan completeness; `--enforce` fails closed on it.
- **`completeness`, `skipped_files_detail`, and `artifact_revision` are now
  serialized in JSON output** so CI gates can read the "INCOMPLETE != CLEAN"
  signal (previously only in the data model, not emitted).
- **New rule `HFS-095`**: raw socket / DNS-resolution primitives
  (`socket.socket`, `getaddrinfo`, `create_connection`) in *any* model file are
  flagged as a data-exfiltration vector (previously only inside loader-named files).
- **`--aibom` is now implemented.** The flag previously parsed but did nothing;
  it now writes a CycloneDX 1.6 AIBOM.
- **Webhook default bind** changed from `0.0.0.0` to `127.0.0.1` (opt-in via
  `WEBHOOK_BIND_HOST`).

### Fixed
- `hf-webhook-scan.yml`: declared `scan` job `outputs` (previously the
  `notify-hf` job read empty values), fixed a YAML block-scalar indentation bug
  that mangled the issue-comment body, and moved the HF-discussion POST into a
  standalone, lint-clean script (`.github/scripts/post_hf_discussion.py`).
- `Makefile`: `lint`/`format`/`security`/`verify` referenced a nonexistent
  top-level `attack_mapping` path; corrected to `scanner tests benchmarks`.
- Red-team suites are now Windows-safe (UTF-8 stdout) and their
  detection/false-positive accounting counts only *actionable* (non-INFO)
  findings, so the `HFS-SANDBOX-BACKEND` capability notice no longer inflates
  either metric. Verified: core 12/12, extended 18/18 with **0** false
  positives — now CI-guarded by `tests/redteam/test_detection_counts.py`.

### Docs
- RUNBOOK: corrected the coverage gate (real ~64% line coverage, CI gate 55%,
  not 80%), documented `completeness`/exit-code semantics, the `--enforce` and
  `--aibom` flags, and marked network/Docker/sibling-repo commands as manual-only.

## [0.2.0] - 2026-07-22

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