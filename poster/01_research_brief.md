# Research Brief — Poster 03

## Repository
`github.com/poojakira/hf-model-provenance-scanner` (public, default branch `main`, primary language Python). Apache-2.0 • Python 3.12 • HEAD 13a5ae4 • verified 2026-09-26

## Academic Project Title
**Non-Executing Security Analysis of AI Model Supply-Chain Artifacts**

### Subtitle
Provenance, Serialization, Impersonation, and Repository Risk Inspection

## One-Sentence Contribution
A non-executing supply-chain scanner combining AST, taint, symbolic-string, and binary- format engines across pickle/SafeTensors/GGUF/ONNX/Keras, with fail-loud handling of unanalyzable streams and ATT&CK v19 mapping — signals for pre-load review, not a safety proof.

## Problem Statement
Loading a model can execute code. Pickle-based checkpoints run arbitrary opcodes on deserialize; Keras Lambda layers and ONNX custom ops load native code; typosquatted repos impersonate trusted ones. The danger is realized the moment an artifact is loaded — so inspection must happen before that.

## Threat Model
Chain: MALICIOUS ARTIFACT -> MODEL REPOSITORY -> LOAD / DESERIALIZE -> NON-EXEC SCAN BOUNDARY -> FINDING + ATT&CK MAP.
Adversary capability: publishes crafted model repo or artifact; Assumptions: scan runs before load; dynamic exec disabled; Out of scope: neural weight backdoors; cross-file taint; runtime behavior; Residual risk: novel bypass; missing provenance ≠ compromise.

## Research / Engineering Question
> Can important model supply-chain risk signals be identified without loading or executing untrusted model artifacts?

## Objective
Determine whether static parsers + pattern/taint/ symbolic analysis can surface supply-chain risk signals across model formats without execution.

## Engineering Sub-Objectives
O1 — Pickle opcode + 5 binary formats
O2 — AST / taint / symbolic string engines
O3 — Provenance & impersonation checks
O4 — ATT&CK v19 mapping on findings

## Methodology
1 Enumerate (artifacts) -> 2 AST (patterns) -> 3 Taint (+symbolic) -> 4 Parse (binaries) -> 5 Provenance (checks) -> 6·7 Map + gate (ATT&CK/exit)

## Current Verified Evidence + Claim Ledger
- **VERIFIED_CURRENT** — 33/33 committed fixtures detected; 0 actionable FP on 4 benign — evidence/DETECTION_PROOF.md + tests/redteam/redteam_report.json; pinned by test_detection_counts.py. Fixture-only.
- **VERIFIED_CURRENT** — 5 binary format parsers; 5 analysis engines — README/LIMITATIONS.md enumerate pickle/SafeTensors/GGUF/ONNX/Keras and AST/taint/symbolic/sandbox(disabled)/binary.
- **VERIFIED_CURRENT** — Fail-loud HFS-096 INDETERMINATE on unanalyzable pickle — LIMITATIONS.md; elevates risk >=HIGH; --enforce nonzero exit.
- **VERIFIED_HISTORICAL** — 211 passed + 6 subtests; 66.9% coverage — CI run 36043740861 (751a62a, 2026-09-24), Py 3.11/3.12. Not re-run at current HEAD.
- **UNSUPPORTED (disclaimed)** — General detection rate / 0% FP on arbitrary models — README + DETECTION_PROOF scope note forbid generalizing fixture results; not claimed.
- **UNSUPPORTED (disclaimed)** — Neural weight backdoor detection — LIMITATIONS.md lists as fundamental non-capability.

## Important Negative / Honest Results
See RESULTS panel: Committed fixtures only (redteam_report.json). Do not generalize to arbitrary HF repos.

## Limitations
1. Fixture results ≠ real-world detection rate.
2. No broad benign false-positive benchmark.
3. Cannot detect weight-space neural backdoors.
4. Cross-file / whole-program taint not modeled.
5. Missing provenance is a signal, not proof.

## Future Work
• Broad benign-model FP benchmark.
• Whole-repo cross-file taint analysis.
• Larger real-model corpus.
• Published latency benchmark artifact.
• Signature/SBOM verification depth.

## Reproducibility
```
pytest tests/
python tests/redteam/simulate_attacks.py
```
Evidence: VERIFIED_METRICS.md, evidence/DETECTION_PROOF.md, tests/redteam/

## References
[1] MITRE ATT&CK v19 · [2] MITRE ATLAS · [3] JFrog/Sonatype PickleScan Bypass Research · [4] SLSA Provenance · [5] OWASP ML Supply Chain · [6] HF SafeTensors
