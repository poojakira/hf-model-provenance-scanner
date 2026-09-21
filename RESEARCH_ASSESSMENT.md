# Research Assessment: HF Model Provenance Scanner

**Evidence status:** repository assessment based on committed source, tests, fixtures, and GitHub Actions evidence.  
**Last reconciled:** 2026-09-21

This document intentionally avoids invented reviewer personas, product rankings, deployment recommendations, and unsupported comparisons with other scanners.

## 1. What the repository implements

The repository implements a pre-load model-repository scanner for supply-chain and provenance risks. The committed code includes analysis paths for Python/source behavior, pickle-family artifacts, SafeTensors, GGUF, ONNX, Keras/H5, provenance indicators, signatures, SBOM/AIBOM evidence, temporal changes, and selected identity/impersonation signals.

The strongest supported description is: **a multi-signal model-supply-chain scanner that attempts to identify risky repository content without treating fixture results as universal detection effectiveness.**

## 2. Evidence that is safe to cite

The authoritative quantitative files are:

- `VERIFIED_METRICS.md`
- `RESUME_EVIDENCE.md`
- `evidence/DETECTION_PROOF.md`
- `tests/redteam/redteam_report.json`
- `tests/redteam/extended_report.json`
- `tests/redteam/test_detection_counts.py`

### Test-suite evidence

A historical Windows 11 / PowerShell / Python 3.12.10 validation is preserved at commit
`267618d3f7799d70c8c8d85b079f4a39d211aefa`:

- **195 passed**
- **2 skipped**
- **6 subtests passed**

That is a historical local-validation snapshot, not the current CI total.

Current verified Linux CI evidence reports:

- **199 passed**
- **1 skipped**
- **6 subtests passed**
- **65.89% statement coverage**

The latest verified CI run referenced by this audit is GitHub Actions run `35564351689`, which completed successfully across the Python matrix and the repository's lint, security, CodeQL, type-check, sandbox, Trivy, and Docker jobs.

### Fixture evidence

The committed red-team evidence records:

- **12/12 core incident-reproduction fixtures detected**
- **18/18 extended attack variants detected**
- **3/3 large-scale fixtures detected**
- **0 actionable findings across the four committed benign samples in the extended fixture set**

These are **fixture-suite measurements only**. They are not a measured real-world detection rate and do not establish a universal false-positive rate.

## 3. What the evidence does not establish

The repository does **not** currently establish:

- a universal detection rate for arbitrary Hugging Face repositories;
- a universal 0% false-positive rate;
- comparative superiority over PickleScan, ModelScan, Guardian, HiddenLayer, or any other third-party product;
- that a historical real-world incident would certainly have been prevented in deployment;
- production-scale latency, memory, or throughput guarantees for large model repositories;
- field deployment, adoption, or operational effectiveness in a production Hugging Face organization;
- semantic-backdoor detection in arbitrary model weights.

Any statement beyond the committed test, fixture, or benchmark scope should be treated as unverified until reproduced with a documented corpus, environment, command, commit, and raw result artifact.

## 4. Architecture and limitations

The scanner combines several kinds of analysis rather than relying on a single signal. Relevant committed mechanisms include static source inspection, suspicious-data-flow checks, symbolic/string inspection, sandbox-oriented execution monitoring, binary-format parsing, provenance metadata checks, and temporal/fingerprint logic.

Important limitations remain:

- heuristic rules can produce false positives and false negatives;
- sandbox-oriented analysis may not reach environment-gated, delayed, or dependency-heavy payloads;
- static source analysis cannot resolve every dynamic Python behavior;
- binary-format inspection does not prove model-weight semantic safety;
- provenance indicators are risk signals, not proof of compromise;
- incomplete or unsupported input must be surfaced as incomplete/indeterminate rather than interpreted as clean.

## 5. How quantitative claims should be presented

Acceptable wording:

> Validated 199 passing tests at 65.89% statement coverage; the committed internal red-team suite detects 12/12 core incident-reproduction fixtures, 18/18 extended variants, and 3/3 large-scale fixtures, with zero actionable findings across four committed benign samples.

Required qualifier:

> These are committed fixture-suite results and must not be generalized to arbitrary repositories or a universal false-positive rate.

Historical résumé wording may cite **195 passing tests** only when it is identified as the documented historical local snapshot described in `RESUME_EVIDENCE.md`.

## 6. Reproduction

Use the dependency versions and CI configuration in the repository. Key checks include:

```bash
pytest tests/
python tests/redteam/simulate_attacks.py
python tests/redteam/extended_attacks.py
python tests/redteam/test_large_scale.py
```

For current test and coverage evidence, prefer the cited GitHub Actions run over undocumented local results.

## 7. Assessment conclusion

The repository demonstrates a substantial model-supply-chain security implementation with reproducible internal tests and explicitly scoped red-team fixtures. Its credibility comes from source code, regression tests, CI, machine-readable reports, and documented limitations—not from rankings, marketing comparisons, or universal effectiveness claims.

Future credibility should be improved through independently reproducible larger-corpus evaluation, clearly versioned benchmark artifacts, and broader benign/malicious datasets while preserving the same evidence boundaries.
