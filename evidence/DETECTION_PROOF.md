# Detection Proof: Internal Red-Team Fixture Suite

## Summary

The HF Model Provenance Scanner is exercised against an **internal red-team fixture
suite** that reproduces documented 2025-2026 model supply-chain incidents and attack
techniques. This suite contains **33 fixtures** total:

- **12 documented incident reproductions** (`tests/redteam/simulate_attacks.py`)
- **18 extended attack variants** (`tests/redteam/extended_attacks.py`)
- **3 large-scale fixtures** (`tests/redteam/test_large_scale.py`)

Against this committed suite the scanner detects **33/33** fixtures, with **0 actionable
(non-INFO) findings** on the 4 benign ML samples included in the extended suite.

> **Scope note — read this first.** These are *fixture-suite* results, reproducible from
> the committed scripts and JSON reports below. They are **not** a measured detection rate
> against arbitrary Hugging Face models, and must not be generalized to one. No broad
> clean-model false-positive benchmark is committed, so no general "0% false-positive rate"
> is claimed. The numbers in the table are copied verbatim from
> `tests/redteam/redteam_report.json`.

## Core Incident Reproductions (12/12)

| # | Attack | Source | CVE | Detected | Findings | Time |
|---|--------|--------|-----|----------|----------|------|
| 1 | May 2026 Open-OSS/privacy-filter | MLHive, CSO Online | — | ✅ | 11 | 445.7ms |
| 2 | HF Transformers RCE | DigitalWarfare | CVE-2026-4372 | ✅ | 5 | 320.7ms |
| 3 | LiteLLM Supply Chain | StartupFortune | — | ✅ | 2 | 250.3ms |
| 4 | LMDeploy trust_remote_code | SentinelOne | CVE-2026-46517 | ✅ | 3 | 285.0ms |
| 5 | Acronis TRU Credential Stealer | Acronis | — | ✅ | 2 | 301.3ms |
| 6 | Multi-layer chr() obfuscation | HF malware campaigns | — | ✅ | 2 | 301.5ms |
| 7 | JFrog PickleScan Bypass (corrupted) | JFrog Research | — | ✅ | 2 | <1ms |
| 8 | JFrog PickleScan Bypass (eval) | JFrog Research | — | ✅ | 1 | <1ms |
| 9 | Sonatype PickleScan Bypass (copyreg) | Sonatype | — | ✅ | 2 | <1ms |
| 10 | Protocol 4 STACK_GLOBAL | JFrog/SANS | — | ✅ | 1 | <1ms |
| 11 | SafeTensors metadata C2 injection | Novel technique | — | ✅ | 2 | <1ms |
| 12 | GGUF metadata shell injection | Novel technique | — | ✅ | 1 | <1ms |

**Core fixture detection: 12/12** (source: `tests/redteam/redteam_report.json`)
**Extended variants: 18/18**, 0 missed, **0 actionable false positives** on 4 benign
samples (source: `tests/redteam/extended_report.json`)
**Large-scale fixtures: 3/3** (source: `tests/redteam/test_large_scale.py`)
**Findings-by-severity across the 12 core fixtures:** 12 critical, 9 high, 1 medium, 6 low
(28 actionable), plus 6 INFO capability notices (excluded from detection counts).

> Timing note: per-fixture times are wall-clock on the reproduction host and are **not** a
> hardware-normalized benchmark. These historical timings include a subprocess spawn in source-code fixtures;
> that execution path is disabled. Re-run the static fixture suite for current timing.

## How to Reproduce

```bash
git clone https://github.com/poojakira/hf-model-provenance-scanner.git
cd hf-model-provenance-scanner
python3 tests/redteam/simulate_attacks.py      # 12/12 core
python3 tests/redteam/extended_attacks.py      # 18/18 extended, 0 FP
python3 tests/redteam/test_large_scale.py      # 3/3 large-scale
```

The CI-guarded test `tests/redteam/test_detection_counts.py` locks these counts so a
regression (or re-inflation via INFO notices) fails CI.

## Machine-Readable Reports

See `tests/redteam/redteam_report.json` and `tests/redteam/extended_report.json` for the
full structured output.

## Comparative-efficacy boundary

This repository does not claim comparative superiority over third-party scanners from
the internal fixture suite alone. A defensible product comparison would require
running explicitly versioned third-party tools against the same committed corpus,
using the same execution environment and counting rules, and publishing the raw
outputs. No such current cross-tool benchmark is committed here.

The supported claim is limited to this scanner's own reproducible fixture results
documented above.
