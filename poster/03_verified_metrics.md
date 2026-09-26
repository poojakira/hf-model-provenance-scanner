# Verified Metrics — Poster 03

Apache-2.0 • Python 3.12 • HEAD 7b2cd5f • verified 2026-09-26. Verified for this poster on Windows / CPython 3.12.10.

## Headline cards
- 33/33 — FIXTURES DETECTED
- 0 — BENIGN FP (of 4)
Notes: 12 core + 18 extended + 3 large-scale fixtures. Fixture-suite result — NOT a general detection rate.

## Verified surface
| Item | Value |
|---|---|
| Binary format parsers | 5 |
| PickleScan bypasses caught | 7 |
| Analysis engines | 5 |

## Chart values
| Series | Value |
|---|---|
| Core incidents | 100 |
| Extended variants | 100 |
| Large-scale | 100 |
Note: Committed fixtures only (redteam_report.json). Do not generalize to arbitrary HF repos.

## Historical / provenance
Main CI 36043740861 (751a62a, 2026-09-24): 211 passed + 6 subtests; 66.9% coverage (Py 3.11/3.12), gate 55%. Not re-run at current HEAD.

## Not established by this repository
General detection/false-positive rate on arbitrary models. Neural backdoors. That an artifact is benign.
