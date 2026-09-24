# Performance Measurement Status

## Evidence status

The repository contains `benchmarks/scan_perf.py`, but **no current, version-pinned raw performance artifact is committed that supports a public p95, p99, throughput, startup-time, or memory claim**.

Therefore the repository does not publish a current performance baseline or performance guarantee.

This document replaces earlier hand-written baseline values that were not tied to a committed raw result artifact.

## Benchmark scope

`benchmarks/scan_perf.py` is the repository's performance measurement harness. When used, any result should be reported with all of the following:

- exact Git commit;
- Python version;
- operating system and runner/hardware context;
- fixture corpus definition and hash where practical;
- command line;
- raw JSON output;
- number of measured files and repetitions;
- p50/p95/p99 or other quoted statistic;
- whether the files are synthetic fixtures or externally sourced artifacts.

A result without that provenance should not be presented as a current repository performance metric.

## Reproduction

A local exploratory run can be started with:

```bash
python benchmarks/scan_perf.py
```

If a result is intended for public use, save the raw output to a versioned artifact rather than copying a number manually into documentation.

## CI status

As of the 2026-09-24 security repair, `benchmarks/scan_perf.py` is **not a required performance gate in `.github/workflows/ci.yml`**. The normal CI pipeline validates tests, lint/format, type checking, security scans, rejection of unsafe dynamic execution, container scanning, and Docker build, but a current performance benchmark is not part of the merge gate.

## Claim boundary

Do not claim any of the following from this repository until a current raw benchmark artifact and CI/reproduction path support them:

- p95 or p99 scan latency;
- files-per-second throughput;
- memory consumption limits;
- large-model performance;
- hardware-independent performance guarantees.

The test/coverage and red-team fixture metrics used in résumé and portfolio material are maintained separately in `VERIFIED_METRICS.md` and are not performance benchmarks.
