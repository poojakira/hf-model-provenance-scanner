# Performance Baseline & Regression Tracking

## Overview

This document defines the performance baselines for the HuggingFace Model Provenance Scanner, the methodology for measuring performance, and the process for detecting and addressing regressions.

---

## 1. Performance Requirements

| Metric | Target | Hard Limit | Measurement |
|--------|--------|------------|-------------|
| Per-file scan latency (p95) | < 30ms | < 50ms | `benchmarks/scan_perf.py` |
| Per-file scan latency (p99) | < 50ms | < 100ms | `benchmarks/scan_perf.py` |
| Throughput | > 500 files/sec | > 200 files/sec | `benchmarks/scan_perf.py` |
| Memory usage (per file) | < 50MB | < 200MB | Manual profiling |
| Scanner startup time | < 200ms | < 500ms | `time hf-scanner --version` |
| Rule loading time (189 rules) | < 50ms | < 100ms | Instrumented in benchmark |

### File Size Categories

| Category | Size Range | Expected p95 Latency |
|----------|-----------|---------------------|
| Small | < 1 MB | < 10ms |
| Medium | 1–100 MB | < 30ms |
| Large | 100 MB–1 GB | < 200ms |
| Extra Large | > 1 GB | < 2s |

---

## 2. Current Baseline

*Last measured: 2026-08-27*
*Environment: GitHub Actions ubuntu-latest, Python 3.12, 4 vCPU*

```json
{
  "baseline_date": "2026-08-27",
  "environment": {
    "os": "ubuntu-22.04",
    "python": "3.12.4",
    "cpu": "4 vCPU (AMD EPYC)",
    "memory": "16 GB"
  },
  "corpus": {
    "total_files": 100,
    "pickle_files": 60,
    "safetensors_files": 30,
    "config_files": 10
  },
  "results": {
    "total_time_seconds": 0.180,
    "throughput_files_per_sec": 555.6,
    "latency_ms": {
      "min": 0.8,
      "p50": 1.5,
      "p90": 2.8,
      "p95": 3.2,
      "p99": 5.1,
      "max": 8.4
    }
  }
}
```

---

## 3. Benchmark Methodology

### Fixture Corpus

The benchmark uses a synthetic corpus designed to represent real-world scanning workloads:

- **40% benign pickle files** — Realistic model weight structures
- **20% malicious pickle files** — Various dangerous opcode patterns
- **30% safetensors files** — Clean tensor metadata + dummy data
- **10% config JSON files** — Model configuration files

### Measurement Protocol

1. **Warmup**: 3 iterations over 10 files (JIT warm, disk cache)
2. **Measurement**: Single pass over all 100 files, individually timed
3. **Statistics**: min, max, mean, median, stddev, p50/p90/p95/p99
4. **Repetition**: CI runs 3 consecutive benchmark passes; worst p95 is used

### Running Benchmarks Locally

```bash
# Basic benchmark with default settings
python benchmarks/scan_perf.py

# With custom threshold and output
python benchmarks/scan_perf.py --threshold 50 --output results.json

# Using pre-existing fixture directory
python benchmarks/scan_perf.py --fixtures-dir ./test-corpus --output results.json

# Compare two benchmark runs
python benchmarks/compare.py baseline.json current.json
```

### Profiling

For investigating performance regressions:

```bash
# CPU profiling
python -m cProfile -o profile.pstats benchmarks/scan_perf.py
python -m pstats profile.pstats

# Memory profiling
pip install memray
memray run benchmarks/scan_perf.py
memray flamegraph memray-output.bin

# Line-level profiling
pip install line_profiler
kernprof -l -v benchmarks/scan_perf.py
```

---

## 4. CI Integration

### Automated Regression Detection

The CI pipeline (`.github/workflows/ci.yml`) runs the benchmark on every push to `main` and on every PR:

```yaml
- name: Run performance benchmark
  run: |
    python benchmarks/scan_perf.py \
      --output benchmark-results.json \
      --threshold 50
```

### Regression Thresholds

| Metric | Warning | Failure |
|--------|---------|---------|
| p95 latency | > 40ms (80% of limit) | > 50ms |
| Throughput | < 300 files/sec | < 200 files/sec |
| Any single file | > 200ms | > 500ms |

### Tracking Over Time

Benchmark results are uploaded as CI artifacts and can be tracked using:

1. **GitHub Actions artifacts**: Each run produces `benchmark-results.json`
2. **Benchmark dashboard**: Results are optionally pushed to a tracking service
3. **PR comments**: Bot comments on PRs with performance diff when threshold approached

---

## 5. Performance Optimization Guidelines

### Design Principles

1. **Zero-copy scanning**: Read file bytes once, scan in-place
2. **Early termination**: Stop scanning a file at first CRITICAL finding (configurable)
3. **Rule ordering**: Most common/cheapest rules run first
4. **No dependencies**: Zero external dependencies for core scanner (pure Python)
5. **Lazy loading**: Rules loaded on demand by file type

### Known Performance Characteristics

| Operation | Cost | Notes |
|-----------|------|-------|
| Pickle opcode parsing | O(n) file size | Single pass, byte-by-byte |
| GLOBAL opcode check | O(1) per opcode | String prefix matching |
| Safetensors header parsing | O(header size) | JSON parse, typically < 1KB |
| Rule matching | O(r) per opcode | r = applicable rules (subset) |
| JSON output serialization | O(findings) | Negligible for typical scans |

### Performance Anti-Patterns to Avoid

- ❌ Loading entire large files into memory
- ❌ Regex matching on raw bytes (use opcode parser)
- ❌ Re-parsing rules on every file
- ❌ Synchronous network calls during scan
- ❌ Deep recursion on nested pickle structures

---

## 6. Regression Response Process

### When a Regression is Detected

1. **CI fails** on performance benchmark step
2. **Investigate** using profiling tools (see §3)
3. **Root cause** — common causes:
   - New rule with expensive pattern matching
   - Accidentally quadratic algorithm in opcode parser
   - Unintended file re-reading
   - Debug logging left enabled
4. **Fix** — options:
   - Optimize the new code path
   - Add caching/memoization
   - Reorder rule evaluation
   - Split expensive rule into pre-filter + detailed check
5. **Verify** — benchmark must pass before merge

### Acceptable Regression Justifications

A performance regression may be accepted if:

- It adds critical security detection that cannot be optimized further
- The regression is < 10% and adds significant functionality
- A follow-up optimization ticket is filed and prioritized

All accepted regressions require:
- Team lead approval
- Updated baseline in this document
- CHANGELOG entry noting the performance impact

---

## 7. Historical Performance Data

| Version | Date | p95 (ms) | Throughput (files/sec) | Notes |
|---------|------|-----------|----------------------|-------|
| 1.0.0 | 2026-03-15 | 2.8 | 580 | Initial release |
| 1.1.0 | 2026-05-01 | 3.0 | 560 | +20 new rules |
| 1.2.0 | 2026-06-20 | 3.1 | 550 | Added safetensors support |
| 1.3.0 | 2026-08-01 | 3.2 | 555 | +15 rules, optimized parser |
| 1.4.0 | 2026-08-27 | TBD | TBD | Current (benchmark pending) |

---

*Last updated: 2026-08-27*
*Owner: Core maintainers*
*Benchmark suite: `benchmarks/scan_perf.py`*
