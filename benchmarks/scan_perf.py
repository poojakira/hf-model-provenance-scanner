"""
Performance benchmark for HuggingFace Model Provenance Scanner.

Measures scan throughput and latency across a corpus of fixture files.
Results are output as JSON for tracking in CI and detecting regressions.

Usage:
    python benchmarks/scan_perf.py [--fixtures-dir DIR] [--output results.json]

Exit codes:
    0 - All performance assertions passed
    1 - Performance regression detected (p95 > threshold)
"""

import argparse
import json
import pickle
import statistics
import struct
import sys
import tempfile
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

NUM_FIXTURE_FILES = 100
P95_THRESHOLD_MS = 100.0  # Max acceptable p95 latency per file (ms). Set with
# headroom for cold-cache file reads on CI runners;
# warm-run p95 is typically ~3-6ms (see docs).
WARMUP_ITERATIONS = 5  # Number of warmup passes before measuring


# ---------------------------------------------------------------------------
# Fixture Generation
# ---------------------------------------------------------------------------


def generate_benign_pickle(index: int) -> bytes:
    """Generate a benign pickle file with realistic model-like structure."""
    data = {
        "layer_weights": {f"layer_{i}": list(range(100)) for i in range(10)},
        "metadata": {
            "model_name": f"benchmark-model-{index}",
            "framework": "pytorch",
            "version": "2.1.0",
            "parameters": 7_000_000_000,
        },
        "config": {
            "hidden_size": 4096,
            "num_attention_heads": 32,
            "num_hidden_layers": 32,
            "vocab_size": 32000,
        },
    }
    return pickle.dumps(data, protocol=2)


def generate_malicious_pickle(index: int) -> bytes:
    """Generate a pickle with dangerous GLOBAL opcodes for scanner to detect."""
    PROTO = b"\x80\x02"
    GLOBAL = b"\x63"
    SHORT_BINUNICODE = b"\x8c"
    TUPLE1 = b"\x85"
    REDUCE = b"\x52"
    STOP = b"."

    dangerous_modules = [
        b"os\nsystem\n",
        b"subprocess\ncall\n",
        b"builtins\neval\n",
        b"nt\nsystem\n",
        b"posix\nsystem\n",
    ]

    module = dangerous_modules[index % len(dangerous_modules)]
    arg = b"echo test"

    return (
        PROTO
        + GLOBAL
        + module
        + SHORT_BINUNICODE
        + struct.pack("<B", len(arg))
        + arg
        + TUPLE1
        + REDUCE
        + STOP
    )


def generate_safetensors_file(index: int) -> bytes:
    """Generate a minimal safetensors-format file."""
    header = json.dumps(
        {
            "__metadata__": {"format": "pt"},
            f"model.layer.{index}.weight": {
                "dtype": "F32",
                "shape": [1024, 1024],
                "data_offsets": [0, 4194304],
            },
        }
    ).encode()
    header_size = struct.pack("<Q", len(header))
    # Add some dummy tensor data
    dummy_data = b"\x00" * 1024
    return header_size + header + dummy_data


def create_fixture_corpus(tmp_dir: Path) -> list:
    """
    Create a mixed corpus of files for benchmarking.

    Distribution:
    - 40% benign pickle files
    - 20% malicious pickle files
    - 30% safetensors files
    - 10% config JSON files
    """
    files = []

    for i in range(40):
        fp = tmp_dir / f"benign_model_{i:03d}.pkl"
        fp.write_bytes(generate_benign_pickle(i))
        files.append(fp)

    for i in range(20):
        fp = tmp_dir / f"malicious_model_{i:03d}.pkl"
        fp.write_bytes(generate_malicious_pickle(i))
        files.append(fp)

    for i in range(30):
        fp = tmp_dir / f"model_shard_{i:03d}.safetensors"
        fp.write_bytes(generate_safetensors_file(i))
        files.append(fp)

    for i in range(10):
        fp = tmp_dir / f"config_{i:03d}.json"
        fp.write_text(
            json.dumps(
                {
                    "model_type": "llama",
                    "architectures": ["LlamaForCausalLM"],
                    "hidden_size": 4096,
                    "num_layers": 32,
                    "index": i,
                }
            )
        )
        files.append(fp)

    return files


# ---------------------------------------------------------------------------
# Benchmark Runner
# ---------------------------------------------------------------------------


def import_scanner():
    """Return a callable that scans a single file in-process.

    Uses the real per-format analyzers from scanner.cli (pickle, safetensors,
    config, generic source). This measures the true analysis hot path without
    subprocess/interpreter startup overhead.
    """
    from pathlib import Path as _Path

    from scanner.cli import (
        analyze_config_file,
        analyze_pickle_file,
        analyze_safetensors_file,
        is_pickle_file,
        is_safetensors_file,
    )

    def scan_file(path: str):
        p = _Path(path)
        try:
            data = p.read_bytes()
        except OSError:
            return []
        if is_pickle_file(p):
            return analyze_pickle_file(str(p), data)
        if is_safetensors_file(p):
            return analyze_safetensors_file(str(p), data)
        if p.suffix.lower() in (".json", ".yaml", ".yml", ".toml"):
            return analyze_config_file(str(p), data)
        return []

    return scan_file


def run_benchmark(fixtures_dir: Path, output_path: Path | None = None) -> dict:
    """
    Run the performance benchmark suite.

    Returns a dict with all timing results and pass/fail status.
    """
    scan_file = import_scanner()
    files = sorted(fixtures_dir.glob("*"))

    if len(files) < NUM_FIXTURE_FILES:
        print(f"WARNING: Only {len(files)} fixture files found, expected {NUM_FIXTURE_FILES}")

    # --- Warmup phase ---
    print(f"Warming up ({WARMUP_ITERATIONS} iterations)...")
    for _ in range(WARMUP_ITERATIONS):
        for f in files[:10]:
            scan_file(str(f))

    # --- Measurement phase ---
    print(f"Benchmarking {len(files)} files...")
    timings = []
    file_results = []

    for filepath in files:
        start = time.perf_counter()
        try:
            result = scan_file(str(filepath))
            success = True
            error = None
        except Exception as e:
            result = None
            success = False
            error = str(e)
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        timings.append(elapsed_ms)
        file_results.append(
            {
                "file": filepath.name,
                "elapsed_ms": round(elapsed_ms, 3),
                "success": success,
                "error": error,
            }
        )

    # --- Calculate statistics ---
    timings_sorted = sorted(timings)
    total_time_s = sum(timings) / 1000.0

    stats = {
        "num_files": len(files),
        "total_time_seconds": round(total_time_s, 3),
        "throughput_files_per_sec": round(len(files) / total_time_s, 1) if total_time_s > 0 else 0,
        "latency_ms": {
            "min": round(min(timings), 3),
            "max": round(max(timings), 3),
            "mean": round(statistics.mean(timings), 3),
            "median": round(statistics.median(timings), 3),
            "stddev": round(statistics.stdev(timings), 3) if len(timings) > 1 else 0,
            "p50": round(timings_sorted[int(len(timings_sorted) * 0.50)], 3),
            "p90": round(timings_sorted[int(len(timings_sorted) * 0.90)], 3),
            "p95": round(timings_sorted[int(len(timings_sorted) * 0.95)], 3),
            "p99": round(timings_sorted[int(len(timings_sorted) * 0.99)], 3),
        },
    }

    # --- Performance assertion ---
    p95 = stats["latency_ms"]["p95"]
    passed = p95 <= P95_THRESHOLD_MS

    results = {
        "benchmark": "hf-scanner-scan-performance",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "python_version": sys.version,
        "platform": sys.platform,
        "configuration": {
            "num_fixture_files": NUM_FIXTURE_FILES,
            "p95_threshold_ms": P95_THRESHOLD_MS,
            "warmup_iterations": WARMUP_ITERATIONS,
        },
        "statistics": stats,
        "passed": passed,
        "assertion": {
            "metric": "p95_latency_ms",
            "actual": p95,
            "threshold": P95_THRESHOLD_MS,
            "result": "PASS" if passed else "FAIL",
        },
        "file_results": file_results,
    }

    # --- Output ---
    output_json = json.dumps(results, indent=2)

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(output_json)
        print(f"Results written to: {output_path}")
    else:
        print(output_json)

    # --- Summary ---
    print(f"\n{'='*60}")
    print("  SCAN PERFORMANCE BENCHMARK RESULTS")
    print(f"{'='*60}")
    print(f"  Files scanned:    {stats['num_files']}")
    print(f"  Total time:       {stats['total_time_seconds']:.3f}s")
    print(f"  Throughput:       {stats['throughput_files_per_sec']:.1f} files/sec")
    print(f"  p50 latency:      {stats['latency_ms']['p50']:.3f}ms")
    print(f"  p95 latency:      {stats['latency_ms']['p95']:.3f}ms")
    print(f"  p99 latency:      {stats['latency_ms']['p99']:.3f}ms")
    print(f"  Threshold (p95):  {P95_THRESHOLD_MS}ms")
    print(f"  Status:           {'PASS' if passed else 'FAIL'}")
    print(f"{'='*60}\n")

    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    global P95_THRESHOLD_MS
    parser = argparse.ArgumentParser(description="HF Scanner performance benchmark")
    parser.add_argument(
        "--fixtures-dir",
        type=Path,
        default=None,
        help="Directory containing fixture files (generated if not provided)",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=None,
        help="Output path for JSON results",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=P95_THRESHOLD_MS,
        help=f"p95 threshold in ms (default: {P95_THRESHOLD_MS})",
    )
    args = parser.parse_args()

    P95_THRESHOLD_MS = args.threshold

    if args.fixtures_dir and args.fixtures_dir.exists():
        fixtures_dir = args.fixtures_dir
    else:
        # Generate fixture corpus in temp directory
        tmp_dir = tempfile.mkdtemp(prefix="hf_scanner_bench_")
        fixtures_dir = Path(tmp_dir)
        print(f"Generating {NUM_FIXTURE_FILES} fixture files in {fixtures_dir}...")
        create_fixture_corpus(fixtures_dir)

    results = run_benchmark(fixtures_dir, args.output)

    # Exit with appropriate code
    sys.exit(0 if results["passed"] else 1)


if __name__ == "__main__":
    main()
