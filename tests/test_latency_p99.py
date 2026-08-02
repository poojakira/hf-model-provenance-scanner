"""P99 latency benchmark and false-positive verification.

Measures scanner performance on clean model payloads to verify:
- P99 latency < 200 ms per scan (over 50 runs)
- Zero false positives on GPT-2 and Llama-3-8B clean inputs

All data is constructed in-memory. No network calls.
"""

import json
import struct
import time

from scanner.analyzer.ast_visitor import analyze_python_source
from scanner.analyzer.safetensors_scanner import analyze_safetensors_file


def _build_clean_safetensors(n_layers: int, model_name: str) -> bytes:
    """Build a valid safetensors binary with no malicious content."""
    offset = 0
    header = {"__metadata__": {"format": "pt", "model_type": model_name}}
    for i in range(n_layers):
        size = 768 * 4
        header[f"model.layers.{i}.weight"] = {
            "dtype": "F32",
            "shape": [768],
            "data_offsets": [offset, offset + size],
        }
        offset += size
    hdr_bytes = json.dumps(header).encode()
    return struct.pack("<Q", len(hdr_bytes)) + hdr_bytes + b"\x00" * offset


def _build_clean_config(model_name: str) -> str:
    """Return clean Python config with no suspicious patterns."""
    return (
        f"# Configuration for {model_name}\n"
        "HIDDEN_SIZE = 768\n"
        "NUM_LAYERS = 12\n"
        "VOCAB_SIZE = 50257\n"
        "MAX_SEQ_LEN = 2048\n"
    )


GPT2_SAFETENSORS = _build_clean_safetensors(12, "openai-community/gpt2")
GPT2_CONFIG = _build_clean_config("openai-community/gpt2")
LLAMA3_SAFETENSORS = _build_clean_safetensors(32, "meta-llama/Meta-Llama-3-8B")
LLAMA3_CONFIG = _build_clean_config("meta-llama/Meta-Llama-3-8B")

N_RUNS = 50
P99_LIMIT_MS = 200.0


def _p99(timings: list[float]) -> float:
    s = sorted(timings)
    return s[int(len(s) * 0.99)]


def _scan_once(st_bytes: bytes, config_src: str, name: str) -> float:
    """Run scanners and return elapsed ms. Assert zero findings."""
    t0 = time.perf_counter()
    findings_st = analyze_safetensors_file(f"{name}.safetensors", st_bytes)
    findings_py = analyze_python_source(f"{name}_config.py", config_src)
    elapsed_ms = (time.perf_counter() - t0) * 1000
    assert findings_st == [], f"FP on {name} safetensors: {findings_st}"
    assert findings_py == [], f"FP on {name} config: {findings_py}"
    return elapsed_ms


class TestLatencyAndFalsePositives:
    def test_gpt2_zero_false_positives(self):
        """GPT-2 clean model produces zero scanner findings."""
        assert analyze_safetensors_file("gpt2.safetensors", GPT2_SAFETENSORS) == []
        assert analyze_python_source("gpt2_config.py", GPT2_CONFIG) == []

    def test_llama3_8b_zero_false_positives(self):
        """Llama-3-8B clean model produces zero scanner findings."""
        assert analyze_safetensors_file("llama3.safetensors", LLAMA3_SAFETENSORS) == []
        assert analyze_python_source("llama3_config.py", LLAMA3_CONFIG) == []

    def test_gpt2_p99_under_200ms(self):
        """GPT-2 scan P99 latency stays under 200 ms."""
        timings = [_scan_once(GPT2_SAFETENSORS, GPT2_CONFIG, "gpt2") for _ in range(N_RUNS)]
        p99 = _p99(timings)
        print(f"\n  GPT-2 P99={p99:.1f}ms mean={sum(timings)/len(timings):.1f}ms")
        assert p99 < P99_LIMIT_MS, f"GPT-2 P99 {p99:.1f}ms > {P99_LIMIT_MS}ms"

    def test_llama3_8b_p99_under_200ms(self):
        """Llama-3-8B scan P99 latency stays under 200 ms."""
        timings = [_scan_once(LLAMA3_SAFETENSORS, LLAMA3_CONFIG, "llama3") for _ in range(N_RUNS)]
        p99 = _p99(timings)
        print(f"\n  Llama-3-8B P99={p99:.1f}ms mean={sum(timings)/len(timings):.1f}ms")
        assert p99 < P99_LIMIT_MS, f"Llama-3-8B P99 {p99:.1f}ms > {P99_LIMIT_MS}ms"
