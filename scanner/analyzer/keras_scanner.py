"""
Keras/H5 Model Scanner — Detect Lambda layers and unsafe custom objects.

Keras models saved in HDF5 (.h5) or SavedModel format can contain:
1. Lambda layers with arbitrary Python code (executed on model load)
2. custom_objects references that load arbitrary classes
3. Embedded Python source in model config JSON
4. Unsafe deserialization via pickle in older Keras versions

Since we can't import h5py (zero deps), we scan the raw bytes for:
- JSON model config embedded in the file
- Python code patterns within Lambda layer definitions
- custom_objects declarations
"""

import re

from scanner.models import Finding
from scanner.rules.definitions import get_rule

# HDF5 magic number
HDF5_MAGIC = b"\x89HDF\r\n\x1a\n"

# Patterns indicating Keras model config
KERAS_CONFIG_PATTERNS = [
    re.compile(rb'"class_name"\s*:\s*"Lambda"', re.IGNORECASE),
    re.compile(rb'"class_name"\s*:\s*"TFOpLambda"', re.IGNORECASE),
]

# Patterns for dangerous code in Lambda layers
LAMBDA_CODE_PATTERNS = [
    re.compile(r"os\.", re.IGNORECASE),
    re.compile(r"subprocess", re.IGNORECASE),
    re.compile(r"__import__", re.IGNORECASE),
    re.compile(r"exec\s*\(", re.IGNORECASE),
    re.compile(r"eval\s*\(", re.IGNORECASE),
    re.compile(r"open\s*\(", re.IGNORECASE),
    re.compile(r"system\s*\(", re.IGNORECASE),
    re.compile(r"urllib|requests|socket", re.IGNORECASE),
    re.compile(r"base64\.", re.IGNORECASE),
    re.compile(r"pickle\.", re.IGNORECASE),
    re.compile(r"ctypes\.", re.IGNORECASE),
]

# custom_objects detection
CUSTOM_OBJECTS_RE = re.compile(
    rb'"custom_objects"\s*:\s*\{[^}]+\}', re.DOTALL
)

# Keras config JSON extraction (find JSON blobs in binary)
JSON_BLOB_RE = re.compile(
    rb'\{[^{}]*"class_name"[^{}]*\}', re.DOTALL
)


def _make_finding(rule_id: str, file_path: str, evidence: str) -> Finding:
    rule = get_rule(rule_id)
    return Finding(
        rule_id=rule_id, severity=rule.severity, file_path=file_path,
        line_number=0, column=0, message=rule.description,
        evidence=evidence[:300], remediation=rule.remediation, cwe=rule.cwe,
    )


def is_keras_file(file_path: str) -> bool:
    """Check if file might be a Keras model."""
    lower = file_path.lower()
    return lower.endswith((".h5", ".hdf5", ".keras"))


def analyze_keras_file(file_path: str, data: bytes) -> list[Finding]:
    """
    Scan a Keras model file for Lambda layers and unsafe patterns.
    """
    findings: list[Finding] = []

    # Verify it's actually HDF5 (or at least has relevant content)
    is_hdf5 = data[:8] == HDF5_MAGIC
    is_keras_zip = data[:2] == b"PK"  # .keras format is ZIP

    if not is_hdf5 and not is_keras_zip:
        # Try scanning as raw bytes anyway (might be a config file)
        if b"class_name" not in data:
            return findings

    # Check for Lambda layers
    for pattern in KERAS_CONFIG_PATTERNS:
        matches = pattern.findall(data)
        if matches:
            findings.append(_make_finding(
                "HFS-076", file_path,
                f"Keras Lambda layer detected. Lambda layers can execute "
                f"arbitrary Python code on model load. Found {len(matches)} "
                f"Lambda layer(s)."
            ))
            break

    # Extract and analyze JSON config blobs
    _scan_embedded_configs(file_path, data, findings)

    # Check for custom_objects
    custom_obj_matches = CUSTOM_OBJECTS_RE.findall(data)
    if custom_obj_matches:
        for match in custom_obj_matches[:3]:
            try:
                snippet = match.decode("utf-8", errors="replace")
                findings.append(_make_finding(
                    "HFS-076", file_path,
                    f"custom_objects declaration found: {snippet[:200]}. "
                    "Custom objects can load arbitrary classes on deserialization."
                ))
            except Exception:
                pass

    # Check for pickle markers in the file
    if b"cos\nsystem\n" in data or b"csubprocess\n" in data:
        findings.append(_make_finding(
            "HFS-076", file_path,
            "Pickle opcode patterns found in Keras model file. "
            "This file may contain embedded pickle payloads."
        ))

    return findings


def _scan_embedded_configs(
    file_path: str, data: bytes, findings: list[Finding]
):
    """Extract JSON configs from the binary and scan for dangerous code."""
    # Search for model_config or config JSON within the file
    # Keras stores config as a JSON string attribute in HDF5
    config_markers = [b"model_config", b'"config"', b'"keras_version"']

    for marker in config_markers:
        idx = data.find(marker)
        if idx == -1:
            continue

        # Try to extract a JSON blob around this marker
        # Search forward for a complete JSON object
        search_start = max(0, idx - 100)
        search_end = min(len(data), idx + 100_000)
        chunk = data[search_start:search_end]

        # Find JSON-like structures
        try:
            text = chunk.decode("utf-8", errors="replace")
        except Exception:
            continue

        # Look for Lambda function bodies
        lambda_pattern = re.compile(
            r'"function"\s*:\s*"([^"]+)"', re.DOTALL
        )
        for match in lambda_pattern.finditer(text):
            func_body = match.group(1)
            # Unescape
            func_body = func_body.replace("\\n", "\n").replace("\\t", "\t")

            # Check if Lambda body contains dangerous patterns
            for danger_pattern in LAMBDA_CODE_PATTERNS:
                if danger_pattern.search(func_body):
                    findings.append(_make_finding(
                        "HFS-076", file_path,
                        f"Dangerous code in Keras Lambda layer: "
                        f"'{func_body[:150]}'"
                    ))
                    break
