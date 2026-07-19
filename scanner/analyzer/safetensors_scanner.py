"""
SafeTensors Format Validator — Detect metadata injection and format abuse.

SafeTensors is designed to be safe, but attackers can:
1. Inject code into oversized metadata headers
2. Hide URLs/scripts in tensor name fields
3. Exploit metadata parsing bugs with malformed headers
4. Use the __metadata__ field to embed executable content

This scanner validates SafeTensors structural integrity without loading tensors.
"""

import json
import re
import struct

from scanner.models import Finding
from scanner.rules.definitions import get_rule

# SafeTensors format: 8-byte LE header_size + JSON header + tensor data
SAFETENSORS_HEADER_SIZE_BYTES = 8
MAX_REASONABLE_HEADER_SIZE = 10_000_000  # 10MB header is suspicious
MAX_REASONABLE_METADATA_VALUE = 10_000   # Single metadata value > 10KB
SUSPICIOUS_PATTERNS = [
    re.compile(r"https?://[^\s\"']+", re.IGNORECASE),
    re.compile(r"<script[^>]*>", re.IGNORECASE),
    re.compile(r"\\x[0-9a-f]{2}", re.IGNORECASE),
    re.compile(r"base64[,:]", re.IGNORECASE),
    re.compile(r"eval\s*\(", re.IGNORECASE),
    re.compile(r"exec\s*\(", re.IGNORECASE),
    re.compile(r"import\s+os", re.IGNORECASE),
    re.compile(r"subprocess", re.IGNORECASE),
    re.compile(r"powershell", re.IGNORECASE),
    re.compile(r"cmd\.exe", re.IGNORECASE),
]


def _make_finding(rule_id: str, file_path: str, evidence: str) -> Finding:
    rule = get_rule(rule_id)
    return Finding(
        rule_id=rule_id,
        severity=rule.severity,
        file_path=file_path,
        line_number=0,
        column=0,
        message=rule.description,
        evidence=evidence[:300],
        remediation=rule.remediation,
        cwe=rule.cwe,
    )


def is_safetensors_file(file_path: str) -> bool:
    """Check if file is a SafeTensors file by extension."""
    return file_path.lower().endswith(".safetensors")


def analyze_safetensors_file(file_path: str, data: bytes) -> list[Finding]:
    """
    Validate SafeTensors file structure and scan metadata for injections.
    """
    findings: list[Finding] = []

    if len(data) < SAFETENSORS_HEADER_SIZE_BYTES:
        findings.append(_make_finding(
            "HFS-055", file_path,
            "File too small to be valid SafeTensors (< 8 bytes)"
        ))
        return findings

    # Parse header size (first 8 bytes, little-endian uint64)
    header_size = struct.unpack_from("<Q", data, 0)[0]

    # Validate header size
    if header_size == 0:
        findings.append(_make_finding(
            "HFS-055", file_path,
            "SafeTensors header size is 0 — invalid file"
        ))
        return findings

    if header_size > MAX_REASONABLE_HEADER_SIZE:
        findings.append(_make_finding(
            "HFS-054", file_path,
            f"Oversized SafeTensors header: {header_size:,} bytes "
            f"(max expected: {MAX_REASONABLE_HEADER_SIZE:,}). "
            "May contain injected code or data."
        ))

    if header_size > len(data) - SAFETENSORS_HEADER_SIZE_BYTES:
        findings.append(_make_finding(
            "HFS-055", file_path,
            f"Header size ({header_size:,}) exceeds file data "
            f"({len(data) - SAFETENSORS_HEADER_SIZE_BYTES:,} available)"
        ))
        return findings

    # Extract and parse JSON header
    header_bytes = data[SAFETENSORS_HEADER_SIZE_BYTES:
                        SAFETENSORS_HEADER_SIZE_BYTES + header_size]

    try:
        header_json = json.loads(header_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        findings.append(_make_finding(
            "HFS-055", file_path,
            f"SafeTensors header is not valid JSON: {e}"
        ))
        return findings

    if not isinstance(header_json, dict):
        findings.append(_make_finding(
            "HFS-055", file_path,
            f"SafeTensors header root is {type(header_json).__name__}, expected dict"
        ))
        return findings

    # Scan __metadata__ field for injected content
    metadata = header_json.get("__metadata__")
    if metadata and isinstance(metadata, dict):
        _scan_metadata(file_path, metadata, findings)

    # Scan tensor names for suspicious patterns
    for key, value in header_json.items():
        if key == "__metadata__":
            continue
        # Check tensor name itself
        _check_string_for_injection(file_path, f"tensor_name:{key}", key, findings)
        # Check tensor descriptor fields
        if isinstance(value, dict):
            dtype = value.get("dtype", "")
            if isinstance(dtype, str) and len(dtype) > 20:
                findings.append(_make_finding(
                    "HFS-054", file_path,
                    f"Suspicious dtype value in tensor '{key}': {dtype[:100]}"
                ))

    # Verify tensor data region makes sense
    expected_data_start = SAFETENSORS_HEADER_SIZE_BYTES + header_size
    actual_remaining = len(data) - expected_data_start
    if actual_remaining < 0:
        findings.append(_make_finding(
            "HFS-055", file_path,
            "No tensor data region — file is header-only"
        ))

    return findings


def _scan_metadata(file_path: str, metadata: dict, findings: list[Finding]):
    """Deep-scan the __metadata__ dict for injected content."""
    total_metadata_size = 0

    for key, value in metadata.items():
        if not isinstance(value, str):
            continue

        total_metadata_size += len(value)

        # Check for oversized individual values
        if len(value) > MAX_REASONABLE_METADATA_VALUE:
            findings.append(_make_finding(
                "HFS-054", file_path,
                f"Oversized metadata value for key '{key}': "
                f"{len(value):,} chars (suspicious)"
            ))

        # Scan for injection patterns
        _check_string_for_injection(
            file_path, f"__metadata__.{key}", value, findings
        )

    # Total metadata size check
    if total_metadata_size > 1_000_000:
        findings.append(_make_finding(
            "HFS-054", file_path,
            f"Total __metadata__ content: {total_metadata_size:,} bytes — "
            "excessive for model metadata"
        ))


def _check_string_for_injection(
    file_path: str, context: str, value: str, findings: list[Finding]
):
    """Check a string value for code/URL injection patterns."""
    for pattern in SUSPICIOUS_PATTERNS:
        match = pattern.search(value)
        if match:
            findings.append(_make_finding(
                "HFS-053", file_path,
                f"Suspicious content in {context}: "
                f"pattern='{pattern.pattern}' match='{match.group()[:80]}'"
            ))
            break  # One finding per field is enough
