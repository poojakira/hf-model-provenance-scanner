"""
GGUF Format Inspector — Scan GGUF model files for metadata anomalies.

GGUF (GPT-Generated Unified Format) is used by llama.cpp and derivatives.
Attack surfaces:
1. Metadata key-value pairs can contain URLs, scripts, or encoded payloads
2. Custom metadata fields can hide C2 endpoints
3. Tensor names can contain injection strings
4. File header manipulation for parser confusion

Format specification: https://github.com/ggerganov/ggml/blob/master/docs/gguf.md
"""

import re
import struct

from scanner.models import Finding
from scanner.rules.definitions import get_rule

# GGUF magic number
GGUF_MAGIC = b"GGUF"
GGUF_MAGIC_LE = 0x46475547  # "GGUF" as LE uint32

# GGUF value types
GGUF_TYPE_UINT8 = 0
GGUF_TYPE_INT8 = 1
GGUF_TYPE_UINT16 = 2
GGUF_TYPE_INT16 = 3
GGUF_TYPE_UINT32 = 4
GGUF_TYPE_INT32 = 5
GGUF_TYPE_FLOAT32 = 6
GGUF_TYPE_BOOL = 7
GGUF_TYPE_STRING = 8
GGUF_TYPE_ARRAY = 9
GGUF_TYPE_UINT64 = 10
GGUF_TYPE_INT64 = 11
GGUF_TYPE_FLOAT64 = 12

# Suspicious patterns in metadata values
SUSPICIOUS_METADATA_PATTERNS = [
    re.compile(r"https?://[^\s]+", re.IGNORECASE),
    re.compile(r"powershell|cmd\.exe|/bin/(?:ba)?sh", re.IGNORECASE),
    re.compile(r"eval\s*\(|exec\s*\(", re.IGNORECASE),
    re.compile(r"subprocess|os\.system", re.IGNORECASE),
    re.compile(r"base64\.b64decode", re.IGNORECASE),
    re.compile(r"\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){3,}", re.IGNORECASE),
    re.compile(r"<script|javascript:", re.IGNORECASE),
    re.compile(r"curl\s+.*\|.*sh", re.IGNORECASE),
]

# Known legitimate metadata keys
LEGITIMATE_KEYS = {
    "general.architecture", "general.name", "general.author",
    "general.description", "general.url", "general.license",
    "general.file_type", "general.quantization_version",
    "general.source.url", "general.source.huggingface.repository",
}


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


def is_gguf_file(file_path: str) -> bool:
    """Check if file is a GGUF file by extension."""
    return file_path.lower().endswith(".gguf")


def _read_gguf_string(data: bytes, pos: int) -> tuple[str, int]:
    """Read a GGUF string (uint64 length + UTF-8 data)."""
    if pos + 8 > len(data):
        raise ValueError("Truncated string length")
    str_len = struct.unpack_from("<Q", data, pos)[0]
    pos += 8
    if str_len > 10_000_000:  # 10MB string limit
        raise ValueError(f"String too long: {str_len}")
    if pos + str_len > len(data):
        raise ValueError("Truncated string data")
    value = data[pos:pos + str_len].decode("utf-8", errors="replace")
    return value, pos + str_len


def _read_gguf_value(data: bytes, pos: int, value_type: int) -> tuple:
    """Read a typed GGUF value. Returns (value, new_pos)."""
    if value_type == GGUF_TYPE_UINT8:
        return data[pos], pos + 1
    elif value_type == GGUF_TYPE_INT8:
        return struct.unpack_from("<b", data, pos)[0], pos + 1
    elif value_type == GGUF_TYPE_UINT16:
        return struct.unpack_from("<H", data, pos)[0], pos + 2
    elif value_type == GGUF_TYPE_INT16:
        return struct.unpack_from("<h", data, pos)[0], pos + 2
    elif value_type == GGUF_TYPE_UINT32:
        return struct.unpack_from("<I", data, pos)[0], pos + 4
    elif value_type == GGUF_TYPE_INT32:
        return struct.unpack_from("<i", data, pos)[0], pos + 4
    elif value_type == GGUF_TYPE_FLOAT32:
        return struct.unpack_from("<f", data, pos)[0], pos + 4
    elif value_type == GGUF_TYPE_UINT64:
        return struct.unpack_from("<Q", data, pos)[0], pos + 8
    elif value_type == GGUF_TYPE_INT64:
        return struct.unpack_from("<q", data, pos)[0], pos + 8
    elif value_type == GGUF_TYPE_FLOAT64:
        return struct.unpack_from("<d", data, pos)[0], pos + 8
    elif value_type == GGUF_TYPE_BOOL:
        return bool(data[pos]), pos + 1
    elif value_type == GGUF_TYPE_STRING:
        return _read_gguf_string(data, pos)
    elif value_type == GGUF_TYPE_ARRAY:
        # Array: element_type(uint32) + count(uint64) + elements
        elem_type = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        count = struct.unpack_from("<Q", data, pos)[0]
        pos += 8
        if count > 1_000_000:
            raise ValueError(f"Array too large: {count}")
        elements = []
        for _ in range(min(count, 100)):  # Scan first 100 elements max
            val, pos = _read_gguf_value(data, pos, elem_type)
            elements.append(val)
        # Skip remaining elements
        if count > 100:
            for _ in range(count - 100):
                _, pos = _read_gguf_value(data, pos, elem_type)
        return elements, pos
    else:
        raise ValueError(f"Unknown GGUF type: {value_type}")


def analyze_gguf_file(file_path: str, data: bytes) -> list[Finding]:
    """
    Parse GGUF header and metadata, scanning for anomalies and injections.
    """
    findings: list[Finding] = []

    if len(data) < 24:  # Minimum: magic(4) + version(4) + tensor_count(8) + kv_count(8)
        findings.append(_make_finding(
            "HFS-058", file_path,
            "File too small to be valid GGUF"
        ))
        return findings

    # Verify magic
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic != GGUF_MAGIC_LE:
        findings.append(_make_finding(
            "HFS-058", file_path,
            f"Invalid GGUF magic: 0x{magic:08X} (expected 0x{GGUF_MAGIC_LE:08X})"
        ))
        return findings

    # Parse header
    version = struct.unpack_from("<I", data, 4)[0]
    if version < 2 or version > 3:
        findings.append(_make_finding(
            "HFS-058", file_path,
            f"Unsupported GGUF version: {version} (expected 2 or 3)"
        ))
        return findings

    tensor_count = struct.unpack_from("<Q", data, 8)[0]
    kv_count = struct.unpack_from("<Q", data, 16)[0]

    if kv_count > 100_000:
        findings.append(_make_finding(
            "HFS-057", file_path,
            f"Excessive metadata entries: {kv_count:,} (possible header abuse)"
        ))
        return findings

    # Parse key-value metadata
    pos = 24
    metadata_strings: list[tuple[str, str]] = []

    try:
        for _ in range(min(kv_count, 10_000)):
            # Read key
            key, pos = _read_gguf_string(data, pos)

            # Read value type
            if pos + 4 > len(data):
                break
            value_type = struct.unpack_from("<I", data, pos)[0]
            pos += 4

            # Read value
            value, pos = _read_gguf_value(data, pos, value_type)

            # Collect string values for scanning
            if isinstance(value, str):
                metadata_strings.append((key, value))
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        metadata_strings.append((key, item))

    except (ValueError, struct.error, IndexError):
        # Partial parse is OK — scan what we have
        pass

    # Scan collected metadata strings
    for key, value in metadata_strings:
        # Check for suspicious content
        for pattern in SUSPICIOUS_METADATA_PATTERNS:
            match = pattern.search(value)
            if match:
                # URLs in general.url or general.source.url are expected
                if key in LEGITIMATE_KEYS and pattern.pattern.startswith("http"):
                    continue
                findings.append(_make_finding(
                    "HFS-056", file_path,
                    f"Suspicious metadata in key '{key}': "
                    f"matched '{match.group()[:80]}'"
                ))
                break

        # Check for excessively long values (potential payload staging)
        if len(value) > 50_000:
            findings.append(_make_finding(
                "HFS-057", file_path,
                f"Oversized metadata value for '{key}': {len(value):,} chars"
            ))

    return findings
