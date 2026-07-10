"""
Tests for the GGUF format inspector.
Verifies detection of metadata anomalies, suspicious content, and malformed files.
"""
import os
import struct
import unittest

from scanner.analyzer.gguf_scanner import (
    analyze_gguf_file,
    is_gguf_file,
)

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "binary")


def _load_fixture(name: str) -> bytes:
    path = os.path.join(FIXTURES_DIR, name)
    with open(path, "rb") as f:
        return f.read()


def _write_gguf_string_bytes(s: str) -> bytes:
    encoded = s.encode("utf-8")
    return struct.pack("<Q", len(encoded)) + encoded


class TestGGUFFileDetection(unittest.TestCase):
    def test_extension_detection(self):
        self.assertTrue(is_gguf_file("model.gguf"))
        self.assertTrue(is_gguf_file("model.GGUF"))
        self.assertFalse(is_gguf_file("model.pt"))
        self.assertFalse(is_gguf_file("model.safetensors"))


class TestGGUFSafeFile(unittest.TestCase):
    def test_clean_gguf_no_findings(self):
        """A well-formed GGUF with standard metadata should be clean."""
        data = _load_fixture("safe_model.gguf")
        findings = analyze_gguf_file("safe.gguf", data)
        suspicious = [f for f in findings if f.rule_id in ("HFS-056", "HFS-057")]
        self.assertEqual(len(suspicious), 0,
                         f"Clean GGUF should not trigger findings, got: "
                         f"{[(f.rule_id, f.evidence) for f in suspicious]}")


class TestGGUFMaliciousMetadata(unittest.TestCase):
    def test_shell_command_in_metadata(self):
        """Detect shell commands in GGUF metadata."""
        data = _load_fixture("malicious_metadata.gguf")
        findings = analyze_gguf_file("evil.gguf", data)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("HFS-056", rule_ids,
                      "Should detect curl|bash pattern in metadata")

    def test_url_in_non_standard_key(self):
        """Detect URLs in custom metadata keys."""
        # Build GGUF with URL in non-standard key
        buf = bytearray()
        buf.extend(struct.pack("<I", 0x46475547))  # GGUF magic
        buf.extend(struct.pack("<I", 3))  # version
        buf.extend(struct.pack("<Q", 0))  # 0 tensors
        buf.extend(struct.pack("<Q", 1))  # 1 kv

        buf.extend(_write_gguf_string_bytes("custom.callback_url"))
        buf.extend(struct.pack("<I", 8))  # type STRING
        buf.extend(_write_gguf_string_bytes("https://malware-staging.xyz/payload"))

        findings = analyze_gguf_file("test.gguf", bytes(buf))
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("HFS-056", rule_ids)


class TestGGUFMalformed(unittest.TestCase):
    def test_wrong_magic(self):
        """Invalid magic number should be detected."""
        data = _load_fixture("malformed.gguf")
        findings = analyze_gguf_file("bad.gguf", data)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("HFS-058", rule_ids,
                      "Should detect invalid GGUF magic number")

    def test_too_small(self):
        """File smaller than minimum header should be invalid."""
        findings = analyze_gguf_file("tiny.gguf", b"\x00" * 10)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("HFS-058", rule_ids)

    def test_unsupported_version(self):
        """Version 99 should be flagged."""
        buf = struct.pack("<I", 0x46475547) + struct.pack("<I", 99) + b"\x00" * 16
        findings = analyze_gguf_file("v99.gguf", buf)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("HFS-058", rule_ids)


class TestGGUFOversizedMetadata(unittest.TestCase):
    def test_oversized_string_value(self):
        """Detect excessively large metadata values."""
        buf = bytearray()
        buf.extend(struct.pack("<I", 0x46475547))
        buf.extend(struct.pack("<I", 3))
        buf.extend(struct.pack("<Q", 0))
        buf.extend(struct.pack("<Q", 1))

        buf.extend(_write_gguf_string_bytes("custom.payload"))
        buf.extend(struct.pack("<I", 8))  # type STRING
        big_value = "X" * 60_000
        buf.extend(_write_gguf_string_bytes(big_value))

        findings = analyze_gguf_file("big.gguf", bytes(buf))
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("HFS-057", rule_ids,
                      "Should detect oversized metadata value")


if __name__ == "__main__":
    unittest.main()
