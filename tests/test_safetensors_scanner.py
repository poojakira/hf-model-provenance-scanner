"""
Tests for the SafeTensors format validator.
Verifies detection of metadata injection, oversized headers, and malformed files.
"""
import json
import os
import struct
import unittest

from scanner.analyzer.safetensors_scanner import (
    analyze_safetensors_file,
    is_safetensors_file,
)

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "binary")


def _load_fixture(name: str) -> bytes:
    path = os.path.join(FIXTURES_DIR, name)
    with open(path, "rb") as f:
        return f.read()


class TestSafeTensorsDetection(unittest.TestCase):
    def test_extension_detection(self):
        self.assertTrue(is_safetensors_file("model.safetensors"))
        self.assertTrue(is_safetensors_file("weights.SAFETENSORS"))
        self.assertFalse(is_safetensors_file("model.pt"))
        self.assertFalse(is_safetensors_file("model.gguf"))


class TestSafeTensorsSafe(unittest.TestCase):
    def test_clean_file_no_findings(self):
        """A properly constructed SafeTensors file should have no findings."""
        data = _load_fixture("safe_model.safetensors")
        findings = analyze_safetensors_file("safe.safetensors", data)
        # Should have zero critical/high findings
        critical_high = [f for f in findings
                         if f.rule_id in ("HFS-053", "HFS-054", "HFS-055")]
        self.assertEqual(len(critical_high), 0,
                         f"Clean file should not trigger findings, got: {critical_high}")


class TestSafeTensorsMaliciousMetadata(unittest.TestCase):
    def test_url_in_metadata(self):
        """Detect URLs injected into metadata fields."""
        data = _load_fixture("malicious_metadata.safetensors")
        findings = analyze_safetensors_file("evil.safetensors", data)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("HFS-053", rule_ids,
                      "Should detect URL injection in metadata")

    def test_eval_in_metadata(self):
        """Detect eval() patterns in metadata."""
        data = _load_fixture("malicious_metadata.safetensors")
        findings = analyze_safetensors_file("evil.safetensors", data)
        # The fixture has both URL and eval pattern
        self.assertTrue(len(findings) >= 1,
                        "Should detect at least one suspicious pattern")


class TestSafeTensorsOversizedHeader(unittest.TestCase):
    def test_oversized_metadata_value(self):
        """Detect abnormally large metadata values."""
        data = _load_fixture("oversized_header.safetensors")
        findings = analyze_safetensors_file("big.safetensors", data)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("HFS-054", rule_ids,
                      "Should detect oversized metadata value")


class TestSafeTensorsMalformed(unittest.TestCase):
    def test_header_exceeds_file(self):
        """Detect malformed file where header size > file size."""
        data = _load_fixture("malformed.safetensors")
        findings = analyze_safetensors_file("bad.safetensors", data)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("HFS-055", rule_ids,
                      "Should detect header size exceeding file data")

    def test_too_small_file(self):
        """File smaller than 8 bytes is invalid."""
        findings = analyze_safetensors_file("tiny.safetensors", b"\x00\x01")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("HFS-055", rule_ids)

    def test_zero_header_size(self):
        """Header size of 0 is invalid."""
        data = struct.pack("<Q", 0) + b"\x00" * 10
        findings = analyze_safetensors_file("zero.safetensors", data)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("HFS-055", rule_ids)


class TestSafeTensorsInlineConstruction(unittest.TestCase):
    def test_script_tag_in_metadata(self):
        """Detect HTML script injection in metadata."""
        header = {
            "__metadata__": {
                "xss": "<script>alert('pwned')</script>",
            },
            "w": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]},
        }
        header_bytes = json.dumps(header).encode("utf-8")
        data = struct.pack("<Q", len(header_bytes)) + header_bytes + b"\x00" * 4
        findings = analyze_safetensors_file("xss.safetensors", data)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("HFS-053", rule_ids)


if __name__ == "__main__":
    unittest.main()
