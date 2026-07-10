"""
Tests for weight fingerprinting module.
Verifies SafeTensors fingerprinting, comparison, and modification detection.
"""
import json
import struct
import unittest

from scanner.analyzer.weight_fingerprint import (
    ModelFingerprint,
    TensorFingerprint,
    compare_fingerprints,
    fingerprint_file,
    fingerprint_safetensors,
)


def _create_safetensors(tensors: dict[str, bytes], metadata: dict = None) -> bytes:
    """Helper: build a minimal SafeTensors file from tensor data."""
    header = {}
    if metadata:
        header["__metadata__"] = metadata

    offset = 0
    for name, data in tensors.items():
        size = len(data)
        # Assume F32, shape inferred from byte count
        num_elements = size // 4
        header[name] = {
            "dtype": "F32",
            "shape": [num_elements],
            "data_offsets": [offset, offset + size],
        }
        offset += size

    header_bytes = json.dumps(header).encode("utf-8")
    header_size = struct.pack("<Q", len(header_bytes))
    tensor_data = b"".join(tensors.values())
    return header_size + header_bytes + tensor_data


class TestSafeTensorsFingerprint(unittest.TestCase):
    def test_basic_fingerprint(self):
        """Generate fingerprint for a simple SafeTensors file."""
        tensor_data = b"\x01\x02\x03\x04" * 4  # 16 bytes = 4 floats
        file_data = _create_safetensors({"weight": tensor_data})

        fp, findings = fingerprint_safetensors("model.safetensors", file_data)
        self.assertIsNotNone(fp)
        self.assertEqual(fp.format, "safetensors")
        self.assertEqual(fp.tensor_count, 1)
        self.assertEqual(fp.total_params, 4)
        self.assertTrue(len(fp.file_hash) == 64)
        self.assertTrue(len(fp.aggregate_hash) == 64)
        self.assertEqual(len(fp.tensors), 1)
        self.assertEqual(fp.tensors[0].name, "weight")

    def test_multiple_tensors(self):
        """Fingerprint with multiple tensors."""
        file_data = _create_safetensors({
            "layer1.weight": b"\x00" * 64,
            "layer1.bias": b"\x01" * 16,
            "layer2.weight": b"\x02" * 64,
        })
        fp, _ = fingerprint_safetensors("model.safetensors", file_data)
        self.assertEqual(fp.tensor_count, 3)
        self.assertEqual(fp.total_params, 16 + 4 + 16)  # 64/4 + 16/4 + 64/4

    def test_deterministic_hash(self):
        """Same file should produce same fingerprint."""
        data = _create_safetensors({"w": b"\x42" * 32})
        fp1, _ = fingerprint_safetensors("a.safetensors", data)
        fp2, _ = fingerprint_safetensors("b.safetensors", data)
        self.assertEqual(fp1.aggregate_hash, fp2.aggregate_hash)
        self.assertEqual(fp1.file_hash, fp2.file_hash)


class TestFingerprintComparison(unittest.TestCase):
    def test_identical_fingerprints_no_findings(self):
        """Identical fingerprints produce no findings."""
        data = _create_safetensors({"w": b"\x00" * 16})
        fp1, _ = fingerprint_safetensors("model.safetensors", data)
        fp2, _ = fingerprint_safetensors("model.safetensors", data)
        findings = compare_fingerprints(fp1, fp2, "model.safetensors")
        self.assertEqual(len(findings), 0)

    def test_modified_tensor_detected(self):
        """Changed tensor data should be detected."""
        data1 = _create_safetensors({"w": b"\x00" * 16})
        data2 = _create_safetensors({"w": b"\xff" * 16})
        fp1, _ = fingerprint_safetensors("model.safetensors", data1)
        fp2, _ = fingerprint_safetensors("model.safetensors", data2)
        findings = compare_fingerprints(fp1, fp2, "model.safetensors")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("HFS-060", rule_ids,
                      "Should detect tensor modification")

    def test_added_tensor_detected(self):
        """New tensor in current version should be detected."""
        data1 = _create_safetensors({"w": b"\x00" * 16})
        data2 = _create_safetensors({"w": b"\x00" * 16, "backdoor": b"\xff" * 16})
        fp1, _ = fingerprint_safetensors("model.safetensors", data1)
        fp2, _ = fingerprint_safetensors("model.safetensors", data2)
        findings = compare_fingerprints(fp1, fp2, "model.safetensors")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("HFS-060", rule_ids,
                      "Should detect new tensor added")

    def test_removed_tensor_detected(self):
        """Removed tensor should be detected."""
        data1 = _create_safetensors({"w": b"\x00" * 16, "bias": b"\x01" * 8})
        data2 = _create_safetensors({"w": b"\x00" * 16})
        fp1, _ = fingerprint_safetensors("model.safetensors", data1)
        fp2, _ = fingerprint_safetensors("model.safetensors", data2)
        findings = compare_fingerprints(fp1, fp2, "model.safetensors")
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("HFS-060", rule_ids,
                      "Should detect tensor removal")

    def test_tensor_count_change(self):
        """Different tensor counts should be flagged."""
        data1 = _create_safetensors({"a": b"\x00" * 4, "b": b"\x00" * 4})
        data2 = _create_safetensors({"a": b"\x00" * 4})
        fp1, _ = fingerprint_safetensors("m.safetensors", data1)
        fp2, _ = fingerprint_safetensors("m.safetensors", data2)
        findings = compare_fingerprints(fp1, fp2, "m.safetensors")
        self.assertTrue(len(findings) > 0)


class TestFingerprintFileRouter(unittest.TestCase):
    def test_safetensors_routed(self):
        """SafeTensors files should be fingerprinted."""
        data = _create_safetensors({"w": b"\x00" * 8})
        fp, _ = fingerprint_file("model.safetensors", data)
        self.assertEqual(fp.format, "safetensors")

    def test_unknown_format(self):
        """Unknown formats get file-level hash only."""
        fp, _ = fingerprint_file("model.xyz", b"hello world")
        self.assertEqual(fp.format, "unknown")
        self.assertTrue(len(fp.file_hash) == 64)


class TestModelFingerprintSerialization(unittest.TestCase):
    def test_to_dict(self):
        """Fingerprint should serialize to dict cleanly."""
        fp = ModelFingerprint(
            file_path="test.safetensors",
            file_hash="a" * 64,
            format="safetensors",
            tensor_count=1,
            total_params=100,
            tensors=[TensorFingerprint("w", "F32", [100], "b" * 64, 400)],
            metadata_hash="c" * 64,
            aggregate_hash="d" * 64,
        )
        d = fp.to_dict()
        self.assertEqual(d["file_path"], "test.safetensors")
        self.assertEqual(d["tensor_count"], 1)
        self.assertEqual(len(d["tensors"]), 1)
        self.assertEqual(d["tensors"][0]["name"], "w")


if __name__ == "__main__":
    unittest.main()
