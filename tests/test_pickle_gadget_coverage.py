"""Regression tests for expanded pickle RCE-gadget coverage.

Added after a real-data benchmark against the picklescan corpus showed the
original scanner detected only ~26% of malicious pickles (finite blocklist,
CRLF-evasion bug, and dead ZIP-unpacking path). These tests lock in:
  * CRLF-terminated protocol-0 globals are still detected (evasion fix)
  * long-tail RCE gadgets (idlelib / profile / torch.* / pydoc / lib2to3 …)
  * ZIP-wrapped pickle payloads
  * legitimate torch/numpy reconstruction globals stay clean (no false positive)
"""
import io
import zipfile
import unittest

from scanner.analyzer.pickle_scanner import scan_pickle_bytes, is_pickle_file


def _pickle_with_global(module: str, name: str, newline: bytes = b"\n") -> bytes:
    """Build a minimal protocol-0 pickle that imports module.name via GLOBAL."""
    return b"c" + module.encode() + newline + name.encode() + newline + b"(t\x52."


class TestCRLFEvasion(unittest.TestCase):
    def test_lf_eval_detected(self):
        findings = scan_pickle_bytes("m.pkl", _pickle_with_global("builtins", "eval"))
        self.assertIn("HFS-050", [f.rule_id for f in findings])

    def test_crlf_eval_detected(self):
        # CRLF line endings must not evade detection
        findings = scan_pickle_bytes("m.pkl", _pickle_with_global("builtins", "eval", b"\r\n"))
        self.assertIn("HFS-050", [f.rule_id for f in findings],
                      "CRLF-terminated globals must still be detected")


class TestGadgetCoverage(unittest.TestCase):
    GADGETS = [
        ("idlelib.pyshell", "ModifiedInterpreter.runcode"),
        ("profile", "Profile.run"),
        ("cProfile", "run"),
        ("trace", "Trace.run"),
        ("pydoc", "locate"),
        ("lib2to3.pgen2.grammar", "Grammar.loads"),
        ("pty", "spawn"),
        ("torch.utils.collect_env", "run"),
        ("torch.utils.bottleneck.__main__", "run_cprofile"),
        ("operator", "methodcaller"),
        ("timeit", "timeit"),
        ("requests.api", "get"),
    ]

    def test_gadgets_detected(self):
        for module, name in self.GADGETS:
            data = _pickle_with_global(module, name)
            rule_ids = [f.rule_id for f in scan_pickle_bytes("m.pkl", data)]
            self.assertIn("HFS-050", rule_ids, f"gadget {module}.{name} not detected")


class TestZipWrappedPayload(unittest.TestCase):
    def test_zip_pickle_detected(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("archive/data.pkl", _pickle_with_global("os", "system"))
        findings = scan_pickle_bytes("model.zip", buf.getvalue())
        self.assertIn("HFS-050", [f.rule_id for f in findings],
                      "ZIP-wrapped malicious pickle must be detected")

    def test_zip_extension_scanned(self):
        import tempfile
        import os
        # Create a temporary ZIP file to test the extension detection
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            with zipfile.ZipFile(tmp, "w") as zf:
                zf.writestr("data.pkl", _pickle_with_global("os", "system"))
            tmp_path = tmp.name
        try:
            self.assertTrue(is_pickle_file(tmp_path))
        finally:
            os.unlink(tmp_path)


class TestNoFalsePositiveOnSafeGlobals(unittest.TestCase):
    SAFE = [
        ("torch._utils", "_rebuild_tensor_v2"),
        ("collections", "OrderedDict"),
        ("numpy.core.multiarray", "_reconstruct"),
        ("torch", "FloatStorage"),
    ]

    def test_safe_globals_not_flagged(self):
        for module, name in self.SAFE:
            data = _pickle_with_global(module, name)
            criticals = [f for f in scan_pickle_bytes("m.pkl", data)
                         if f.rule_id == "HFS-050"]
            self.assertEqual(criticals, [], f"safe global {module}.{name} wrongly flagged")


if __name__ == "__main__":
    unittest.main()
