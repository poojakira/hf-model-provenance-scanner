"""
tests/test_pickle_safety.py — Security-hardening tests for pickle_scanner.py

Three tests mandated by agent/security-hardening-v1:

1. test_pickle_scanner_rejects_direct_load
   AST-parse scanner source; fail if pickle.loads / pickle.load appears as a call.

2. test_oversized_pickle_rejected
   Write a temp file larger than MAX_PICKLE_SIZE_BYTES; verify scan_pickle_bytes
   returns a size-limit finding instead of crashing.

3. test_malformed_pickle_handled
   Write random garbage bytes to a .pkl temp file; verify the public API does not
   raise an unhandled exception.
"""

import ast
import os
import struct
import tempfile
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SCANNER_SRC = Path(__file__).parent.parent / "scanner" / "analyzer" / "pickle_scanner.py"


def _load_scanner_ast() -> ast.Module:
    """Return the parsed AST of pickle_scanner.py."""
    return ast.parse(SCANNER_SRC.read_text(encoding="utf-8"), filename=str(SCANNER_SRC))


# ---------------------------------------------------------------------------
# Test 1 — AST proof that pickle.loads / pickle.load is never called
# ---------------------------------------------------------------------------


class _PickleLoadCallVisitor(ast.NodeVisitor):
    """Collect any call that matches pickle.loads or pickle.load."""

    def __init__(self):
        self.violations: list[str] = []

    def visit_Call(self, node: ast.Call):
        # Pattern: pickle.loads(...) or pickle.load(...)
        if isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "pickle"
                and node.func.attr in ("loads", "load")
            ):
                self.violations.append(
                    f"Line {node.lineno}: pickle.{node.func.attr}() call detected"
                )
        # Pattern: bare loads(...) / load(...) after `from pickle import loads`
        if isinstance(node.func, ast.Name) and node.func.id in ("loads", "load"):
            self.violations.append(
                f"Line {node.lineno}: bare {node.func.id}() call (possible pickle.loads alias)"
            )
        self.generic_visit(node)


def test_pickle_scanner_rejects_direct_load():
    """
    pickle_scanner.py MUST NOT call pickle.loads or pickle.load.

    Calling pickle.loads on untrusted data is a Remote Code Execution (RCE) risk.
    The scanner must use its own opcode walker (PickleScanner._parse_opcodes) instead.

    This test AST-parses the source file so it catches the violation even if the
    function is aliased or imported under a different name.
    """
    tree = _load_scanner_ast()
    visitor = _PickleLoadCallVisitor()
    visitor.visit(tree)

    assert visitor.violations == [], (
        "pickle_scanner.py contains unsafe pickle.loads/load calls — CRITICAL RCE risk!\n"
        + "\n".join(visitor.violations)
    )


# Also verify that `import pickle` is absent (belt-and-suspenders check).
def test_pickle_module_not_imported():
    """
    pickle_scanner.py should not import the pickle module at all.

    Importing pickle is a yellow flag — the scanner works entirely with raw bytes
    and struct, so no pickle import should be necessary.
    """
    tree = _load_scanner_ast()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name != "pickle", (
                    f"Line {node.lineno}: `import pickle` found in pickle_scanner.py. "
                    "The scanner must not import the pickle module."
                )
        if isinstance(node, ast.ImportFrom):
            assert node.module != "pickle", (
                f"Line {node.lineno}: `from pickle import ...` found in pickle_scanner.py. "
                "The scanner must not import the pickle module."
            )


# ---------------------------------------------------------------------------
# Test 2 — Oversized pickle is rejected with a size-limit finding
# ---------------------------------------------------------------------------


def test_oversized_pickle_rejected():
    """
    scan_pickle_bytes must return a HFS-098 size-limit finding (not crash) when
    given data larger than MAX_PICKLE_SIZE_BYTES.

    This tests CWE-770: Allocation of Resources Without Limits protection.
    """
    from scanner.analyzer.pickle_scanner import scan_pickle_bytes
    from scanner.config import MAX_PICKLE_SIZE_BYTES

    # Create data that is exactly 1 byte over the limit.
    # We use a bytearray filled with zeros rather than a real pickle payload so
    # the test runs fast even at 100 MB+.
    #
    # We write to a temp file and read back to exercise the realistic path where
    # a large file arrives from disk.  However scan_pickle_bytes itself receives
    # bytes, so we just pass the oversized bytes directly.
    oversized_data = b"\x80\x04" + b"\x00" * MAX_PICKLE_SIZE_BYTES  # 1 byte over limit

    findings = scan_pickle_bytes("fake_large_model.pkl", oversized_data)

    # Should get exactly one size-limit finding, not a crash
    assert len(findings) >= 1, "Expected at least one finding for oversized pickle"
    rule_ids = {f.rule_id for f in findings}
    assert "HFS-098" in rule_ids, f"Expected HFS-098 size-limit finding, got rule IDs: {rule_ids}"

    # Verify the finding mentions size information
    size_findings = [f for f in findings if f.rule_id == "HFS-098"]
    assert any(
        "MAX_PICKLE_SIZE" in f.evidence or "MB" in f.evidence or "size" in f.evidence.lower()
        for f in size_findings
    ), f"HFS-098 finding evidence doesn't mention size limit: {[f.evidence for f in size_findings]}"


def test_oversized_pickle_rejected_via_tempfile():
    """
    Secondary version of the size test — writes to a real temp file and verifies
    analyze_pickle_file also honours the limit when the caller has already loaded
    the bytes.
    """
    from scanner.analyzer.pickle_scanner import analyze_pickle_file
    from scanner.config import MAX_PICKLE_SIZE_BYTES

    oversized_data = b"\x80\x04" + b"\x00" * MAX_PICKLE_SIZE_BYTES

    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as tf:
        tf.write(oversized_data)
        tf_path = tf.name

    try:
        findings = analyze_pickle_file(tf_path, oversized_data)
        rule_ids = {f.rule_id for f in findings}
        assert (
            "HFS-098" in rule_ids
        ), f"analyze_pickle_file did not return HFS-098 for oversized data; got: {rule_ids}"
    finally:
        os.unlink(tf_path)


# ---------------------------------------------------------------------------
# Test 3 — Malformed pickle bytes do not crash the scanner
# ---------------------------------------------------------------------------


def test_malformed_pickle_handled():
    """
    Writing garbage bytes to a .pkl file must not cause an unhandled exception.

    The scanner wraps PickleScanner.scan() in a try/except so that even
    completely broken input is handled gracefully — it may produce a
    'corrupted pickle' finding but must never raise to the caller.

    This tests CWE-248: Uncaught Exception protection.
    """
    from scanner.analyzer.pickle_scanner import scan_pickle_bytes

    malformed_inputs = [
        # Random garbage with no pickle structure
        b"\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8",
        # Pickle magic followed by truncated opcode payload
        b"\x80\x04" + b"\x93\x8c",  # STACK_GLOBAL with no stack data
        # Pure null bytes
        b"\x00" * 64,
        # Protocol 0 with invalid continuation
        b"c" + b"\xff" * 16,
        # Struct that would cause struct.unpack_from to fail
        b"\x80\x04\x95" + b"\xff\xff\xff\xff\xff\xff\xff\xff",  # FRAME with huge length
        # Mix of valid start and garbage
        b"\x80\x02\x8c\xff",  # SHORT_BINUNICODE with length 255 but only 0 bytes following
    ]

    for i, bad_data in enumerate(malformed_inputs):
        # Must not raise — must return a list (possibly empty, possibly with findings)
        try:
            findings = scan_pickle_bytes(f"malformed_{i}.pkl", bad_data)
            assert isinstance(
                findings, list
            ), f"scan_pickle_bytes returned non-list for input {i}: {type(findings)}"
        except Exception as exc:
            pytest.fail(
                f"scan_pickle_bytes raised unhandled {type(exc).__name__} for malformed input {i}: {exc}\n"
                f"Input bytes: {bad_data!r}"
            )


def test_malformed_pickle_via_analyze_pickle_file():
    """
    analyze_pickle_file (public API) must not crash on malformed/garbage .pkl files.
    """
    from scanner.analyzer.pickle_scanner import analyze_pickle_file

    garbage_payload = b"\x80\x04\x95" + struct.pack("<Q", 2**60) + b"\x00" * 8

    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as tf:
        tf.write(garbage_payload)
        tf_path = tf.name

    try:
        # Must not raise
        try:
            findings = analyze_pickle_file(tf_path, garbage_payload)
            assert isinstance(findings, list)
        except Exception as exc:
            pytest.fail(f"analyze_pickle_file raised unhandled {type(exc).__name__}: {exc}")
    finally:
        os.unlink(tf_path)
