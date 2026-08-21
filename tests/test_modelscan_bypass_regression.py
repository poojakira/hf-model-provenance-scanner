"""
Regression tests for denylist-bypass pickle payloads.

These payloads use stdlib modules that reach code execution through indirect
paths. Verified on 2026-08-08 that Protect AI ModelScan 0.8.8 MISSES timeit
and importlib (total_issues=0), while this scanner flags them CRITICAL.

If any of these regress to "not detected", we have lost a real competitive
edge  --  treat a failure here as a security regression, not a flaky test.
"""

import pickle  # noqa: S403

from scanner.analyzer.pickle_scanner import analyze_pickle_file


def _detected(obj) -> tuple[bool, list[str]]:
    """Pickle an object (without running __init__) and scan the bytes."""
    inst = obj.__class__.__new__(obj.__class__)
    data = pickle.dumps(inst)
    findings = analyze_pickle_file("regression.pkl", data)
    high = [f.rule_id for f in findings if f.severity.value in ("critical", "high")]
    return bool(high), high


class _Timeit:
    """timeit.timeit executes an arbitrary code string via its stmt arg.

    Uses a memoized module name (BINGET reuse) that defeats naive
    stack-global reconstruction. ModelScan 0.8.8 misses this.
    """

    def __reduce__(self):
        import timeit

        return (timeit.timeit, ("__import__('os').system('id')",))


class _ImportlibOs:
    """importlib.import_module('os') is a gadget-chain building block.

    ModelScan 0.8.8 does not flag importlib; this scanner does.
    """

    def __reduce__(self):
        import importlib

        return (importlib.import_module, ("os",))


class _RunpyRunPath:
    """runpy.run_path executes arbitrary Python from a file path."""

    def __reduce__(self):
        import runpy

        return (runpy.run_path, ("/tmp/payload.py",))


class _BdbRun:
    """bdb.Bdb().run executes a code string in the debugger."""

    def __reduce__(self):
        import bdb

        return (bdb.Bdb().run, ("__import__('os').system('id')",))


class TestDenylistBypassDetection:
    """Each payload must be flagged high/critical (ModelScan misses some)."""

    def test_timeit_stmt_execution(self):
        detected, rules = _detected(_Timeit())
        assert detected, f"timeit.timeit bypass not detected (rules={rules})"

    def test_importlib_indirect_import(self):
        detected, rules = _detected(_ImportlibOs())
        assert detected, f"importlib.import_module bypass not detected (rules={rules})"

    def test_runpy_run_path(self):
        detected, rules = _detected(_RunpyRunPath())
        assert detected, f"runpy.run_path bypass not detected (rules={rules})"

    def test_bdb_debugger_execution(self):
        detected, rules = _detected(_BdbRun())
        assert detected, f"bdb.Bdb().run bypass not detected (rules={rules})"


class TestLegitimateModelsNotFlagged:
    """Legitimate structures must NOT be flagged (precision guard)."""

    def test_ordered_dict_state_dict(self):
        from collections import OrderedDict

        sd = OrderedDict([("layer.weight", [1.0, 2.0]), ("layer.bias", [0.1])])
        data = pickle.dumps(sd)
        findings = analyze_pickle_file("legit.pkl", data)
        high = [f for f in findings if f.severity.value in ("critical", "high")]
        assert not high, f"false positive on OrderedDict state_dict: {[f.rule_id for f in high]}"

    def test_plain_config_dict(self):
        cfg = {"arch": "transformer", "layers": 6, "dims": (512, 512)}
        data = pickle.dumps(cfg)
        findings = analyze_pickle_file("cfg.pkl", data)
        high = [f for f in findings if f.severity.value in ("critical", "high")]
        assert not high, f"false positive on config dict: {[f.rule_id for f in high]}"
