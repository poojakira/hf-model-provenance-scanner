from types import SimpleNamespace

from scanner.analyzer import sandbox_executor
from scanner.analyzer.sandbox_executor import sandbox_execute


def test_runtime_instrumentation_intercepts_os_file_operations():
    source = """
import os
print('cwd', os.getcwd())
os.listdir('.')
os.remove('should_not_exist.txt')
"""
    findings = sandbox_execute("payload.py", source)
    evidence = "\n".join(f.evidence for f in findings)

    assert "os.listdir" in evidence
    assert "os.remove" in evidence


def test_runtime_instrumentation_keeps_bare_os_import_quiet():
    findings = sandbox_execute("payload.py", "import os\nprint(os.name)\n")

    assert findings == []


def test_runtime_instrumentation_executes_target_in_separate_globals(monkeypatch):
    captured = {}

    def fake_run(cmd, capture_output, text, timeout, env, cwd):
        with open(cmd[-1], encoding="utf-8") as handle:
            captured["script"] = handle.read()
        return SimpleNamespace(stdout="[]", stderr="", returncode=0)

    monkeypatch.setattr(sandbox_executor.subprocess, "run", fake_run)
    sandbox_executor._sandbox_single_run(
        "payload.py", "_safe_os.listdir('.')", {"PATH": ""}
    )

    script = captured["script"]
    assert "_USER_GLOBALS" in script
    assert "_re(_code, _USER_GLOBALS, _USER_GLOBALS)" in script
