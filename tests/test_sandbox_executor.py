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