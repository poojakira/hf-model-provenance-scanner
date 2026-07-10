"""
Sandbox Execution Engine — Run untrusted code in a restricted subprocess.
Instruments code to capture dangerous operations without allowing them.
"""

import json
import os
import subprocess
import sys
import tempfile
import textwrap
from typing import Optional

from scanner.models import Finding
from scanner.rules.definitions import get_rule

SANDBOX_TIMEOUT = 5
MAX_OUTPUT = 65536


def _make_finding(rule_id: str, file_path: str, line: int, evidence: str) -> Finding:
    rule = get_rule(rule_id)
    return Finding(rule_id, rule.severity, file_path, line, 0,
                   rule.description, evidence[:300], rule.remediation, rule.cwe)


HARNESS = textwrap.dedent('''
import sys, json
_F = []
_BM = {"os","subprocess","shutil","ctypes","socket","webbrowser","urllib","http"}
class _M:
    def __init__(s,n): s._n=n
    def __getattr__(s,a):
        _F.append({"op":"attr","module":s._n,"attr":a})
        return lambda *a,**k: None
    def __call__(s,*a,**k): return None
class _IH:
    def find_module(s,n,p=None):
        if n.split(".")[0] in _BM: return s
    def load_module(s,n):
        _F.append({"op":"import","module":n})
        m=_M(n); sys.modules[n]=m; return m
sys.meta_path.insert(0,_IH())
import builtins as _b
_re,_rv,_rc=exec,eval,compile
def _he(c,*a,**k): _F.append({"op":"exec","code":str(c)[:500]})
def _hv(c,*a,**k): _F.append({"op":"eval","code":str(c)[:500]}); return None
def _hc(s,*a,**k): _F.append({"op":"compile","source":str(s)[:500]}); return _rc("pass","<s>","exec")
_b.exec=_he; _b.eval=_hv; _b.compile=_hc
_b.open=lambda *a,**k: (_ for _ in ()).throw(PermissionError("sandbox"))
''')

FOOTER = '\nimport sys,json\nsys.stdout.write(json.dumps(_F))\n'


def sandbox_execute(file_path: str, source: str) -> list[Finding]:
    """Execute code in sandboxed subprocess, return findings for dangerous ops."""
    findings: list[Finding] = []
    instrumented = HARNESS + "\n" + source + "\n" + FOOTER

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
        f.write(instrumented)
        tmp = f.name

    try:
        result = subprocess.run(
            [sys.executable, "-S", "-u", tmp],
            capture_output=True, text=True, timeout=SANDBOX_TIMEOUT,
            env={"PATH": "", "HOME": "/tmp", "PYTHONDONTWRITEBYTECODE": "1"})
        stdout = result.stdout[:MAX_OUTPUT]
        if stdout:
            try:
                ops = json.loads(stdout)
                findings.extend(_interpret(file_path, ops))
            except json.JSONDecodeError:
                pass
        if result.returncode < 0:
            findings.append(_make_finding("HFS-072", file_path, 0,
                                          f"Process killed by signal {-result.returncode}"))
    except subprocess.TimeoutExpired:
        findings.append(_make_finding("HFS-072", file_path, 0,
                                      f"Sandbox timed out after {SANDBOX_TIMEOUT}s"))
    except OSError:
        pass
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    return findings


def _interpret(file_path: str, ops: list) -> list[Finding]:
    findings: list[Finding] = []
    seen = set()
    for entry in ops:
        if not isinstance(entry, dict):
            continue
        op = entry.get("op", "")
        key = (op, entry.get("module", ""), entry.get("code", "")[:30])
        if key in seen:
            continue
        seen.add(key)
        if op == "exec":
            findings.append(_make_finding("HFS-072", file_path, 0,
                                          f"Sandbox: exec() with: {entry.get('code','')}"))
        elif op == "eval":
            findings.append(_make_finding("HFS-072", file_path, 0,
                                          f"Sandbox: eval() with: {entry.get('code','')}"))
        elif op == "import":
            findings.append(_make_finding("HFS-072", file_path, 0,
                                          f"Sandbox: blocked import '{entry.get('module','')}'"))
        elif op == "attr":
            attr = entry.get("attr", "")
            if attr in ("system", "popen", "Popen", "run", "call"):
                findings.append(_make_finding("HFS-072", file_path, 0,
                                              f"Sandbox: {entry.get('module','')}.{attr}()"))
    return findings
