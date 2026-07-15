"""
Runtime Instrumentation Engine — observe selected untrusted code paths in a subprocess.
Instruments imports and dangerous builtins to capture operations without claiming OS-level containment.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap

from scanner.models import Finding
from scanner.rules.definitions import get_rule

SANDBOX_TIMEOUT = int(os.environ.get("HF_SCANNER_SANDBOX_TIMEOUT", "30"))
MAX_OUTPUT = 65536

# Environment configurations to test against (catches gated payloads)
SANDBOX_ENV_CONFIGS = [
    # Default: minimal environment
    {"PATH": "", "HOME": "/tmp", "PYTHONDONTWRITEBYTECODE": "1"},
    # Windows-like: triggers platform.system() == "Windows" gates
    {
        "PATH": "",
        "HOME": "/tmp",
        "PYTHONDONTWRITEBYTECODE": "1",
        "OS": "Windows_NT",
        "SYSTEMROOT": "C:\\Windows",
        "COMSPEC": "cmd.exe",
    },
    # CI environment: triggers CI-detection gates
    {
        "PATH": "",
        "HOME": "/tmp",
        "PYTHONDONTWRITEBYTECODE": "1",
        "CI": "true",
        "GITHUB_ACTIONS": "true",
        "GITLAB_CI": "true",
    },
]


def _make_finding(rule_id: str, file_path: str, line: int, evidence: str) -> Finding:
    rule = get_rule(rule_id)
    return Finding(
        rule_id,
        rule.severity,
        file_path,
        line,
        0,
        rule.description,
        evidence[:300],
        rule.remediation,
        rule.cwe,
    )


HARNESS = textwrap.dedent("""
import sys, json
_F = []
import os as _safe_os
import os.path as _safe_path
_BM = {"os","subprocess","shutil","ctypes","socket","webbrowser","urllib","http"}
class _M:
    def __init__(s,n): s._n=n
    def __getattr__(s,a):
        if s._n == "os" and a in ("environ", "path", "getcwd", "sep", "linesep",
                                   "name", "devnull", "getpid", "getenv"):
            if a == "environ": return _safe_os.environ
            if a == "path": return _safe_path
            if a == "getenv": return _safe_os.getenv
            return getattr(_safe_os, a, None)
        _F.append({"op":"attr","module":s._n,"attr":a})
        return lambda *a,**k: None
    def __call__(s,*a,**k): return None
import importlib.util as _ilu
class _IH:
    def find_spec(s,n,path=None,target=None):
        if n.split(".")[0] in _BM:
            return _ilu.spec_from_loader(n, s)
        return None
    def create_module(s,spec):
        _F.append({"op":"import","module":spec.name})
        m=_M(spec.name); sys.modules[spec.name]=m; return m
    def exec_module(s,module):
        pass
sys.meta_path.insert(0,_IH())
import builtins as _b
_real_import = _b.__import__
def _hi(n, globals=None, locals=None, fromlist=(), level=0):
    top = n.split(".")[0]
    if top in _BM:
        _F.append({"op":"import","module":n})
        return _M(n)
    return _real_import(n, globals, locals, fromlist, level)
_b.__import__ = _hi
_re,_rv,_rc=exec,eval,compile
def _he(c,*a,**k): _F.append({"op":"exec","code":str(c)[:500]})
def _hv(c,*a,**k): _F.append({"op":"eval","code":str(c)[:500]}); return None
def _hc(s,*a,**k): _F.append({"op":"compile","source":str(s)[:500]}); return _rc("pass","<s>","exec")
_b.exec=_he; _b.eval=_hv; _b.compile=_hc
_b.open=lambda *a,**k: (_ for _ in ()).throw(PermissionError("sandbox"))
""")

FOOTER = "\nimport sys,json\nsys.stdout.write(json.dumps(_F))\n"


def sandbox_execute(file_path: str, source: str) -> list[Finding]:
    """Execute code with runtime instrumentation across multiple env configs."""
    findings: list[Finding] = []
    seen_evidence = set()

    for env_config in SANDBOX_ENV_CONFIGS:
        env_findings = _sandbox_single_run(file_path, source, env_config)
        # Deduplicate across env runs
        for f in env_findings:
            key = (f.rule_id, f.evidence[:100])
            if key not in seen_evidence:
                seen_evidence.add(key)
                findings.append(f)
        # Stop after first env that finds something (optimization)
        if findings:
            break

    return findings


def _sandbox_single_run(file_path: str, source: str, env: dict) -> list[Finding]:
    """Single instrumented execution with a specific environment."""
    findings: list[Finding] = []
    instrumented = (
        HARNESS
        + "\n_SRC = "
        + repr(source)
        + "\n_USER_GLOBALS = {'__builtins__': _b, '__name__': '__sandbox_target__', '__file__': '<sandbox_target>'}\n"
        + "_code = _rc(_SRC, '<sandbox_target>', 'exec')\n"
        + "_re(_code, _USER_GLOBALS, _USER_GLOBALS)\n"
        + FOOTER
    )

    # Write into a dedicated, empty temp directory. The child interpreter puts
    # the script's directory on sys.path[0]; a shared temp dir may contain stray
    # or attacker-planted modules (e.g. enum.py) that would shadow stdlib imports
    # and silently break instrumentation. A private dir + -I (isolated mode)
    # eliminates that path-injection surface.
    tmp_dir = tempfile.mkdtemp(prefix="hfscan_sbx_")
    tmp = os.path.join(tmp_dir, "sandbox_target.py")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(instrumented)

    try:
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-u", tmp],
            capture_output=True,
            text=True,
            timeout=SANDBOX_TIMEOUT,
            env=env,
            cwd=tmp_dir,
        )
        stdout = result.stdout[:MAX_OUTPUT]
        if stdout:
            try:
                ops = json.loads(stdout)
            except json.JSONDecodeError:
                json_start = stdout.rfind("[")
                if json_start == -1:
                    ops = []
                else:
                    try:
                        ops = json.loads(stdout[json_start:])
                    except json.JSONDecodeError:
                        ops = []
            findings.extend(_interpret(file_path, ops))
        # Check stderr for blocked module access (sandbox crashed before output)
        stderr = result.stderr[:MAX_OUTPUT] if result.stderr else ""
        if not stdout and stderr:
            # Only flag if network/execution modules caused the crash
            # (os alone is too common in legitimate code)
            dangerous_crash_modules = [
                "subprocess",
                "socket",
                "ctypes",
                "webbrowser",
                "urllib",
                "http",
            ]
            blocked_indicators = ["AttributeError", "PermissionError", "OSError"]
            for module in dangerous_crash_modules:
                if module in stderr and any(
                    ind in stderr for ind in blocked_indicators
                ):
                    findings.append(
                        _make_finding(
                            "HFS-072",
                            file_path,
                            0,
                            f"Sandbox: code crashed accessing blocked module '{module}': "
                            f"{stderr[:150]}",
                        )
                    )
                    break
        if result.returncode < 0:
            findings.append(
                _make_finding(
                    "HFS-072",
                    file_path,
                    0,
                    f"Process killed by signal {-result.returncode}",
                )
            )
    except subprocess.TimeoutExpired:
        findings.append(
            _make_finding(
                "HFS-072", file_path, 0, f"Sandbox timed out after {SANDBOX_TIMEOUT}s"
            )
        )
    except OSError:
        pass
    finally:
        try:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except OSError:
            pass
    return findings


def _interpret(file_path: str, ops: list) -> list[Finding]:
    findings: list[Finding] = []
    seen = set()
    # Track which modules were imported (to distinguish bare import from usage)
    imported_modules = set()
    dangerous_ops = []

    for entry in ops:
        if not isinstance(entry, dict):
            continue
        op = entry.get("op", "")
        if op == "import":
            imported_modules.add(entry.get("module", ""))
        elif op in ("exec", "eval", "compile"):
            dangerous_ops.append(entry)
        elif op == "attr":
            attr = entry.get("attr", "")
            if attr in (
                "system",
                "popen",
                "Popen",
                "run",
                "call",
                "check_output",
                "getaddrinfo",
                "connect",
                "socket",
                "urlopen",
                "create_connection",
                "AF_INET",
                "SOCK_RAW",
                "remove",
                "unlink",
                "rmdir",
                "listdir",
                "scandir",
                "walk",
            ):
                dangerous_ops.append(entry)

    # Only report import findings if the module was ALSO used dangerously
    # (i.e., there are exec/eval/attr findings that reference it)
    has_dangerous_usage = len(dangerous_ops) > 0

    for entry in ops:
        if not isinstance(entry, dict):
            continue
        op = entry.get("op", "")
        key = (
            op,
            entry.get("module", ""),
            entry.get("attr", ""),
            entry.get("code", "")[:30],
        )
        if key in seen:
            continue
        seen.add(key)

        if op == "exec":
            findings.append(
                _make_finding(
                    "HFS-072",
                    file_path,
                    0,
                    f"Sandbox: exec() with: {entry.get('code','')}",
                )
            )
        elif op == "eval":
            findings.append(
                _make_finding(
                    "HFS-072",
                    file_path,
                    0,
                    f"Sandbox: eval() with: {entry.get('code','')}",
                )
            )
        elif op == "compile":
            findings.append(
                _make_finding(
                    "HFS-072",
                    file_path,
                    0,
                    f"Sandbox: compile() with: {entry.get('source','')}",
                )
            )
        elif op == "import":
            # Only flag blocked imports if there's also dangerous usage
            # (bare "import os" in a data loading script is legitimate)
            if has_dangerous_usage:
                findings.append(
                    _make_finding(
                        "HFS-072",
                        file_path,
                        0,
                        f"Sandbox: blocked import '{entry.get('module','')}'",
                    )
                )
        elif op == "attr":
            attr = entry.get("attr", "")
            if attr in (
                "system",
                "popen",
                "Popen",
                "run",
                "call",
                "check_output",
                "getaddrinfo",
                "connect",
                "socket",
                "urlopen",
                "remove",
                "unlink",
                "rmdir",
                "listdir",
                "scandir",
                "walk",
            ):
                findings.append(
                    _make_finding(
                        "HFS-072",
                        file_path,
                        0,
                        f"Sandbox: {entry.get('module','')}.{attr}()",
                    )
                )
    return findings
