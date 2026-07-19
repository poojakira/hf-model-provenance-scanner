"""
Sandbox Execution Engine — Run untrusted code in restricted environments.
Supports: subprocess (fallback), gVisor (runsc), Firecracker microVMs.
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

# gVisor runtime
GVISOR_RUNTIME = os.environ.get("GVISOR_RUNTIME", shutil.which("runsc") or "runsc")
GVISOR_FLAGS = [
    "--platform=ptrace",
    "--network=none",
    "--disk-type=none",
    "--cpus=1",
    "--memory=512M",
]

# Firecracker microVM (requires pre-configured microVM)
FIRECRACKER_RUNTIME = os.environ.get("FIRECRACKER_RUNTIME", "firecracker")

# Environment configurations to test against (catches gated payloads)
SANDBOX_ENV_CONFIGS = [
    # Default: minimal environment
    {"PATH": "", "HOME": "/tmp", "PYTHONDONTWRITEBYTECODE": "1"},
    # Windows-like: triggers platform.system() == "Windows" gates
    {"PATH": "", "HOME": "/tmp", "PYTHONDONTWRITEBYTECODE": "1",
     "OS": "Windows_NT", "SYSTEMROOT": "C:\\Windows", "COMSPEC": "cmd.exe"},
    # CI environment: triggers CI-detection gates
    {"PATH": "", "HOME": "/tmp", "PYTHONDONTWRITEBYTECODE": "1",
     "CI": "true", "GITHUB_ACTIONS": "true", "GITLAB_CI": "true"},
]


def _make_finding(rule_id: str, file_path: str, line: int, evidence: str) -> Finding:
    rule = get_rule(rule_id)
    return Finding(rule_id, rule.severity, file_path, line, 0,
                   rule.description, evidence[:300], rule.remediation, rule.cwe)


HARNESS = textwrap.dedent('''
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
    """Execute code in sandboxed environment with multiple env configs, return findings."""
    backend = os.environ.get("HF_SANDBOX_BACKEND", "subprocess").lower()

    if backend == "gvisor":
        return _sandbox_gvisor(file_path, source)
    elif backend == "firecracker":
        return _sandbox_firecracker(file_path, source)
    else:
        return _sandbox_subprocess(file_path, source)


def _sandbox_subprocess(file_path: str, source: str) -> list[Finding]:
    """Legacy subprocess-based sandbox with multiple env configs (fallback)."""
    findings: list[Finding] = []
    seen_evidence = set()

    for env_config in SANDBOX_ENV_CONFIGS:
        env_findings = _sandbox_single_run(file_path, source, env_config)
        for f in env_findings:
            key = (f.rule_id, f.evidence[:100])
            if key not in seen_evidence:
                seen_evidence.add(key)
                findings.append(f)
        if findings:
            break

    # Add warning about legacy sandbox
    findings.append(_make_finding(
        "HFS-072", file_path, 0,
        "Sandbox: using legacy subprocess backend — set HF_SANDBOX_BACKEND=gvisor for stronger isolation"
    ))

    return findings


def _sandbox_gvisor(file_path: str, source: str) -> list[Finding]:
    """Execute code in gVisor sandbox (runsc) for strong isolation."""
    findings: list[Finding] = []

    if not _check_gvisor_available():
        # Fallback to subprocess with clear warning
        fallback = _sandbox_subprocess(file_path, source)
        fallback.append(_make_finding(
            "HFS-072", file_path, 0,
            "gVisor (runsc) not available — install runsc or set HF_SANDBOX_BACKEND=subprocess"
        ))
        return fallback

    for env_config in SANDBOX_ENV_CONFIGS:
        env_findings = _sandbox_gvisor_single(file_path, source, env_config)
        findings.extend(env_findings)
        if findings:
            break

    return findings


def _check_gvisor_available() -> bool:
    """Check if gVisor runsc is available."""
    return shutil.which("runsc") is not None


def _sandbox_gvisor_single(file_path: str, source: str, env: dict) -> list[Finding]:
    """Single gVisor sandbox execution with a specific environment."""
    findings: list[Finding] = []
    instrumented = HARNESS + "\n" + source + "\n" + FOOTER

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
        f.write(instrumented)
        tmp = f.name

    # Build runsc command
    cmd = [
        GVISOR_RUNTIME,
        "run",
        "--platform=ptrace",
        "--network=none",
        "--disk-type=none",
        "--cpus=1",
        "--memory=512M",
        "--",
        sys.executable, "-S", "-u", tmp
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=SANDBOX_TIMEOUT,
            env=env)
        stdout = result.stdout[:MAX_OUTPUT]
        if stdout:
            try:
                ops = json.loads(stdout)
                findings.extend(_interpret(file_path, ops))
            except json.JSONDecodeError:
                pass

        stderr = result.stderr[:MAX_OUTPUT] if result.stderr else ""
        if not result.stdout and stderr:
            dangerous_crash_modules = ["subprocess", "socket", "ctypes",
                                       "webbrowser", "urllib", "http"]
            blocked_indicators = ["AttributeError", "PermissionError", "OSError"]
            for module in dangerous_crash_modules:
                if module in stderr and any(ind in stderr for ind in blocked_indicators):
                    findings.append(_make_finding("HFS-072", file_path, 0,
                        f"Sandbox: code crashed accessing blocked module '{module}': "
                        f"{stderr[:150]}"))
                    break
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


def _sandbox_firecracker(file_path: str, source: str) -> list[Finding]:
    """Execute code in Firecracker microVM for strongest isolation."""
    findings: list[Finding] = []

    if not _check_firecracker_available():
        fallback = _sandbox_subprocess(file_path, source)
        fallback.append(_make_finding(
            "HFS-072", file_path, 0,
            "Firecracker not available — install firecracker or set HF_SANDBOX_BACKEND=subprocess"
        ))
        return fallback

    # Firecracker requires a pre-configured microVM image
    # This is a simplified implementation - production would use a pre-built microVM
    findings.append(_make_finding(
        "HFS-072", file_path, 0,
        "Firecracker backend: requires pre-configured microVM image (kernel + rootfs). "
        "See docs/firecracker-setup.md. Falling back to subprocess."
    ))
    return _sandbox_subprocess(file_path, source)


def _sandbox_firecracker(file_path: str, source: str) -> list[Finding]:
    """Execute code in Firecracker microVM for strongest isolation."""
    findings: list[Finding] = []

    if not _check_firecracker_available():
        fallback = _sandbox_subprocess(file_path, source)
        fallback.append(_make_finding(
            "HFS-072", file_path, 0,
            "Firecracker not available — install firecracker or set HF_SANDBOX_BACKEND=subprocess"
        ))
        return fallback

    # Firecracker requires a pre-configured microVM image
    # This is a simplified implementation - production would use a pre-built microVM
    findings.append(_make_finding(
        "HFS-072", file_path, 0,
        "Firecracker backend: requires pre-configured microVM image (kernel + rootfs). "
        "See docs/firecracker-setup.md. Falling back to subprocess."
    ))
    return _sandbox_subprocess(file_path, source)


def _check_firecracker_available() -> bool:
    """Check if Firecracker is available."""
    return shutil.which("firecracker") is not None


def _sandbox_single_run(file_path: str, source: str, env: dict) -> list[Finding]:
    """Single sandbox execution with a specific environment."""
    findings: list[Finding] = []
    instrumented = HARNESS + "\n" + source + "\n" + FOOTER

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
        f.write(instrumented)
        tmp = f.name

    try:
        result = subprocess.run(
            [sys.executable, "-S", "-u", tmp],
            capture_output=True, text=True, timeout=SANDBOX_TIMEOUT,
            env=env)
        stdout = result.stdout[:MAX_OUTPUT]
        if stdout:
            try:
                ops = json.loads(stdout)
                findings.extend(_interpret(file_path, ops))
            except json.JSONDecodeError:
                pass

        # Check stderr for blocked module access (sandbox crashed before output)
        stderr = result.stderr[:MAX_OUTPUT] if result.stderr else ""
        if not stdout and stderr:
            # Only flag if network/execution modules caused the crash
            # (os alone is too common in legitimate code)
            dangerous_crash_modules = ["subprocess", "socket", "ctypes",
                                       "webbrowser", "urllib", "http"]
            blocked_indicators = ["AttributeError", "PermissionError", "OSError"]
            for module in dangerous_crash_modules:
                if module in stderr and any(ind in stderr for ind in blocked_indicators):
                    findings.append(_make_finding("HFS-072", file_path, 0,
                        f"Sandbox: code crashed accessing blocked module '{module}': "
                        f"{stderr[:150]}"))
                    break
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


def _sandbox_subprocess(file_path: str, source: str) -> list[Finding]:
    """Legacy subprocess-based sandbox with multiple env configs."""
    findings: list[Finding] = []
    seen_evidence = set()

    for env_config in SANDBOX_ENV_CONFIGS:
        env_findings = _sandbox_single_run(file_path, source, env_config)
        for f in env_findings:
            key = (f.rule_id, f.evidence[:100])
            if key not in seen_evidence:
                seen_evidence.add(key)
                findings.append(f)
        if findings:
            break

    # Add warning about legacy sandbox
    findings.append(_make_finding(
        "HFS-072", file_path, 0,
        "Sandbox: using legacy subprocess backend — set HF_SANDBOX_BACKEND=gvisor for stronger isolation"
    ))

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
            if attr in ("system", "popen", "Popen", "run", "call", "check_output",
                        "getaddrinfo", "connect", "socket", "urlopen",
                        "create_connection", "AF_INET", "SOCK_RAW"):
                dangerous_ops.append(entry)

    # Only report import findings if the module was ALSO used dangerously
    # (i.e., there are exec/eval/attr findings that reference it)
    has_dangerous_usage = len(dangerous_ops) > 0

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
        elif op == "compile":
            findings.append(_make_finding("HFS-072", file_path, 0,
                                          f"Sandbox: compile() with: {entry.get('source','')}"))
        elif op == "import":
            # Only flag blocked imports if there's also dangerous usage
            # (bare "import os" in a data loading script is legitimate)
            if has_dangerous_usage:
                findings.append(_make_finding("HFS-072", file_path, 0,
                                              f"Sandbox: blocked import '{entry.get('module','')}'"))
        elif op == "attr":
            attr = entry.get("attr", "")
            if attr in ("system", "popen", "Popen", "run", "call", "check_output",
                       "getaddrinfo", "connect", "socket", "urlopen"):
                findings.append(_make_finding("HFS-072", file_path, 0,
                                              f"Sandbox: {entry.get('module','')}.{attr}()"))
    return findings
