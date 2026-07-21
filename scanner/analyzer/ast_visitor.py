import ast
import base64
import os
import re
from typing import Optional

from scanner.models import Finding, Severity
from scanner.rules.definitions import get_rule
from scanner.utils.entropy import shannon_entropy

FULL_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$", re.IGNORECASE)
LOADER_NAMES = {"loader.py", "setup.py", "install.py", "start.py", "run.py", "inference.py"}
NETWORK_PREFIXES = ("urllib", "urllib.request", "requests", "http.client", "socket")
EXECUTION_CALLS = {"subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "os.system", "pickle.loads", "marshal.loads", "eval", "exec", "compile", "__import__"}

HIGH_ENTROPY_ALLOWLIST_PATTERNS = [
    re.compile(r"^[0-9a-f]{40,}$", re.IGNORECASE),
    re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
    re.compile(r"^\d+\.\d+\.\d+"),
]

BYTE_PATTERNS = [
    (b"powershell", "HFS-001", Severity.CRITICAL),
    (b"cmd.exe", "HFS-001", Severity.CRITICAL),
    (b"pwsh", "HFS-001", Severity.CRITICAL),
    (b"jsonkeeper", "HFS-004", Severity.CRITICAL),
    (b"pastebin", "HFS-004", Severity.CRITICAL),
    (b"gist.githubusercontent", "HFS-004", Severity.CRITICAL),
    (b"ngrok", "HFS-004", Severity.CRITICAL),
    (b"eth-fastscan", "HFS-004", Severity.CRITICAL),
    (b"Zone.Identifier", "HFS-013", Severity.HIGH),
    (b"Add-MpPreference", "HFS-015", Severity.HIGH),
    (b"Set-MpPreference", "HFS-015", Severity.HIGH),
    (b"-ExclusionPath", "HFS-015", Severity.HIGH),
    (b"-EncodedCommand", "HFS-005", Severity.CRITICAL),
    (b"AmsiScanBuffer", "HFS-006", Severity.CRITICAL),
    (b"AmsiUtils", "HFS-006", Severity.CRITICAL),
    (b"EtwEventWrite", "HFS-006", Severity.CRITICAL),
    (b"NtSetInformationProcess", "HFS-006", Severity.CRITICAL),
    (b"CREATE_NO_WINDOW", "HFS-014", Severity.HIGH),
    (b"SW_HIDE", "HFS-014", Severity.HIGH),
    (b"WindowStyle Hidden", "HFS-014", Severity.HIGH),
    (b"schtasks", "HFS-016", Severity.HIGH),
]


def is_base64_candidate(s: str) -> bool:
    if len(s) < 20:
        return False
    if not re.match(r"^[A-Za-z0-9+/=\s]+$", s):
        return False
    stripped = re.sub(r"\s+", "", s)
    if len(stripped) % 4 != 0 and not stripped.endswith("="):
        return False
    if shannon_entropy(stripped) < 4.5:
        return False
    return not any(pattern.match(stripped) for pattern in HIGH_ENTROPY_ALLOWLIST_PATTERNS)


def safe_b64decode(s: str) -> Optional[bytes]:
    stripped = re.sub(r"\s+", "", s)
    try:
        return base64.b64decode(stripped, validate=True)
    except Exception:
        try:
            return base64.b64decode(stripped + "==", validate=False)
        except Exception:
            return None


def byte_pattern_scan(data: bytes, file_path: str, decoded_layer: int) -> list[Finding]:
    findings = []
    data_lower = data.lower()
    for pattern, rule_id, _ in BYTE_PATTERNS:
        if pattern.lower() in data_lower:
            rule = get_rule(rule_id)
            findings.append(Finding(
                rule_id=rule_id,
                severity=rule.severity,
                file_path=file_path,
                line_number=0,
                column=0,
                message=f"{rule.name} (decoded layer {decoded_layer})",
                evidence=f"[decoded] matches {pattern.decode('ascii', errors='ignore')}",
                remediation=rule.remediation,
                cwe=rule.cwe,
                decoded_layer=decoded_layer,
            ))
    return findings


def dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


class ScannerASTVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, source: str, decoded_layer: int = 0):
        self.file_path = file_path
        self.source = source
        self.decoded_layer = decoded_layer
        self.findings: list[Finding] = []
        self.strings: list[tuple[str, ast.AST]] = []
        self.constants: dict[str, str] = {}
        self.basename = os.path.basename(file_path).lower()

    def report(self, rule_id: str, node: ast.AST, evidence: str):
        rule = get_rule(rule_id)
        self.findings.append(Finding(
            rule_id=rule_id,
            severity=rule.severity,
            file_path=self.file_path,
            line_number=getattr(node, "lineno", 0),
            column=getattr(node, "col_offset", 0),
            message=rule.description,
            evidence=evidence[:300],
            remediation=rule.remediation,
            cwe=rule.cwe,
            decoded_layer=self.decoded_layer,
        ))

    def literal_string(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                return node.value
            if isinstance(node.value, bytes):
                try:
                    return node.value.decode("utf-8")
                except UnicodeDecodeError:
                    return None
            if isinstance(node.value, (int, float, bool)):
                return str(node.value)
        if isinstance(node, ast.Name):
            return self.constants.get(node.id)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self.literal_string(node.left)
            right = self.literal_string(node.right)
            if left is not None and right is not None:
                return left + right
        if isinstance(node, ast.JoinedStr):
            parts = []
            for value in node.values:
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    parts.append(value.value)
                else:
                    return None
            return "".join(parts)
        return None

    def call_text(self, node: ast.Call) -> str:
        parts = [dotted_name(node.func)]
        for arg in node.args:
            value = self.literal_string(arg)
            if value:
                parts.append(value)
        for kw in node.keywords:
            value = self.literal_string(kw.value)
            if value:
                parts.append(f"{kw.arg}={value}")
        return " ".join(parts)

    def visit_Constant(self, node):
        value_str = self.literal_string(node)
        if value_str is not None:
            self.strings.append((value_str, node))
            if len(value_str) >= 40:
                entropy = shannon_entropy(value_str)
                if entropy >= 5.7 and not any(pattern.match(value_str) for pattern in HIGH_ENTROPY_ALLOWLIST_PATTERNS):
                    self.report("HFS-010", node, f"entropy: {entropy:.2f}, len: {len(value_str)}")
        self.generic_visit(node)

    def visit_Call(self, node):
        call_name = dotted_name(node.func)
        call_text = self.call_text(node)
        call_lower = call_text.lower()

        for kw in node.keywords:
            if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                self.report("HFS-002", node, "verify=False")
            if kw.arg == "trust_remote_code" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                self.report("HFS-031", node, "trust_remote_code=True")
            if kw.arg == "creationflags":
                if "create_no_window" in call_lower or "134217728" in call_lower or "0x08000000" in call_lower:
                    self.report("HFS-014", node, call_text)

        if call_name.endswith("._create_unverified_context"):
            self.report("HFS-002", node, "ssl._create_unverified_context()")

        if call_name in EXECUTION_CALLS:
            if self.basename == "__init__.py" or call_name in {"eval", "exec", "compile", "__import__", "os.system", "subprocess.run", "subprocess.Popen", "pickle.loads", "marshal.loads"}:
                self.report("HFS-001", node, call_text)
            if any(term in call_lower for term in ("powershell", "cmd.exe", "pwsh")):
                self.report("HFS-001", node, call_text)
            if any(term in call_lower for term in ("windowstyle hidden", "create_no_window", "sw_hide")):
                self.report("HFS-014", node, call_text)
            if "schtasks" in call_lower:
                self.report("HFS-016", node, call_text)

        if call_name in {"eval", "exec"} and any(term in call_lower for term in ("b64decode", "base64")):
            self.report("HFS-003", node, call_text)

        if self.basename in LOADER_NAMES and (call_name.startswith(NETWORK_PREFIXES) or any(p in call_lower for p in ("urlopen", "request", "socket"))):
            self.report("HFS-023", node, call_text)

        if call_name.endswith("from_pretrained"):
            revision = None
            for kw in node.keywords:
                if kw.arg == "revision":
                    revision = self.literal_string(kw.value)
            if revision is None or not FULL_SHA_RE.match(revision):
                self.report("HFS-030", node, f"from_pretrained revision={revision!r}")

        # Bypass-hardened: getattr on dangerous modules
        if call_name in ("getattr", "builtins.getattr") and len(node.args) >= 2:
            obj = dotted_name(node.args[0]) if isinstance(node.args[0], (ast.Name, ast.Attribute)) else ""
            if obj in ("os", "subprocess", "builtins", "__builtins__", "shutil", "ctypes"):
                self.report("HFS-011", node, f"getattr({obj}, ...) on dangerous module")

        # Bypass-hardened: compile() + exec
        if call_name == "compile":
            self.report("HFS-011", node, "compile() generates code objects for exec")

        # Bypass-hardened: ctypes FFI
        if "ctypes" in call_name or "CDLL" in call_name or "cdll" in call_lower:
            self.report("HFS-011", node, f"ctypes FFI: {call_name}")

        # Bypass-hardened: codecs.decode with rot_13
        if call_name in ("codecs.decode", "codecs.encode"):
            if any(enc in call_lower for enc in ("rot_13", "rot13")):
                self.report("HFS-011", node, f"codecs obfuscation: {call_text[:80]}")

        # Bypass-hardened: __import__ with non-literal arg
        if call_name in ("__import__", "builtins.__import__"):
            if node.args and not isinstance(node.args[0], ast.Constant):
                self.report("HFS-011", node, "__import__ with dynamic argument")

        # Bypass-hardened: exec/eval with any call as argument
        if call_name in ("exec", "eval") and node.args:
            if isinstance(node.args[0], ast.Call):
                self.report("HFS-003", node, f"{call_name}(func_call()) — dynamic execution")
            elif isinstance(node.args[0], ast.Name):
                self.report("HFS-003", node, f"{call_name}(variable) — executing variable content")

        self.generic_visit(node)

    def visit_ExceptHandler(self, node):
        catches_broad = getattr(node, "type", None) is None or (isinstance(node.type, ast.Name) and node.type.id == "Exception")
        if catches_broad and len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            self.report("HFS-012", node, "except: pass")
        self.generic_visit(node)

    def visit_BinOp(self, node):
        if isinstance(node.op, ast.Add):
            left = self.literal_string(node.left)
            right = self.literal_string(node.right)
            if left is not None and right is not None and any(token in (left + right).lower() for token in ("process", "system", "eval", "exec", "import")):
                self.report("HFS-011", node, f"{left!r} + {right!r}")
        self.generic_visit(node)

    def visit_Assign(self, node):
        value = self.literal_string(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                if value is not None:
                    self.constants[target.id] = value
                if target.id == "trust_remote_code" and isinstance(node.value, ast.Constant) and node.value.value is True:
                    self.report("HFS-031", node, "trust_remote_code=True")
            target_name = dotted_name(target)
            if target_name.endswith("check_hostname") and isinstance(node.value, ast.Constant) and node.value.value is False:
                self.report("HFS-002", node, "check_hostname=False")
            if target_name.endswith("verify_mode") and dotted_name(node.value).endswith("CERT_NONE"):
                self.report("HFS-002", node, "verify_mode=ssl.CERT_NONE")
        self.generic_visit(node)


def analyze_python_source(file_path: str, source: str, decoded_layer: int = 0, max_decode_depth: int = 3) -> list[Finding]:
    findings = byte_pattern_scan(source.encode("utf-8", errors="ignore"), file_path, decoded_layer)

    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError as e:
        rule = get_rule("HFS-099")
        findings.append(Finding("HFS-099", rule.severity, file_path, getattr(e, "lineno", 0) or 0, getattr(e, "offset", 0) or 0, rule.description, str(e), rule.remediation, rule.cwe, decoded_layer))
        return findings

    visitor = ScannerASTVisitor(file_path, source, decoded_layer)
    visitor.visit(tree)
    findings.extend(visitor.findings)

    if decoded_layer < max_decode_depth:
        for s, node in visitor.strings:
            if not is_base64_candidate(s):
                continue
            decoded = safe_b64decode(s)
            if decoded is None:
                continue
            try:
                decoded_str = decoded.decode("utf-8")
                ast.parse(decoded_str)
                rule = get_rule("HFS-003")
                findings.append(Finding("HFS-003", rule.severity, file_path, getattr(node, "lineno", 0), getattr(node, "col_offset", 0), rule.description, "Base64 decoded payload evaluates as executable", rule.remediation, rule.cwe, decoded_layer))
                findings.extend(analyze_python_source(file_path, decoded_str, decoded_layer + 1, max_decode_depth))
            except (UnicodeDecodeError, SyntaxError):
                byte_findings = byte_pattern_scan(decoded, file_path, decoded_layer + 1)
                if any(f.rule_id == "HFS-001" for f in byte_findings):
                    rule = get_rule("HFS-003")
                    findings.append(Finding("HFS-003", rule.severity, file_path, getattr(node, "lineno", 0), getattr(node, "col_offset", 0), rule.description, "Base64 decoded payload executes PowerShell", rule.remediation, rule.cwe, decoded_layer))
                findings.extend(byte_findings)
                if decoded_layer + 1 < max_decode_depth:
                    try:
                        decoded_str = decoded.decode("utf-8")
                        if is_base64_candidate(decoded_str):
                            decoded2 = safe_b64decode(decoded_str)
                            if decoded2 is not None:
                                findings.extend(byte_pattern_scan(decoded2, file_path, decoded_layer + 2))
                    except UnicodeDecodeError:
                        pass
    return findings
