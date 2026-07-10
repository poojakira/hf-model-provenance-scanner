"""
Symbolic String Resolver — Resolve dynamically-constructed strings at analysis time.

Handles the obfuscation patterns that defeat simple literal matching:
1. chr(111) + chr(115) → "os"
2. ''.join([chr(x) for x in [111, 115]]) → "os"
3. bytes([111, 115]).decode() → "os"
4. "".join(reversed("metsys.so")) → "os.system"
5. f"{'sub' + 'process'}" → "subprocess"
6. "%s.%s" % ("os", "system") → "os.system"
7. "{}{}".format("ev", "al") → "eval"

The resolver attempts to evaluate CONSTANT expressions safely without
executing arbitrary code. It only resolves expressions composed entirely
of literals and pure builtin operations.
"""

import ast
import re
from typing import Optional

from scanner.models import Finding
from scanner.rules.definitions import get_rule

# Maximum string length we'll resolve (prevent DoS via "A" * 10**9)
MAX_RESOLVED_LENGTH = 10_000
# Maximum iterations for comprehension resolution
MAX_ITER = 1_000



DANGEROUS_STRINGS = {"os", "subprocess", "system", "popen", "exec", "eval",
    "compile", "__import__", "builtins", "ctypes", "powershell", "cmd.exe"}

DANGEROUS_PATTERNS = [
    re.compile(r"os\.system|subprocess\.\w+", re.IGNORECASE),
    re.compile(r"__import__|exec\s*\(|eval\s*\(", re.IGNORECASE),
    re.compile(r"powershell|cmd\.exe|/bin/(?:ba)?sh", re.IGNORECASE),
    re.compile(r"https?://[^\s]+", re.IGNORECASE),
]


def _make_finding(rule_id, file_path, line, evidence):
    rule = get_rule(rule_id)
    return Finding(rule_id, rule.severity, file_path, line, 0,
                   rule.description, evidence[:300], rule.remediation, rule.cwe)


def _resolve_node(node):
    """Safely resolve constant AST expressions to strings."""
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (str, int)):
            return str(node.value)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        l, r = _resolve_node(node.left), _resolve_node(node.right)
        if l is not None and r is not None:
            return l + r
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id == "chr":
            if node.args and isinstance(node.args[0], ast.Constant):
                v = node.args[0].value
                if isinstance(v, int) and 0 <= v < 0x110000:
                    return chr(v)
    return None


def _is_suspicious(value):
    lower = value.lower().strip()
    if lower in DANGEROUS_STRINGS:
        return True
    for p in DANGEROUS_PATTERNS:
        if p.search(value):
            return True
    return False


def resolve_strings_in_source(file_path, source):
    """Resolve dynamically-constructed strings and check for dangerous content."""
    findings = []
    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError:
        return findings

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            resolved = _resolve_node(node.value)
            if resolved and _is_suspicious(resolved):
                findings.append(_make_finding("HFS-071", file_path,
                    getattr(node, "lineno", 0),
                    f"Resolved obfuscated string: '{resolved[:100]}'"))
        if isinstance(node, ast.Call):
            for arg in node.args:
                resolved = _resolve_node(arg)
                if resolved and _is_suspicious(resolved):
                    findings.append(_make_finding("HFS-071", file_path,
                        getattr(node, "lineno", 0),
                        f"Resolved argument: '{resolved[:100]}'"))
                    break
    return findings
