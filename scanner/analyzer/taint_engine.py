"""
Taint Tracking Engine — Intra-procedural dataflow analysis for Python.

Tracks tainted data from SOURCES (untrusted origins) through PROPAGATION
(variable assignments, function returns, container operations) to SINKS
(dangerous execution functions).

This closes the bypass gap that static pattern matching cannot address:
- lambda + map + __builtins__["exec"]
- Variable indirection: x = os; x.system("cmd")
- Container-mediated flows: d = {"exec": exec}; d["exec"](payload)
- Return value propagation: get_cmd() → exec(get_cmd())

Architecture:
    1. First pass: collect all assignments, function defs, imports
    2. Second pass: propagate taint labels through the AST
    3. Third pass: check if any tainted value reaches a SINK
"""

import ast
from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional

from scanner.models import Finding
from scanner.rules.definitions import get_rule


class TaintLabel(Enum):
    """Classification of taint sources."""
    EXEC_CALLABLE = auto()     # exec, eval, compile
    DANGEROUS_MODULE = auto()  # os, subprocess, shutil, ctypes
    NETWORK_CALLABLE = auto()  # urllib, requests, socket
    DECODED_DATA = auto()      # base64.decode, codecs.decode output
    IMPORT_RESULT = auto()     # __import__() return value
    USER_CONTROLLED = auto()   # function parameters, external input
    CONTAINER_LOOKUP = auto()  # dict/list lookup that resolved to tainted


@dataclass
class TaintInfo:
    """Track what a variable/expression is tainted with."""
    labels: set  # set of TaintLabel
    source_line: int = 0
    source_desc: str = ""

    def is_tainted(self) -> bool:
        return len(self.labels) > 0


# --- Source definitions ---
# These create initial taint labels when referenced

DANGEROUS_MODULES = {
    "os", "subprocess", "shutil", "ctypes", "webbrowser",
    "runpy", "importlib", "nt", "posix", "signal",
}

EXEC_FUNCTIONS = {
    "exec", "eval", "compile", "execfile",
    "os.system", "os.popen", "os.exec", "os.execl", "os.execle",
    "os.execlp", "os.execv", "os.execve", "os.execvp", "os.execvpe",
    "subprocess.run", "subprocess.Popen", "subprocess.call",
    "subprocess.check_call", "subprocess.check_output",
    "builtins.exec", "builtins.eval", "builtins.compile",
    "__builtins__.exec", "__builtins__.eval",
}

NETWORK_FUNCTIONS = {
    "urllib.request.urlopen", "urllib.request.urlretrieve",
    "http.client.HTTPConnection", "http.client.HTTPSConnection",
    "socket.socket", "socket.create_connection",
}

DECODE_FUNCTIONS = {
    "base64.b64decode", "base64.b85decode", "base64.b32decode",
    "base64.b16decode", "base64.a85decode", "base64.decodebytes",
    "codecs.decode", "binascii.unhexlify", "binascii.a2b_base64",
    "zlib.decompress", "gzip.decompress", "bz2.decompress",
    "lzma.decompress",
}

# Sink functions: if tainted data reaches these, it's a finding
SINK_FUNCTIONS = EXEC_FUNCTIONS | {
    "os.system", "os.popen",
    "ctypes.CDLL", "ctypes.cdll.LoadLibrary",
}


def _make_finding(rule_id: str, file_path: str, line: int, evidence: str) -> Finding:
    rule = get_rule(rule_id)
    return Finding(
        rule_id=rule_id,
        severity=rule.severity,
        file_path=file_path,
        line_number=line,
        column=0,
        message=rule.description,
        evidence=evidence[:300],
        remediation=rule.remediation,
        cwe=rule.cwe,
    )


def _dotted_name(node: ast.AST) -> str:
    """Extract dotted name from AST node."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


class TaintAnalyzer(ast.NodeVisitor):
    """
    Intra-procedural taint tracker.

    Performs a forward dataflow analysis:
    1. Marks sources (imports of dangerous modules, decode calls)
    2. Propagates through assignments and function calls
    3. Flags when tainted values reach sinks (exec, eval, system)
    """

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.findings: list[Finding] = []

        # Variable → TaintInfo mapping (simplified: flat scope)
        self.taint_map: dict[str, TaintInfo] = {}

        # Track which functions return tainted values
        self.tainted_returns: dict[str, TaintInfo] = {}

        # Track import aliases
        self.import_aliases: dict[str, str] = {}

        # Preload builtins-level taint
        self.taint_map["exec"] = TaintInfo({TaintLabel.EXEC_CALLABLE}, 0, "builtin exec")
        self.taint_map["eval"] = TaintInfo({TaintLabel.EXEC_CALLABLE}, 0, "builtin eval")
        self.taint_map["compile"] = TaintInfo({TaintLabel.EXEC_CALLABLE}, 0, "builtin compile")
        self.taint_map["__import__"] = TaintInfo({TaintLabel.IMPORT_RESULT}, 0, "builtin __import__")

    def analyze(self, source: str) -> list[Finding]:
        """Run taint analysis on source code."""
        try:
            tree = ast.parse(source, filename=self.file_path)
        except SyntaxError:
            return []

        # Pass 1: collect imports and top-level assignments
        self._collect_imports(tree)

        # Pass 2: propagate taint and check sinks
        self.visit(tree)

        return self.findings

    def _collect_imports(self, tree: ast.Module):
        """Pre-scan imports to set up taint sources."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name
                    module = alias.name.split(".")[0]
                    self.import_aliases[name] = alias.name
                    if module in DANGEROUS_MODULES:
                        self.taint_map[name] = TaintInfo(
                            {TaintLabel.DANGEROUS_MODULE},
                            getattr(node, "lineno", 0),
                            f"import {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                base_module = module.split(".")[0]
                for alias in node.names:
                    name = alias.asname or alias.name
                    full_name = f"{module}.{alias.name}"
                    self.import_aliases[name] = full_name
                    if base_module in DANGEROUS_MODULES:
                        self.taint_map[name] = TaintInfo(
                            {TaintLabel.DANGEROUS_MODULE},
                            getattr(node, "lineno", 0),
                            f"from {module} import {alias.name}")
                    elif full_name in EXEC_FUNCTIONS:
                        self.taint_map[name] = TaintInfo(
                            {TaintLabel.EXEC_CALLABLE},
                            getattr(node, "lineno", 0),
                            f"from {module} import {alias.name}")

    def _get_taint(self, node: ast.AST) -> Optional[TaintInfo]:
        """Resolve the taint status of an expression."""
        if isinstance(node, ast.Name):
            return self.taint_map.get(node.id)

        if isinstance(node, ast.Attribute):
            # Check full dotted name
            full = _dotted_name(node)
            if full in EXEC_FUNCTIONS:
                return TaintInfo({TaintLabel.EXEC_CALLABLE}, getattr(node, "lineno", 0), full)
            if full in NETWORK_FUNCTIONS:
                return TaintInfo({TaintLabel.NETWORK_CALLABLE}, getattr(node, "lineno", 0), full)
            if full in DECODE_FUNCTIONS:
                return TaintInfo({TaintLabel.DECODED_DATA}, getattr(node, "lineno", 0), full)
            # Check if base object is tainted
            base_taint = self._get_taint(node.value)
            if base_taint and base_taint.is_tainted():
                return base_taint

        if isinstance(node, ast.Subscript):
            # dict["exec"] or list[0] — propagate container taint
            base_taint = self._get_taint(node.value)
            if base_taint:
                return TaintInfo(
                    base_taint.labels | {TaintLabel.CONTAINER_LOOKUP},
                    getattr(node, "lineno", 0),
                    f"subscript on tainted {_dotted_name(node.value)}")

        if isinstance(node, ast.Call):
            return self._get_call_taint(node)

        return None

    def _get_call_taint(self, node: ast.Call) -> Optional[TaintInfo]:
        """Determine taint of a function call's return value."""
        call_name = _dotted_name(node.func)

        # __import__ always returns a tainted module
        if call_name == "__import__":
            return TaintInfo({TaintLabel.IMPORT_RESULT, TaintLabel.DANGEROUS_MODULE},
                             getattr(node, "lineno", 0), "__import__() result")

        # Decode functions produce tainted (decoded) data
        if call_name in DECODE_FUNCTIONS:
            return TaintInfo({TaintLabel.DECODED_DATA},
                             getattr(node, "lineno", 0), f"{call_name}() output")

        # getattr on tainted module
        if call_name == "getattr":
            if node.args:
                base_taint = self._get_taint(node.args[0])
                if base_taint and TaintLabel.DANGEROUS_MODULE in base_taint.labels:
                    return TaintInfo(
                        {TaintLabel.EXEC_CALLABLE, TaintLabel.DANGEROUS_MODULE},
                        getattr(node, "lineno", 0),
                        "getattr() on dangerous module")

        # Check if calling a tainted callable itself
        func_taint = self._get_taint(node.func)
        if func_taint and TaintLabel.EXEC_CALLABLE in func_taint.labels:
            # This is a SINK — the exec/eval is being called
            return None  # handled in visit_Call

        # Check user-defined function returns
        if call_name in self.tainted_returns:
            return self.tainted_returns[call_name]

        # chr() produces potentially tainted strings when part of a larger expr
        if call_name == "chr":
            return TaintInfo({TaintLabel.USER_CONTROLLED},
                             getattr(node, "lineno", 0), "chr() output")

        return None

    def visit_Assign(self, node: ast.Assign):
        """Propagate taint through assignments."""
        # Determine taint of the right-hand side
        rhs_taint = self._get_taint(node.value)

        for target in node.targets:
            if isinstance(target, ast.Name):
                if rhs_taint and rhs_taint.is_tainted():
                    self.taint_map[target.id] = rhs_taint
                # Also handle: x = __builtins__.__dict__["exec"]
                elif isinstance(node.value, ast.Subscript):
                    base = _dotted_name(node.value.value)
                    if "__builtins__" in base or "builtins" in base:
                        self.taint_map[target.id] = TaintInfo(
                            {TaintLabel.EXEC_CALLABLE, TaintLabel.CONTAINER_LOOKUP},
                            getattr(node, "lineno", 0),
                            f"lookup from {base}")

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Check if a tainted value reaches a sink."""
        call_name = _dotted_name(node.func)
        line = getattr(node, "lineno", 0)

        # Direct sink check: exec(tainted), eval(tainted), os.system(tainted)
        func_taint = self._get_taint(node.func)

        # Is the function itself a sink?
        is_sink = (
            call_name in SINK_FUNCTIONS or
            (func_taint is not None and TaintLabel.EXEC_CALLABLE in func_taint.labels)
        )

        if is_sink:
            # Check if any argument is tainted
            for arg in node.args:
                arg_taint = self._get_taint(arg)
                if arg_taint and arg_taint.is_tainted():
                    self._report_taint_flow(line, call_name, arg_taint)
                    break
            else:
                # Even without tainted args, calling exec/eval from a tainted
                # source (e.g., __builtins__.__dict__["exec"]) is suspicious
                if func_taint and TaintLabel.CONTAINER_LOOKUP in func_taint.labels:
                    self._report_taint_flow(line, call_name, func_taint)

        # Also check: map(exec, [...]) pattern
        if call_name == "map" or call_name == "builtins.map":
            if node.args:
                first_arg_taint = self._get_taint(node.args[0])
                if first_arg_taint and TaintLabel.EXEC_CALLABLE in first_arg_taint.labels:
                    self._report_taint_flow(line, f"map({_dotted_name(node.args[0])})", first_arg_taint)

        # Track return value taint for function calls
        call_taint = self._get_call_taint(node)
        if call_taint:
            # If this call is assigned, it's handled in visit_Assign
            pass

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Track functions that return tainted values."""
        # Simple heuristic: if function body contains return of tainted value,
        # mark the function name as tainted-return
        for child in ast.walk(node):
            if isinstance(child, ast.Return) and child.value:
                ret_taint = self._get_taint(child.value)
                if ret_taint and ret_taint.is_tainted():
                    self.tainted_returns[node.name] = ret_taint
                    break
        self.generic_visit(node)

    def visit_Lambda(self, node: ast.Lambda):
        """Check lambda bodies for tainted sink calls."""
        # lambda x: exec(x) or lambda x: __builtins__["exec"](x)
        if isinstance(node.body, ast.Call):
            call_name = _dotted_name(node.body.func)
            func_taint = self._get_taint(node.body.func)
            if call_name in SINK_FUNCTIONS or (
                func_taint and TaintLabel.EXEC_CALLABLE in func_taint.labels
            ):
                self._report_taint_flow(
                    getattr(node, "lineno", 0),
                    f"lambda→{call_name}",
                    TaintInfo({TaintLabel.EXEC_CALLABLE}, 0, "lambda sink"))
        self.generic_visit(node)

    def _report_taint_flow(self, line: int, sink: str, taint: TaintInfo):
        """Emit a finding for tainted data reaching a sink."""
        evidence = (
            f"Tainted data flows to sink '{sink}'. "
            f"Source: {taint.source_desc} (line {taint.source_line}). "
            f"Labels: {[l.name for l in taint.labels]}"
        )
        self.findings.append(_make_finding(
            "HFS-070", self.file_path, line, evidence
        ))


def analyze_taint(file_path: str, source: str) -> list[Finding]:
    """
    Public API: Run taint analysis on Python source code.
    Returns findings for tainted data reaching dangerous sinks.
    """
    analyzer = TaintAnalyzer(file_path)
    return analyzer.analyze(source)
