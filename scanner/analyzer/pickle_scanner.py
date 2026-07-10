"""
Pickle Opcode Scanner — Zero-dependency binary analysis of pickle files.

Parses pickle bytecode WITHOUT executing it, detecting dangerous opcodes that
invoke arbitrary functions (REDUCE, INST, OBJ, NEWOBJ, STACK_GLOBAL, BUILD).

This catches the #1 attack vector in ML supply chains: pickle deserialization
payloads embedded in .pkl, .pt, .pth, .bin model files.

References:
- Python pickletools module (stdlib) for opcode definitions
- JFrog PickleScan bypass research (2025-2026)
- MITRE ATLAS AML.T0010 (AI Supply Chain Compromise)
"""

import io
import struct
import os
from typing import Optional

from scanner.models import Finding
from scanner.rules.definitions import get_rule

# Pickle protocol opcodes relevant to security analysis
# See: https://docs.python.org/3/library/pickletools.html
PICKLE_MAGIC = b"\x80"  # Protocol header (protocol 2+)

# Opcodes that can invoke arbitrary callables
OP_REDUCE = b"R"        # Apply callable to args tuple on stack
OP_INST = b"i"          # Instantiate class (protocol 0)
OP_OBJ = b"o"           # Build object (protocol 1)
OP_NEWOBJ = b"\x81"     # type.__new__(type, *args) (protocol 2)
OP_NEWOBJ_EX = b"\x92"  # type.__new__(type, *args, **kwargs) (protocol 4)
OP_STACK_GLOBAL = b"\x93"  # Push global from stack-based module.name (protocol 4)
OP_BUILD = b"b"         # obj.__setstate__(state) - can trigger code via __reduce__

# Opcodes that load globals (modules/functions) by name
OP_GLOBAL = b"c"        # Push module.name global (protocol 0)
OP_SHORT_BINUNICODE = b"\x8c"  # Short binary unicode string
OP_BINUNICODE = b"X"    # Binary unicode string

# Stop opcode
OP_STOP = b"."

# Dangerous modules/functions that should NEVER appear in model files
CRITICAL_CALLABLES = {
    # Direct code execution
    "os.system", "os.popen", "os.exec", "os.execl", "os.execle",
    "os.execlp", "os.execv", "os.execve", "os.execvp", "os.execvpe",
    "os.spawn", "os.spawnl", "os.spawnle", "os.spawnlp",
    "posix.system", "nt.system",
    "subprocess.call", "subprocess.check_call", "subprocess.check_output",
    "subprocess.Popen", "subprocess.run",
    "builtins.exec", "builtins.eval", "builtins.compile",
    "__builtin__.exec", "__builtin__.eval",
    "runpy.run_module", "runpy.run_path",
    # Import manipulation
    "builtins.__import__", "__builtin__.__import__",
    "importlib.import_module", "importlib.__import__",
    # Pickle-specific exploitation gadgets
    "pickle.loads", "pickle.load",
    "_pickle.loads", "_pickle.load",
    "copyreg._reconstructor",
    # Network access
    "urllib.request.urlopen", "urllib.request.urlretrieve",
    "http.client.HTTPConnection", "http.client.HTTPSConnection",
    "socket.socket", "socket.create_connection",
    "webbrowser.open",
    # File system manipulation
    "shutil.rmtree", "shutil.move", "shutil.copy",
    "os.remove", "os.unlink", "os.rmdir", "os.makedirs",
    "os.rename", "os.chmod", "os.chown",
    "io.open", "builtins.open", "__builtin__.open",
    # ctypes / code loading
    "ctypes.cdll.LoadLibrary", "ctypes.CDLL",
    "ctypes.WinDLL", "ctypes.windll",
}

# Suspicious but not immediately critical — require context
SUSPICIOUS_CALLABLES = {
    "collections.OrderedDict",  # Often benign in torch, but used in gadget chains
    "torch._utils._rebuild_tensor_v2",  # Legitimate but can be abused
    "numpy.core.multiarray._reconstruct",  # Legitimate numpy
    "numpy.ndarray",
    "_codecs.encode",  # Sometimes used for obfuscation
    "codecs.encode",
}

# Known PickleScan bypass techniques
BYPASS_PATTERNS = {
    # Using __reduce_ex__ instead of __reduce__
    "__reduce_ex__",
    # Overriding __setstate__ for BUILD opcode exploitation
    "__setstate__",
    # Using copyreg dispatch_table manipulation
    "copyreg.dispatch_table",
    "copyreg.pickle",
    # Abusing persistent_load
    "persistent_load",
}

# Legitimate torch/numpy reconstruction functions (allowlist)
SAFE_ALLOWLIST = {
    "torch._utils._rebuild_tensor_v2",
    "torch._utils._rebuild_parameter",
    "torch._utils._rebuild_parameter_with_state",
    "torch.storage._load_from_bytes",
    "torch.FloatStorage", "torch.LongStorage", "torch.IntStorage",
    "torch.DoubleStorage", "torch.HalfStorage", "torch.BFloat16Storage",
    "torch.ShortStorage", "torch.CharStorage", "torch.ByteStorage",
    "torch.BoolStorage", "torch.ComplexFloatStorage", "torch.ComplexDoubleStorage",
    "torch.storage.TypedStorage", "torch.storage.UntypedStorage",
    "torch._C.HalfStorageBase", "torch._C.FloatStorageBase",
    "collections.OrderedDict",
    "numpy.core.multiarray._reconstruct",
    "numpy.ndarray", "numpy.dtype",
    "_codecs.encode",
}


def _make_finding(rule_id: str, file_path: str, evidence: str) -> Finding:
    rule = get_rule(rule_id)
    return Finding(
        rule_id=rule_id,
        severity=rule.severity,
        file_path=file_path,
        line_number=0,
        column=0,
        message=rule.description,
        evidence=evidence[:300],
        remediation=rule.remediation,
        cwe=rule.cwe,
    )


def _read_string_nl(data: bytes, pos: int) -> tuple[str, int]:
    """Read a newline-terminated string (protocol 0 GLOBAL/INST)."""
    end = data.index(b"\n", pos)
    return data[pos:end].decode("ascii", errors="replace"), end + 1


def _read_uint1(data: bytes, pos: int) -> tuple[int, int]:
    return data[pos], pos + 1


def _read_uint2(data: bytes, pos: int) -> tuple[int, int]:
    return struct.unpack_from("<H", data, pos)[0], pos + 2


def _read_uint4(data: bytes, pos: int) -> tuple[int, int]:
    return struct.unpack_from("<I", data, pos)[0], pos + 4


def _read_int4(data: bytes, pos: int) -> tuple[int, int]:
    return struct.unpack_from("<i", data, pos)[0], pos + 4


def _read_uint8(data: bytes, pos: int) -> tuple[int, int]:
    return struct.unpack_from("<Q", data, pos)[0], pos + 8


class PickleScanner:
    """
    Zero-execution pickle bytecode scanner.
    
    Parses opcodes sequentially, tracking the string stack to identify
    what functions are being called via REDUCE/INST/OBJ/NEWOBJ.
    """

    def __init__(self, file_path: str, data: bytes):
        self.file_path = file_path
        self.data = data
        self.pos = 0
        self.findings: list[Finding] = []
        self.globals_found: list[str] = []
        self.reduces_found: int = 0
        self.string_stack: list[str] = []
        self.protocol = 0

    def scan(self) -> list[Finding]:
        """Main scan entry point."""
        if not self.data:
            return []

        # Detect pickle protocol version
        if self.data[0:1] == PICKLE_MAGIC and len(self.data) > 1:
            self.protocol = self.data[1]
            self.pos = 2
        else:
            self.protocol = 0
            self.pos = 0

        try:
            self._parse_opcodes()
        except (IndexError, struct.error, ValueError):
            # Intentionally corrupted pickle — this itself is suspicious
            # (PickleScan bypass: malware executes before full deserialization)
            if self.globals_found:
                self.findings.append(_make_finding(
                    "HFS-052", self.file_path,
                    f"Corrupted pickle with {len(self.globals_found)} globals parsed before error: {self.globals_found[:5]}"
                ))

        # Post-scan analysis
        self._analyze_globals()
        self._check_reduce_count()
        return self.findings

    def _parse_opcodes(self):
        """Walk through pickle opcodes without executing."""
        data = self.data
        length = len(data)
        max_iterations = 1_000_000  # Safety limit

        for _ in range(max_iterations):
            if self.pos >= length:
                break

            op = data[self.pos:self.pos + 1]
            self.pos += 1

            if op == OP_STOP:
                break
            elif op == OP_GLOBAL:
                # "c" opcode: read module\nname\n
                module, self.pos = _read_string_nl(data, self.pos)
                name, self.pos = _read_string_nl(data, self.pos)
                full_name = f"{module}.{name}"
                self.globals_found.append(full_name)
                self.string_stack.append(full_name)
            elif op == OP_STACK_GLOBAL:
                # "\x93" opcode: pop name, pop module from stack
                if len(self.string_stack) >= 2:
                    name = self.string_stack.pop()
                    module = self.string_stack.pop()
                    full_name = f"{module}.{name}"
                    self.globals_found.append(full_name)
                    self.string_stack.append(full_name)
            elif op == OP_INST:
                # "i" opcode: read module\nname\n (protocol 0)
                module, self.pos = _read_string_nl(data, self.pos)
                name, self.pos = _read_string_nl(data, self.pos)
                full_name = f"{module}.{name}"
                self.globals_found.append(full_name)
                self.reduces_found += 1
            elif op in (OP_REDUCE, OP_OBJ, OP_NEWOBJ, OP_NEWOBJ_EX):
                self.reduces_found += 1
            elif op == OP_BUILD:
                # BUILD can trigger __setstate__ which is exploitable
                self.reduces_found += 1
            elif op == OP_SHORT_BINUNICODE:
                # "\x8c" opcode: 1-byte length + string
                str_len, self.pos = _read_uint1(data, self.pos)
                s = data[self.pos:self.pos + str_len].decode("utf-8", errors="replace")
                self.pos += str_len
                self.string_stack.append(s)
            elif op == OP_BINUNICODE:
                # "X" opcode: 4-byte length + string
                str_len, self.pos = _read_uint4(data, self.pos)
                if str_len > 10_000_000:  # Safety limit
                    break
                s = data[self.pos:self.pos + str_len].decode("utf-8", errors="replace")
                self.pos += str_len
                self.string_stack.append(s)
            elif op == b"S":
                # String literal (protocol 0) - read until \n
                s, self.pos = _read_string_nl(data, self.pos)
                # Strip quotes
                s = s.strip("'\"")
                self.string_stack.append(s)
            elif op == b"V":
                # Unicode string (protocol 0)
                s, self.pos = _read_string_nl(data, self.pos)
                self.string_stack.append(s)
            elif op == b"T":
                # 4-byte length binary string
                str_len, self.pos = _read_uint4(data, self.pos)
                if str_len > 10_000_000:
                    break
                self.pos += str_len
            elif op == b"U":
                # 1-byte length binary string
                str_len, self.pos = _read_uint1(data, self.pos)
                self.pos += str_len
            elif op == b"B":
                # BINBYTES (4-byte length)
                str_len, self.pos = _read_uint4(data, self.pos)
                if str_len > 10_000_000:
                    break
                self.pos += str_len
            elif op == b"C":
                # SHORT_BINBYTES (1-byte length)
                str_len, self.pos = _read_uint1(data, self.pos)
                self.pos += str_len
            elif op == b"\x8e":
                # BINBYTES8 (8-byte length)
                str_len, self.pos = _read_uint8(data, self.pos)
                if str_len > 100_000_000:
                    break
                self.pos += str_len
            elif op == b"\x8d":
                # BINUNICODE8 (8-byte length)
                str_len, self.pos = _read_uint8(data, self.pos)
                if str_len > 100_000_000:
                    break
                self.pos += str_len
            elif op == b"G":
                # BINFLOAT (8 bytes)
                self.pos += 8
            elif op == b"J":
                # BININT (4 bytes)
                self.pos += 4
            elif op == b"K":
                # BININT1 (1 byte)
                self.pos += 1
            elif op == b"M":
                # BININT2 (2 bytes)
                self.pos += 2
            elif op == b"N":
                # NONE
                pass
            elif op == b"\x88":
                # NEWTRUE
                pass
            elif op == b"\x89":
                # NEWFALSE
                pass
            elif op == b"\x95":
                # FRAME (8-byte frame length, protocol 4)
                self.pos += 8
            elif op == b"\x94":
                # MEMOIZE (protocol 4)
                pass
            elif op == b"p":
                # PUT (protocol 0)
                _, self.pos = _read_string_nl(data, self.pos)
            elif op == b"q":
                # BINPUT (1-byte index)
                self.pos += 1
            elif op == b"r":
                # LONG_BINPUT (4-byte index)
                self.pos += 4
            elif op == b"g":
                # GET (protocol 0)
                _, self.pos = _read_string_nl(data, self.pos)
            elif op == b"h":
                # BINGET (1-byte index)
                self.pos += 1
            elif op == b"j":
                # LONG_BINGET (4-byte index)
                self.pos += 4
            elif op in (b"(", b")", b"l", b"d", b"t", b"}", b"]",
                        b"\x85", b"\x86", b"\x87", b"\x90", b"\x91",
                        b"0", b"1", b"2", b"a", b"e", b"s", b"u"):
                # Stack manipulation and collection opcodes — no payload
                pass
            elif op == b"I":
                # INT (protocol 0) - read until \n
                _, self.pos = _read_string_nl(data, self.pos)
            elif op == b"L":
                # LONG (protocol 0) - read until \n
                _, self.pos = _read_string_nl(data, self.pos)
            elif op == b"F":
                # FLOAT (protocol 0) - read until \n
                _, self.pos = _read_string_nl(data, self.pos)
            elif op == b"\x8a":
                # LONG1 (1-byte length + data)
                n, self.pos = _read_uint1(data, self.pos)
                self.pos += n
            elif op == b"\x8b":
                # LONG4 (4-byte length + data)
                n, self.pos = _read_int4(data, self.pos)
                self.pos += max(0, n)
            elif op == PICKLE_MAGIC:
                # Nested protocol header
                self.pos += 1  # Skip version byte
            else:
                # Unknown opcode - skip conservatively
                pass

    def _analyze_globals(self):
        """Classify discovered globals into critical/suspicious/safe."""
        for global_name in self.globals_found:
            normalized = global_name.strip()

            # Check critical callables
            if normalized in CRITICAL_CALLABLES:
                self.findings.append(_make_finding(
                    "HFS-050", self.file_path,
                    f"CRITICAL callable in pickle: {normalized}"
                ))
            elif any(normalized.startswith(prefix) for prefix in (
                "os.", "subprocess.", "builtins.", "__builtin__.",
                "nt.", "posix.", "ctypes.", "shutil.", "webbrowser.",
                "runpy.", "importlib.",
            )):
                # Broader check — anything in these modules is suspicious
                if normalized not in SAFE_ALLOWLIST:
                    self.findings.append(_make_finding(
                        "HFS-050", self.file_path,
                        f"Dangerous module access in pickle: {normalized}"
                    ))
            elif normalized in SUSPICIOUS_CALLABLES and normalized not in SAFE_ALLOWLIST:
                self.findings.append(_make_finding(
                    "HFS-051", self.file_path,
                    f"Suspicious callable in pickle: {normalized}"
                ))
            # Check for bypass patterns in global names
            for pattern in BYPASS_PATTERNS:
                if pattern in normalized:
                    self.findings.append(_make_finding(
                        "HFS-052", self.file_path,
                        f"Known PickleScan bypass pattern: {pattern} in {normalized}"
                    ))

    def _check_reduce_count(self):
        """Flag excessive REDUCE operations (indicator of gadget chains)."""
        # Legitimate torch models typically have many REDUCEs for tensor reconstruction
        # but extremely high counts with non-allowlisted globals are suspicious
        dangerous_globals = [g for g in self.globals_found if g not in SAFE_ALLOWLIST]
        if dangerous_globals and self.reduces_found > 0:
            # Already flagged by _analyze_globals, but add context
            pass
        elif self.reduces_found > 100 and not self.globals_found:
            # Many REDUCEs but no parseable globals — possibly obfuscated
            self.findings.append(_make_finding(
                "HFS-051", self.file_path,
                f"{self.reduces_found} REDUCE ops with no recognizable globals — possible obfuscation"
            ))


def is_pickle_file(file_path: str) -> bool:
    """Check if file extension indicates a pickle-serialized model."""
    lower = file_path.lower()
    return lower.endswith((".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt", ".joblib"))


def scan_pickle_bytes(file_path: str, data: bytes) -> list[Finding]:
    """
    Scan raw bytes of a pickle file for malicious opcodes.
    
    Handles:
    - Standard pickle files
    - PyTorch files (ZIP containing data.pkl)
    - Concatenated pickles (multiple STOP opcodes)
    """
    findings: list[Finding] = []

    # Check if it's a ZIP file (PyTorch .pt format)
    if data[:2] == b"PK":
        findings.extend(_scan_pytorch_zip(file_path, data))
    elif data[:1] == PICKLE_MAGIC or _looks_like_pickle(data):
        # Direct pickle file
        scanner = PickleScanner(file_path, data)
        findings.extend(scanner.scan())
    else:
        # Try scanning anyway — some pickle files have no magic
        # Search for pickle opcodes in the first 1MB
        scan_window = data[:1_048_576]
        if OP_GLOBAL in scan_window or OP_STACK_GLOBAL in scan_window:
            scanner = PickleScanner(file_path, data)
            findings.extend(scanner.scan())

    return findings


def _looks_like_pickle(data: bytes) -> bool:
    """Heuristic: does this look like it could be a pickle stream?"""
    if not data:
        return False
    # Protocol 0 pickles start with various opcodes
    first_byte = data[0:1]
    return first_byte in (b"(", b"c", b"l", b"d", b"I", b"S", b"F", b"N", PICKLE_MAGIC)


def _scan_pytorch_zip(file_path: str, data: bytes) -> list[Finding]:
    """Extract and scan pickle entries from PyTorch ZIP archives."""
    import zipfile
    findings: list[Finding] = []

    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
            for name in zf.namelist():
                lower_name = name.lower()
                # PyTorch stores pickled data in data.pkl or similar
                if lower_name.endswith((".pkl", ".pickle")) or "data.pkl" in lower_name:
                    try:
                        pkl_data = zf.read(name)
                        inner_path = f"{file_path}!{name}"
                        scanner = PickleScanner(inner_path, pkl_data)
                        inner_findings = scanner.scan()
                        # Re-attribute findings to the outer file
                        for f in inner_findings:
                            f.file_path = file_path
                            f.evidence = f"[ZIP:{name}] {f.evidence}"
                        findings.extend(inner_findings)
                    except Exception:
                        pass
    except (zipfile.BadZipFile, Exception):
        # Not a valid ZIP — might be raw pickle with PK in content
        scanner = PickleScanner(file_path, data)
        findings.extend(scanner.scan())

    return findings


def analyze_pickle_file(file_path: str, data: bytes) -> list[Finding]:
    """Public API: scan a binary file for pickle deserialization attacks."""
    if not is_pickle_file(file_path):
        return []
    return scan_pickle_bytes(file_path, data)
