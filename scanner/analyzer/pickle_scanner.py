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

from scanner.models import Finding
from scanner.rules.definitions import get_rule

# Pickle protocol opcodes relevant to security analysis
# See: https://docs.python.org/3/library/pickletools.html
PICKLE_MAGIC = b"\x80"  # Protocol header (protocol 2+)

# Opcodes that can invoke arbitrary callables
OP_REDUCE = b"R"  # Apply callable to args tuple on stack
OP_INST = b"i"  # Instantiate class (protocol 0)
OP_OBJ = b"o"  # Build object (protocol 1)
OP_NEWOBJ = b"\x81"  # type.__new__(type, *args) (protocol 2)
OP_NEWOBJ_EX = b"\x92"  # type.__new__(type, *args, **kwargs) (protocol 4)
OP_STACK_GLOBAL = b"\x93"  # Push global from stack-based module.name (protocol 4)
OP_BUILD = b"b"  # obj.__setstate__(state) - can trigger code via __reduce__

# Opcodes that load globals (modules/functions) by name
OP_GLOBAL = b"c"  # Push module.name global (protocol 0)
OP_SHORT_BINUNICODE = b"\x8c"  # Short binary unicode string
OP_BINUNICODE = b"X"  # Binary unicode string

# Stop opcode
OP_STOP = b"."

# Dangerous modules/functions that should NEVER appear in model files
CRITICAL_CALLABLES = {
    # Direct code execution
    "os.system",
    "os.popen",
    "os.exec",
    "os.execl",
    "os.execle",
    "os.execlp",
    "os.execv",
    "os.execve",
    "os.execvp",
    "os.execvpe",
    "os.spawn",
    "os.spawnl",
    "os.spawnle",
    "os.spawnlp",
    "posix.system",
    "nt.system",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
    "subprocess.run",
    "builtins.exec",
    "builtins.eval",
    "builtins.compile",
    "__builtin__.exec",
    "__builtin__.eval",
    "runpy.run_module",
    "runpy.run_path",
    # Import manipulation
    "builtins.__import__",
    "__builtin__.__import__",
    "importlib.import_module",
    "importlib.__import__",
    # Pickle-specific exploitation gadgets
    "pickle.loads",
    "pickle.load",
    "_pickle.loads",
    "_pickle.load",
    "copyreg._reconstructor",
    # Network access
    "urllib.request.urlopen",
    "urllib.request.urlretrieve",
    "http.client.HTTPConnection",
    "http.client.HTTPSConnection",
    "socket.socket",
    "socket.create_connection",
    "webbrowser.open",
    # File system manipulation
    "shutil.rmtree",
    "shutil.move",
    "shutil.copy",
    "os.remove",
    "os.unlink",
    "os.rmdir",
    "os.makedirs",
    "os.rename",
    "os.chmod",
    "os.chown",
    "io.open",
    "builtins.open",
    "__builtin__.open",
    # ctypes / code loading
    "ctypes.cdll.LoadLibrary",
    "ctypes.CDLL",
    "ctypes.WinDLL",
    "ctypes.windll",
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
    "torch.FloatStorage",
    "torch.LongStorage",
    "torch.IntStorage",
    "torch.DoubleStorage",
    "torch.HalfStorage",
    "torch.BFloat16Storage",
    "torch.ShortStorage",
    "torch.CharStorage",
    "torch.ByteStorage",
    "torch.BoolStorage",
    "torch.ComplexFloatStorage",
    "torch.ComplexDoubleStorage",
    "torch.storage.TypedStorage",
    "torch.storage.UntypedStorage",
    "torch._C.HalfStorageBase",
    "torch._C.FloatStorageBase",
    "collections.OrderedDict",
    "numpy.core.multiarray._reconstruct",
    "numpy._core.multiarray._reconstruct",
    "numpy.ndarray",
    "numpy.dtype",
    "_codecs.encode",
}

# ---------------------------------------------------------------------------
# Expanded RCE-gadget coverage (added after real-data benchmark showed the
# original finite blocklist missed the long tail of import-based gadgets that
# picklescan / the CVE (GHSA) corpus flag). These are stdlib / third-party
# callables that provide arbitrary code, command, or file/network primitives
# on deserialization. None of them legitimately appear in a model *weight*
# pickle, so exact/prefix matching keeps false positives at zero on real
# clean models (verified against gpt2 / bert-base-uncased).
# ---------------------------------------------------------------------------

# Exact-match dangerous callables beyond CRITICAL_CALLABLES.
DANGEROUS_CALLABLES = {
    # runpy / timeit / debuggers / profilers (all execute arbitrary code)
    "runpy._run_code",
    "runpy._run_module_code",
    "timeit.timeit",
    "timeit.repeat",
    "timeit.Timer",
    "trace.Trace.run",
    "trace.Trace.runctx",
    "trace.Trace.runfunc",
    "profile.run",
    "profile.runctx",
    "profile.Profile.run",
    "profile.Profile.runctx",
    "cProfile.run",
    "cProfile.runctx",
    "cProfile.Profile.run",
    "cProfile.Profile.runctx",
    "pstats.Stats",
    "bdb.Bdb",
    "bdb.Bdb.run",
    "bdb.Bdb.runctx",
    "bdb.Bdb.runcall",
    "bdb.Bdb.runeval",
    "pdb.run",
    "pdb.runeval",
    "pdb.runcall",
    "pdb.Pdb.run",
    "pdb.Pdb.runcall",
    "doctest.debug_script",
    "doctest.debug",
    "doctest.testsource",
    "doctest.DebugRunner",
    "code.InteractiveInterpreter.runcode",
    "code.InteractiveInterpreter.runsource",
    "code.InteractiveConsole.interact",
    "code.interact",
    "codeop.compile_command",
    "codeop.CommandCompiler",
    # package / environment execution
    "ensurepip._run_pip",
    "ensurepip.bootstrap",
    "pip.main",
    "pip._internal.main",
    "venv.create",
    "venv.EnvBuilder.create",
    "pkgutil.resolve_name",
    # pydoc gadgets (locate -> import arbitrary; pagers -> shell)
    "pydoc.locate",
    "pydoc.pipepager",
    "pydoc.tempfilepager",
    "pydoc.pager",
    "pydoc.ttypager",
    "pydoc.render_doc",
    "pydoc.safeimport",
    "_pyrepl.pager.pipe_pager",
    # 2to3 grammar loaders execute
    "lib2to3.pgen2.grammar.Grammar.loads",
    "lib2to3.pgen2.pgen.ParserGenerator.make_label",
    # pty / tty shells
    "pty.spawn",
    "pty.fork",
    # stdlib command-output helpers
    "uuid._get_command_stdout",
    "_osx_support._read_output",
    "_osx_support.compiler_fixup",
    "_aix_support._read_cmd_output",
    "platform._syscmd_ver",
    "platform.popen",
    "getpass.getpass",
    # operators used to chain gadgets
    "operator.methodcaller",
    "operator.attrgetter",
    "operator.itemgetter",
    "_operator.methodcaller",
    "_operator.attrgetter",
    "_operator.itemgetter",
    "functools.partial",
    "functools.reduce",
    # dynamic code objects
    "types.CodeType",
    "types.FunctionType",
    "marshal.loads",
    "marshal.load",
    # file / library / network primitives
    "_io.FileIO",
    "io.FileIO",
    "io.open_code",
    "logging.FileHandler",
    "logging.config.fileConfig",
    "logging.config.listen",
    "ctypes.WinDLL",
    "ctypes.PyDLL",
    "ctypes.util.find_library",
    "ctypes.cdll",
    "ctypes.windll",
    "ctypes.CDLL",
    "ssl.get_server_certificate",
    "socket.create_connection",
    "asyncio.unix_events._UnixSubprocessTransport._start",
    "distutils.file_util.write_file",
    "distutils.spawn.spawn",
    "numpy.f2py.crackfortran.getlincoef",
    "numpy.testing._private.utils.runstring",
    "numpy.distutils.exec_command.exec_command",
    # deserialization re-entry
    "dill.loads",
    "dill.load",
    "joblib.load",
    "shelve.open",
    # torch gadgets (specific — the torch namespace is otherwise allowlisted)
    "torch.utils.bottleneck.__main__.run_cprofile",
    "torch.utils.bottleneck.__main__.run_autograd_prof",
    "torch.utils.collect_env.run",
    "torch.utils.collect_env.run_and_read_all",
    "torch.jit.unsupported_tensor_ops.execWrapper",
    "torch._inductor.codecache.compile_file",
    "torch.serialization.load",
    "torch.utils._config_module.ConfigModule.load_config",
    "torch.utils.data.datapipes.utils.decoder.basichandlers",
    "torch.fx.experimental.symbolic_shapes.ShapeEnv.evaluate_guards_expression",
    "test.support.script_helper.assert_python_ok",
    # cloudpickle reconstruction primitives
    "cloudpickle.cloudpickle._make_function",
    "cloudpickle.cloudpickle._builtin_type",
    "cloudpickle.cloudpickle._function_setstate",
    "cloudpickle.cloudpickle.subimport",
    "cloudpickle.cloudpickle._make_cell",
    "cloudpickle.cloudpickle._make_empty_cell",
    "cloudpickle.cloudpickle._make_skeleton_class",
}

# Modules where ANY imported name is dangerous in a model artifact. These
# modules never legitimately appear in serialized model weights, so a whole-
# module prefix match is safe (no FP on real models).
DANGEROUS_MODULE_PREFIXES = (
    "idlelib.",
    "lib2to3.",
    "pty.",
    "pdb.",
    "bdb.",
    "profile.",
    "cProfile.",
    "pstats.",
    "trace.",
    "timeit.",
    "doctest.",
    "code.",
    "codeop.",
    "ensurepip.",
    "pip.",
    "venv.",
    "pydoc.",
    "_pyrepl.",
    "imaplib.",
    "ftplib.",
    "telnetlib.",
    "smtplib.",
    "poplib.",
    "nntplib.",
    "socket.",
    "socketserver.",
    "asyncio.",
    "multiprocessing.",
    "concurrent.futures.",
    "xmlrpc.",
    "http.",
    "httplib.",
    "urllib.",
    "urllib2.",
    "requests.",
    "aiohttp.",
    "ssl.",
    "cloudpickle.",
    "distutils.",
    "setuptools.",
    "_distutils_hack.",
    "_osx_support.",
    "_aix_support.",
    "getpass.",
    "test.support.",
    "dill.",
    "smtpd.",
    "wsgiref.",
    "cgi.",
    "cgitb.",
)

# Dangerous *method/attribute* names — matched on the final component of a
# global's qualified name. Catches gadget classes in otherwise-allowlisted
# namespaces (e.g. torch.*) without prefix-flagging the whole namespace.
DANGEROUS_METHOD_NAMES = {
    "system",
    "popen",
    "spawn",
    "spawnl",
    "spawnle",
    "spawnlp",
    "spawnv",
    "spawnve",
    "spawnvp",
    "fork",
    "forkpty",
    "exec",
    "execv",
    "execve",
    "execl",
    "execle",
    "execlp",
    "execvp",
    "execWrapper",
    "run",
    "runctx",
    "runcode",
    "runsource",
    "runcall",
    "runeval",
    "runfunc",
    "_run_code",
    "_run_module_code",
    "run_cprofile",
    "run_autograd_prof",
    "run_and_read_all",
    "runstring",
    "_run_pip",
    "compile_file",
    "compile_command",
    "load_config",
    "evaluate_guards_expression",
    "locate",
    "pipepager",
    "pipe_pager",
    "resolve_name",
    "safeimport",
    "_get_command_stdout",
    "_read_output",
    "_read_cmd_output",
    "get_server_certificate",
    "basichandlers",
    "assert_python_ok",
    "make_label",
    "debug_script",
    "getlincoef",
    "exec_command",
}


def _is_dangerous_global(normalized: str) -> tuple[bool, str]:
    """Return (is_dangerous, reason) for a discovered global, honoring the
    safe allowlist first so legitimate torch/numpy reconstruction is never
    flagged."""
    if normalized in SAFE_ALLOWLIST:
        return False, ""
    if normalized in CRITICAL_CALLABLES or normalized in DANGEROUS_CALLABLES:
        return True, f"dangerous callable: {normalized}"
    if any(
        normalized.startswith(p)
        for p in (
            "os.",
            "subprocess.",
            "builtins.",
            "__builtin__.",
            "nt.",
            "posix.",
            "ctypes.",
            "shutil.",
            "webbrowser.",
            "runpy.",
            "importlib.",
        )
    ) or any(normalized.startswith(p) for p in DANGEROUS_MODULE_PREFIXES):
        return True, f"dangerous module access: {normalized}"
    last = normalized.rsplit(".", 1)[-1]
    if last in DANGEROUS_METHOD_NAMES:
        return True, f"dangerous gadget method: {normalized}"
    return False, ""


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
    """Read a newline-terminated string (protocol 0 GLOBAL/INST).

    Strips a trailing carriage return so that CRLF-terminated pickles do not
    evade detection: without this, ``builtins\\r\\neval\\r\\n`` parses as the
    global ``builtins\\r.eval\\r`` and matches no callable rule. CRLF line
    endings were a real scanner-evasion vector.
    """
    end = data.index(b"\n", pos)
    raw = data[pos:end]
    if raw.endswith(b"\r"):
        raw = raw[:-1]
    return raw.decode("ascii", errors="replace"), end + 1


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
                self.findings.append(
                    _make_finding(
                        "HFS-052",
                        self.file_path,
                        f"Corrupted pickle with {len(self.globals_found)} globals parsed before error: {self.globals_found[:5]}",
                    )
                )

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

            op = data[self.pos : self.pos + 1]
            self.pos += 1

            if op == OP_STOP:
                self.string_stack.clear()
                if self.pos < length:
                    continue
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
                s = data[self.pos : self.pos + str_len].decode(
                    "utf-8", errors="replace"
                )
                self.pos += str_len
                self.string_stack.append(s)
            elif op == OP_BINUNICODE:
                # "X" opcode: 4-byte length + string
                str_len, self.pos = _read_uint4(data, self.pos)
                if str_len > 10_000_000:  # Safety limit
                    break
                s = data[self.pos : self.pos + str_len].decode(
                    "utf-8", errors="replace"
                )
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
            elif op in (
                b"(",
                b")",
                b"l",
                b"d",
                b"t",
                b"}",
                b"]",
                b"\x85",
                b"\x86",
                b"\x87",
                b"\x90",
                b"\x91",
                b"0",
                b"1",
                b"2",
                b"a",
                b"e",
                b"s",
                b"u",
            ):
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
        seen: set[str] = set()
        for global_name in self.globals_found:
            normalized = global_name.strip()
            if normalized in seen:
                continue
            seen.add(normalized)

            is_danger, reason = _is_dangerous_global(normalized)
            if is_danger:
                self.findings.append(
                    _make_finding(
                        "HFS-050",
                        self.file_path,
                        f"CRITICAL callable in pickle: {reason}",
                    )
                )
            elif (
                normalized in SUSPICIOUS_CALLABLES and normalized not in SAFE_ALLOWLIST
            ):
                self.findings.append(
                    _make_finding(
                        "HFS-051",
                        self.file_path,
                        f"Suspicious callable in pickle: {normalized}",
                    )
                )
            # Check for bypass patterns in global names
            for pattern in BYPASS_PATTERNS:
                if pattern in normalized:
                    self.findings.append(
                        _make_finding(
                            "HFS-052",
                            self.file_path,
                            f"Known PickleScan bypass pattern: {pattern} in {normalized}",
                        )
                    )

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
            self.findings.append(
                _make_finding(
                    "HFS-051",
                    self.file_path,
                    f"{self.reduces_found} REDUCE ops with no recognizable globals — possible obfuscation",
                )
            )


def is_pickle_file(file_path: str) -> bool:
    """Check if file extension indicates a pickle-serialized model.

    ``.zip`` is included because PyTorch/joblib checkpoints and many malicious
    payloads wrap pickle streams inside a ZIP container; without this the ZIP
    unpacking path below was dead code for plain ``.zip`` files.
    """
    lower = file_path.lower()
    return lower.endswith(
        (
            ".pkl",
            ".pickle",
            ".pt",
            ".pth",
            ".bin",
            ".ckpt",
            ".joblib",
            ".zip",
            ".npy",
            ".npz",
            ".dill",
            ".model",
        )
    )


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
    """Extract and scan pickle entries from ZIP archives (PyTorch .pt/.bin,
    joblib, or malicious .zip payloads).

    Scans every archive member that either has a pickle-like extension OR whose
    leading bytes look like a pickle stream — malicious archives frequently
    store the payload under an innocuous name (e.g. ``archive/data.pkl`` or a
    bare name with no extension)."""
    import zipfile

    findings: list[Finding] = []

    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
            for name in zf.namelist():
                lower_name = name.lower()
                try:
                    pkl_data = zf.read(name)
                except Exception:
                    continue
                looks_pickle = (
                    lower_name.endswith((".pkl", ".pickle", ".data", ".dat"))
                    or "data.pkl" in lower_name
                    or (pkl_data[:1] == PICKLE_MAGIC)
                    or _looks_like_pickle(pkl_data)
                )
                if not looks_pickle:
                    continue
                try:
                    inner_path = f"{file_path}!{name}"
                    scanner = PickleScanner(inner_path, pkl_data)
                    inner_findings = scanner.scan()
                    for f in inner_findings:
                        f.file_path = file_path
                        f.evidence = f"[ZIP:{name}] {f.evidence}"
                    findings.extend(inner_findings)
                except Exception:
                    continue
    except zipfile.BadZipFile:
        # Not a valid ZIP — might be a raw pickle whose content happens to
        # start with "PK"; fall back to direct scan.
        scanner = PickleScanner(file_path, data)
        findings.extend(scanner.scan())

    return findings


def analyze_pickle_file(file_path: str, data: bytes) -> list[Finding]:
    """Public API: scan a binary file for pickle deserialization attacks."""
    if not is_pickle_file(file_path):
        return []
    return scan_pickle_bytes(file_path, data)
