import os

# ---------------------------------------------------------------------------
# Security limits — authoritative constants for the entire scanner.
# Import these from scanner.config rather than hard-coding in individual modules.
# ---------------------------------------------------------------------------

#: Maximum size of any non-binary source file to read into memory.
MAX_FILE_SIZE_BYTES: int = 500 * 1024 * 1024  # 500 MB

#: Maximum size of a pickle/model file to pass to the opcode scanner.
#: Files larger than this are rejected with a HFS-098 size-limit finding.
MAX_PICKLE_SIZE_BYTES: int = 100 * 1024 * 1024  # 100 MB

#: Maximum number of members to process from a single ZIP/PyTorch archive.
#: Protects against zip-bomb style resource exhaustion.
MAX_ARCHIVE_MEMBERS: int = 1000

#: Per-request network timeout when downloading files from Hugging Face.
#: The value applies to urllib.request.urlopen(timeout=...) calls.
DOWNLOAD_TIMEOUT_SECONDS: int = 300

try:
    import tomllib
except ImportError:
    # Python 3.10 fallback
    class _TomlFallback:
        def loads(self, s):
            # Extremely naive fallback just to keep it zero-dependency
            # In a real tool we'd bundle a tiny toml parser if tomllib is missing.
            # For this MVP, we parse very simple TOML.
            config = {}
            current_section = config
            for line in s.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("[") and line.endswith("]"):
                    section_name = line[1:-1]
                    parts = section_name.split(".")
                    curr = config
                    for p in parts:
                        if p not in curr:
                            curr[p] = {}
                        curr = curr[p]
                    current_section = curr
                elif "=" in line:
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip('"').strip("'")
                    # simple type coercion
                    if v.isdigit():
                        v = int(v)
                    elif v == "true":
                        v = True
                    elif v == "false":
                        v = False
                    elif v.startswith("[") and v.endswith("]"):
                        items = v[1:-1].strip()
                        v = [
                            item.strip().strip('"').strip("'")
                            for item in items.split(",")
                            if item.strip()
                        ]
                    current_section[k.strip('"')] = v
            return config

    tomllib = _TomlFallback()


def load_config(path: str = ".hf-scanner.toml") -> dict:
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return tomllib.loads(f.read())
    return {}
