import os

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
                if not line or line.startswith('#'):
                    continue
                if line.startswith('[') and line.endswith(']'):
                    section_name = line[1:-1]
                    parts = section_name.split('.')
                    curr = config
                    for p in parts:
                        if p not in curr:
                            curr[p] = {}
                        curr = curr[p]
                    current_section = curr
                elif '=' in line:
                    k, v = line.split('=', 1)
                    k = k.strip()
                    v = v.strip().strip('"').strip("'")
                    # simple type coercion
                    if v.isdigit():
                        v = int(v)
                    elif v == "true":
                        v = True
                    elif v == "false":
                        v = False
                    elif v.startswith('[') and v.endswith(']'):
                        v = [] # lists not fully supported in fallback
                    current_section[k.strip('"')] = v
            return config
    tomllib = _TomlFallback()

def load_config(path: str = ".hf-scanner.toml") -> dict:
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return tomllib.loads(f.read())
    return {}
