import os
import sys

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
                        # Parse a simple single-line array of scalars, e.g.
                        # ["openai", "meta"] or [1, 2, 3]. Nested/multiline
                        # arrays are not supported by this fallback.
                        inner = v[1:-1].strip()
                        items = []
                        if inner:
                            for item in inner.split(','):
                                item = item.strip().strip('"').strip("'")
                                if not item:
                                    continue
                                if item.isdigit():
                                    items.append(int(item))
                                elif item == "true":
                                    items.append(True)
                                elif item == "false":
                                    items.append(False)
                                else:
                                    items.append(item)
                        v = items
                    current_section[k.strip('"')] = v
            return config
    tomllib = _TomlFallback()

def load_config(path: str = ".hf-scanner.toml") -> dict:
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return tomllib.loads(f.read())
    return {}
