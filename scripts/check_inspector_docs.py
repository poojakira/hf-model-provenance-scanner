"""Bounded freshness checks for current inspector docs; historical facts remain unverified."""

import re
from pathlib import Path

import tomllib

from scanner.cli import SCANNER_VERSION

ROOT = Path(__file__).resolve().parents[1]
CURRENT = [
    "README.md",
    "SECURITY.md",
    "CHANGELOG.md",
    "docs/INSPECTOR.md",
    "docs/TESTING.md",
    "docs/EVIDENCE.md",
]


def main():
    package = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert SCANNER_VERSION == package["project"]["version"] == "0.3.0"
    for name in CURRENT:
        path = ROOT / name
        body = path.read_text()
        for marker in ("<<<<<<<", ">>>>>>>", "TODO: FILL", "TBD_METRIC"):
            assert marker not in body, (name, marker)
        for target in re.findall(r"\[[^\]]*\]\(([^)]+)\)", body):
            if "://" in target or target.startswith("#"):
                continue
            assert (path.parent / target.split("#")[0]).is_file(), (name, target)
    readme = (ROOT / "README.md").read_text()
    assert "PARTIAL" in readme and "8763" in readme and "33/33" not in readme
    assert "1.0.0" in readme and "0.3.0" in readme
    print(
        "Current inspector version, local links and required limitation markers verified; historical claims/external links NOT VERIFIED"
    )


if __name__ == "__main__":
    main()
