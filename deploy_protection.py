"""Fail-closed model deployment admission gate.

This compatibility entry point deliberately performs one production function:
scan a local model artifact directory before deployment and return success only
when the scanner completed fully, produced no configured blocking finding, and
reported no scan error.

It does NOT claim to isolate a running inference process, quarantine artifacts,
page an operator, or ship events to a SIEM. Runtime containment belongs to the
deployment platform (for example Kubernetes admission policy, sandboxing,
network policy, and workload identity), not to print-only hooks in this script.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from scanner.cli import main as cli_main


class ProtectedModelServer:
    """Backward-compatible name for the fail-closed model admission coordinator."""

    def __init__(self, model_path: str, config: dict | None = None) -> None:
        self.model_path = model_path
        self.config = config or {}
        self.model_hash = self._compute_model_hash()

    def _compute_model_hash(self) -> str:
        """Hash all security-relevant model artifacts in deterministic path order."""
        root = Path(self.model_path)
        if not root.exists():
            raise ValueError(f"model path does not exist: {root}")

        hasher = hashlib.sha256()
        matched = 0
        extensions = {
            ".bin",
            ".safetensors",
            ".gguf",
            ".onnx",
            ".pt",
            ".pth",
            ".pkl",
            ".pickle",
            ".py",
            ".json",
            ".yaml",
            ".yml",
            ".toml",
        }

        for path in sorted(p for p in root.rglob("*") if p.is_file()):
            if path.suffix.lower() not in extensions:
                continue
            matched += 1
            rel = path.relative_to(root).as_posix().encode("utf-8")
            hasher.update(len(rel).to_bytes(8, "big"))
            hasher.update(rel)
            try:
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        hasher.update(chunk)
            except OSError as exc:
                raise RuntimeError(f"unable to hash model artifact {path}: {exc}") from exc

        if matched == 0:
            raise ValueError("model path contains no supported model/config artifacts")
        return hasher.hexdigest()

    def static_scan(self) -> dict[str, object]:
        """Run the real scanner in fail-closed local admission mode."""
        args = [
            self.model_path,
            "--mode",
            "local",
            "--format",
            "json",
            "--fail-on",
            str(self.config.get("fail_on", "high")),
            "--enforce",
        ]

        stdout = io.StringIO()
        stderr = io.StringIO()
        try:
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = cli_main(args)
            payload = stdout.getvalue().strip()
            if not payload:
                raise ValueError(f"scanner produced no JSON output: {stderr.getvalue().strip()}")
            result = json.loads(payload)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return {
                "exit_code": 2,
                "approved": False,
                "completeness": "INDETERMINATE",
                "error": str(exc),
                "model_sha256": self.model_hash,
                "findings": [],
                "risk_score": 100,
                "risk_level": "UNKNOWN",
            }

        completeness = str(result.get("completeness", "UNKNOWN")).upper()
        scan_error = result.get("error")
        approved = exit_code == 0 and completeness == "COMPLETE" and not scan_error
        return {
            "exit_code": exit_code,
            "approved": approved,
            "completeness": completeness,
            "error": scan_error,
            "model_sha256": self.model_hash,
            "findings": result.get("findings", []),
            "risk_score": result.get("risk", {}).get("score", 0),
            "risk_level": result.get("risk", {}).get("level", "UNKNOWN"),
            "artifact_revision": result.get("artifact_revision"),
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail-closed local model artifact admission gate")
    parser.add_argument("--model-path", required=True, help="Local model artifact directory")
    parser.add_argument(
        "--fail-on",
        choices=("critical", "high", "medium", "low", "info"),
        default="high",
        help="Lowest finding severity that blocks admission.",
    )
    parser.add_argument("--output", help="Optional JSON decision output path")
    args = parser.parse_args(argv)

    gate = ProtectedModelServer(args.model_path, {"fail_on": args.fail_on})
    result = gate.static_scan()
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"

    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)

    return 0 if result.get("approved") else 1


if __name__ == "__main__":
    raise SystemExit(main())
