"""Measure the HF scanner against a locally available model artifact directory.

This runner never downloads a model. Supply an already authorized, immutable
artifact directory plus its repository ID and revision. The resulting JSON is
evidence for that exact directory only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from scanner.cli import SCANNER_VERSION, scan_local  # noqa: E402
from scanner.config import load_config  # noqa: E402
from scanner.models import ScanResult  # noqa: E402
from scanner.provenance import verify_sbom_artifacts  # noqa: E402
from scanner.risk import compute_risk  # noqa: E402


def percentile(samples: list[float], level: float) -> float:
    """Return a nearest-rank percentile in milliseconds."""
    if not samples:
        return 0.0
    ordered = sorted(samples)
    return round(ordered[min(len(ordered) - 1, int((len(ordered) - 1) * level))], 3)


def sha256_file(path: Path) -> str:
    """Hash one artifact without loading the entire file into memory."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def artifact_manifest(root: Path) -> list[dict[str, Any]]:
    """Produce a deterministic manifest for every regular file in an artifact directory."""
    entries: list[dict[str, Any]] = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        entries.append(
            {
                "path": path.relative_to(root).as_posix(),
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    return entries


def serialize_result(result: ScanResult) -> dict[str, Any]:
    """Convert an in-process result to the public JSON evidence shape."""
    return {
        "scan_target": result.scan_target,
        "scan_mode": result.scan_mode,
        "scanner_version": result.scanner_version,
        "files_scanned": result.files_scanned,
        "files_skipped": result.files_skipped,
        "findings": [
            {
                "rule_id": finding.rule_id,
                "severity": finding.severity.value,
                "file_path": finding.file_path,
                "evidence": finding.evidence,
            }
            for finding in result.findings
        ],
        "risk": {"score": result.risk.score, "level": result.risk.level},
    }


def scan_once(root: Path, max_binary_mb: int, scope: str) -> tuple[float, dict[str, Any]]:
    """Measure either scanner processing or complete CLI process execution."""
    if scope == "in-process":
        result = ScanResult(str(root), "local", SCANNER_VERSION)
        started = time.perf_counter()
        artifacts, sboms, _ = scan_local(result, str(root), load_config(), max_binary_mb)
        result.findings.extend(verify_sbom_artifacts(sboms, artifacts))
        result.risk = compute_risk(result)
        return (time.perf_counter() - started) * 1000, serialize_result(result)

    command = [
        sys.executable,
        "-m",
        "scanner.cli",
        str(root),
        "--mode",
        "local",
        "--format",
        "json",
        "--fail-on",
        "never",
        "--max-binary-mb",
        str(max_binary_mb),
    ]
    started = time.perf_counter()
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    elapsed_ms = (time.perf_counter() - started) * 1000
    if result.returncode not in {0, 1}:
        raise RuntimeError(f"scanner failed with {result.returncode}: {result.stderr.strip()}")
    try:
        return elapsed_ms, json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"scanner did not emit JSON: {result.stdout[:500]!r}") from error


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact_dir", type=Path)
    parser.add_argument("--model-id", required=True, help="Immutable model repository identifier")
    parser.add_argument(
        "--revision", required=True, help="Model commit, tag, or immutable snapshot revision"
    )
    parser.add_argument("--runs", type=int, default=100)
    parser.add_argument("--warmup", type=int, default=3)
    parser.add_argument("--max-binary-mb", type=int, default=10_000)
    parser.add_argument("--measurement-scope", choices=["in-process", "cli"], default="in-process")
    parser.add_argument("--require-zero-findings", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    if not args.artifact_dir.is_dir():
        parser.error("artifact_dir must be an existing local directory")
    if args.runs < 3:
        parser.error("--runs must be at least 3")

    for _ in range(args.warmup):
        scan_once(args.artifact_dir, args.max_binary_mb, args.measurement_scope)

    samples: list[float] = []
    findings_per_run: list[int] = []
    final_result: dict[str, Any] = {}
    for _ in range(args.runs):
        elapsed_ms, result = scan_once(
            args.artifact_dir, args.max_binary_mb, args.measurement_scope
        )
        samples.append(round(elapsed_ms, 3))
        findings_per_run.append(len(result.get("findings", [])))
        final_result = result

    payload = {
        "schema_version": "hf-real-artifact-evidence-v1",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "claim_boundary": "Results apply only to the local artifact manifest and scanner revision recorded here.",
        "model": {"id": args.model_id, "revision": args.revision},
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "machine": platform.machine(),
        },
        "measurement_scope": args.measurement_scope,
        "scanner_command": ["python", "-m", "scanner.cli", "<artifact_dir>", "--mode", "local"]
        if args.measurement_scope == "cli"
        else ["scan_local", "<artifact_dir>"],
        "artifact_manifest": artifact_manifest(args.artifact_dir),
        "measurement": {
            "runs": args.runs,
            "warmup_runs": args.warmup,
            "raw_end_to_end_ms": samples,
            "p50_ms": percentile(samples, 0.50),
            "p95_ms": percentile(samples, 0.95),
            "p99_ms": percentile(samples, 0.99),
            "max_ms": round(max(samples), 3),
            "findings_per_run": findings_per_run,
            "zero_findings": all(count == 0 for count in findings_per_run),
            "last_scan_result": final_result,
        },
    }
    if args.require_zero_findings and not payload["measurement"]["zero_findings"]:
        raise SystemExit("clean-artifact requirement failed: scanner reported findings")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(payload["measurement"], indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
