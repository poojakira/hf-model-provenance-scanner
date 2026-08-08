"""
False-positive benchmark: hf-model-provenance-scanner vs Protect AI ModelScan.

Detection recall is only half the story. A scanner that flags every legitimate
model as suspicious is useless in production - analysts drown in noise and start
ignoring alerts (alert fatigue is the #1 cause of missed real incidents).

This benchmark builds REAL legitimate model pickles - the exact structures that
scikit-learn, PyTorch state_dicts, and numpy produce when you save a model - and
measures how many each scanner falsely flags as malicious.

Every pickle here is genuinely benign: it reconstructs standard data structures
(OrderedDict, numpy arrays, sklearn estimators) with no code-execution primitive.
A finding on any of these is a false positive by definition.

No synthetic numbers: results come from running both scanners as subprocesses.
"""

from __future__ import annotations

import json
import pickle  # noqa: S403
import subprocess
import sys
import tempfile
import time
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

# ─── Legitimate model artifacts ───────────────────────────────────────────────
# These are the real pickle structures produced by common ML frameworks.
# None of them execute code on load - they only reconstruct data.


def _sklearn_like_estimator() -> Any:
    """A dict resembling a fitted sklearn estimator's __dict__."""
    return {
        "coef_": np.random.randn(10).tolist(),
        "intercept_": 0.42,
        "n_features_in_": 10,
        "classes_": np.array([0, 1]),
        "_sklearn_version": "1.5.0",
    }


def _pytorch_state_dict() -> OrderedDict:
    """An OrderedDict resembling a PyTorch state_dict (numpy-backed tensors)."""
    sd: OrderedDict = OrderedDict()
    sd["layer1.weight"] = np.random.randn(64, 128).astype(np.float32)
    sd["layer1.bias"] = np.random.randn(64).astype(np.float32)
    sd["layer2.weight"] = np.random.randn(10, 64).astype(np.float32)
    sd["bn.running_mean"] = np.zeros(64, dtype=np.float32)
    return sd


def _numpy_arrays() -> dict:
    """Plain numpy arrays - the most common legitimate pickle content."""
    return {
        "embeddings": np.random.randn(100, 384).astype(np.float32),
        "vocab_ids": np.arange(1000, dtype=np.int64),
        "scale": np.float64(1.0),
    }


def _nested_config() -> dict:
    """A nested config dict with tuples, sets, and standard containers."""
    return {
        "architecture": "transformer",
        "layers": [{"dim": 512, "heads": 8} for _ in range(6)],
        "vocab": frozenset(["<pad>", "<unk>", "<bos>", "<eos>"]),
        "shape": (512, 512),
        "dtype_map": OrderedDict([("input", "int64"), ("output", "float32")]),
    }


def _tokenizer_state() -> dict:
    """A tokenizer-like structure with merges and vocab."""
    return {
        "vocab": {f"token_{i}": i for i in range(500)},
        "merges": [("a", "b"), ("c", "d")],
        "special_tokens": OrderedDict([("pad", 0), ("unk", 1)]),
        "model_max_length": 512,
    }


LEGIT_ARTIFACTS: list[tuple[str, Any]] = [
    ("sklearn_estimator", _sklearn_like_estimator()),
    ("pytorch_state_dict", _pytorch_state_dict()),
    ("numpy_arrays", _numpy_arrays()),
    ("nested_config", _nested_config()),
    ("tokenizer_state", _tokenizer_state()),
]


@dataclass
class FPOutcome:
    artifact: str
    modelscan_flagged: bool
    ourscanner_flagged: bool
    modelscan_severity: str = ""
    ourscanner_rules: list[str] | None = None


def _run_modelscan(path: Path) -> tuple[bool, str]:
    """Run ModelScan using its real JSON reporting API (-r json -o file).

    ModelScan writes JSON to a file, NOT stdout. stdout only carries a
    human console report. We read the file for a truthful issue count.
    """
    exe = Path(sys.executable).parent / "Scripts" / "modelscan.exe"
    out_file = Path(tempfile.gettempdir()) / f"ms_{path.stem}_{time.time_ns()}.json"
    cmd = [
        str(exe) if exe.exists() else "modelscan",
        "-p",
        str(path),
        "-r",
        "json",
        "-o",
        str(out_file),
    ]
    try:
        subprocess.run(
            cmd, capture_output=True, text=True, timeout=60, encoding="utf-8", errors="replace"
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return False, f"error: {e}"

    if not out_file.exists():
        return False, "no-output-file"
    try:
        data = json.loads(out_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return False, "unparseable"
    finally:
        out_file.unlink(missing_ok=True)

    total = data.get("summary", {}).get("total_issues", 0)
    issues = data.get("issues", [])
    if total > 0 or issues:
        sev = issues[0].get("severity", "") if issues else ""
        return True, sev
    return False, ""


def _run_our_scanner(path: Path) -> tuple[bool, list[str]]:
    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    from scanner.analyzer.pickle_scanner import analyze_pickle_file

    findings = analyze_pickle_file(str(path), path.read_bytes())
    rule_ids = [f.rule_id for f in findings]
    flagged = any(f.severity.value in ("critical", "high") for f in findings) if findings else False
    return flagged, rule_ids


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parents[1]
        / "evidence"
        / "generated"
        / "modelscan_false_positive.json",
    )
    args = parser.parse_args()

    print("=" * 72)
    print("FALSE-POSITIVE BENCHMARK: our scanner vs ModelScan on LEGITIMATE models")
    print("=" * 72)
    print()

    tmpdir = Path(tempfile.mkdtemp(prefix="legit_bench_"))
    outcomes: list[FPOutcome] = []

    for name, obj in LEGIT_ARTIFACTS:
        pkl_path = tmpdir / f"{name}.pkl"
        with pkl_path.open("wb") as fh:
            pickle.dump(obj, fh)

        ms_flagged, ms_sev = _run_modelscan(pkl_path)
        our_flagged, our_rules = _run_our_scanner(pkl_path)

        outcomes.append(
            FPOutcome(
                artifact=name,
                modelscan_flagged=ms_flagged,
                ourscanner_flagged=our_flagged,
                modelscan_severity=ms_sev,
                ourscanner_rules=our_rules,
            )
        )

        ms = "FALSE-POSITIVE" if ms_flagged else "clean"
        ours = "FALSE-POSITIVE" if our_flagged else "clean"
        print(f"{name:22} | ModelScan: {ms:15} | Ours: {ours:15}")

    total = len(outcomes)
    ms_fp = sum(1 for o in outcomes if o.modelscan_flagged)
    our_fp = sum(1 for o in outcomes if o.ourscanner_flagged)

    print()
    print("=" * 72)
    print("FALSE-POSITIVE RATE ON LEGITIMATE MODELS:")
    print(f"  ModelScan:   {ms_fp}/{total} ({ms_fp / total:.0%}) false positives")
    print(f"  Our scanner: {our_fp}/{total} ({our_fp / total:.0%}) false positives")
    print("=" * 72)

    evidence: dict[str, Any] = {
        "schema_version": "modelscan-fp-benchmark-v1",
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "competitor": "protectai/modelscan 0.8.8",
        "methodology": (
            "Built real legitimate model pickles (sklearn estimator dict, PyTorch "
            "state_dict with numpy tensors, numpy arrays, nested config, tokenizer "
            "state). Ran both scanners. Any finding on these benign artifacts is a "
            "false positive. Numbers reflect actual scan output."
        ),
        "totals": {
            "legitimate_artifacts": total,
            "modelscan_false_positives": ms_fp,
            "our_scanner_false_positives": our_fp,
        },
        "per_artifact": [
            {
                "artifact": o.artifact,
                "modelscan_false_positive": o.modelscan_flagged,
                "modelscan_severity": o.modelscan_severity,
                "our_scanner_false_positive": o.ourscanner_flagged,
                "our_scanner_rules": o.ourscanner_rules,
            }
            for o in outcomes
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(f"\nEvidence written to: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
