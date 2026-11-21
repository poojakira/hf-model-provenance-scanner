"""Generate provenance after source freeze, outside the repository; never a self-hash."""

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from defusedxml import ElementTree


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    if output.is_relative_to(root):
        raise SystemExit("Evidence must be generated outside source")

    def git(*commands):
        return subprocess.check_output(
            ["/usr/bin/git", "-C", str(root), *commands], text=True
        ).strip()

    artifacts = {}
    for path in sorted(args.artifacts.resolve().rglob("*")):
        if path.is_file() and path != output:
            artifacts[str(path.relative_to(args.artifacts.resolve()))] = {
                "bytes": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
    locks = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.glob("requirements*.lock")
    }
    manifest = {
        "repository": "poojakira/hf-model-provenance-scanner",
        "source_commit": git("rev-parse", "HEAD"),
        "branch": git("branch", "--show-current"),
        "source_state": "DIRTY"
        if git("status", "--porcelain", "--untracked-files=all")
        else "CLEAN",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "run_started_utc": os.environ.get("HF_VERIFY_STARTED_UTC", "UNKNOWN"),
        "source_state_before": os.environ.get("HF_SOURCE_STATE_BEFORE", "UNKNOWN"),
        "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
        "job_status": os.environ.get("HF_JOB_STATUS", "UNKNOWN"),
        "commands_source": ".github/workflows/ci.yml local-inspector job and its actual run logs",
        "python": platform.python_version(),
        "platform": platform.platform(),
        "dependencies": {d.metadata["Name"]: d.version for d in importlib.metadata.distributions()},
        "lock_sha256": locks,
        "artifacts": artifacts,
        "decision": "PARTIAL",
        "scope": "Local static inspector evidence; artifact results do not establish production approval or historical claim validity",
    }
    junit = args.artifacts / "junit.xml"
    if junit.is_file():
        tree = ElementTree.parse(junit).getroot()
        suites = [tree] if tree.tag == "testsuite" else list(tree.iter("testsuite"))
        suite_counts = {
            name: sum(int(suite.get(name, "0")) for suite in suites)
            for name in ("tests", "failures", "errors", "skipped")
        }
        cases = list(tree.iter("testcase"))
        counts = {
            "tests": len(cases),
            "failures": sum(case.find("failure") is not None for case in cases),
            "errors": sum(case.find("error") is not None for case in cases),
            "skipped": sum(case.find("skipped") is not None for case in cases),
        }
        counts["passed"] = counts["tests"] - sum(
            counts[name] for name in ("failures", "errors", "skipped")
        )
        manifest["tests"] = counts
        manifest["junit_suite_counts"] = suite_counts
        manifest["test_count_units"] = (
            "Individual JUnit testcase outcomes; suite totals can additionally count native subtests"
        )
        manifest["skips"] = [
            {
                "name": case.get("name"),
                "class": case.get("classname"),
                "reason": skip.get("message"),
            }
            for case in tree.iter("testcase")
            for skip in case.findall("skipped")
        ]
    regression_log = args.artifacts / "regression.log"
    if regression_log.is_file():
        text = regression_log.read_text()
        manifest["subtests"] = {
            outcome: sum(int(count) for count in re.findall(rf"(\d+) subtests {outcome}", text))
            for outcome in ("passed", "failed", "skipped")
        }
    coverage = args.artifacts / "coverage.json"
    if coverage.is_file():
        manifest["coverage"] = json.loads(coverage.read_text())["totals"]
        manifest["coverage_gate"] = 75
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: manifest[key] for key in ("source_commit", "source_state", "decision")}))


if __name__ == "__main__":
    main()
