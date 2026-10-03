"""Public Hugging Face ecosystem canary.

This validates remote-scan interoperability and completeness handling against public
repositories. It is not a malware-detection benchmark and does not label a public
repository safe or unsafe.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from scanner.utils.hf_api import HFApiClient

DEFAULT_REPOS = ("gpt2", "hf-internal-testing/tiny-random-gpt2")


def run_one(repo_id: str) -> dict:
    client = HFApiClient()
    commit_sha = client.resolve_to_commit_sha(repo_id, "main")
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "scanner.cli",
            repo_id,
            "--mode",
            "remote",
            "--revision",
            commit_sha,
            "--format",
            "json",
            "--fail-on",
            "never",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
    )
    parsed = None
    try:
        parsed = json.loads(proc.stdout)
    except json.JSONDecodeError:
        parsed = {"raw_stdout": proc.stdout[-4000:]}
    return {
        "repo_id": repo_id,
        "resolved_commit_sha": commit_sha,
        "scanner_exit_code": proc.returncode,
        "report": parsed,
        "stderr_tail": proc.stderr[-2000:],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", action="append", dest="repos")
    parser.add_argument(
        "--output", type=Path, default=Path("validation/public-hf-canary.json")
    )
    args = parser.parse_args()
    repos = tuple(args.repos or DEFAULT_REPOS)
    results = [run_one(repo_id) for repo_id in repos]
    payload = {
        "classification": "public_repository_interoperability_canary",
        "results": results,
        "claim_boundary": (
            "This canary verifies immutable-revision remote scanning, bounded downloads, "
            "and completeness/error reporting. It is not a population-level detection-rate "
            "or clean-model certification."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    failed = [item for item in results if item["scanner_exit_code"] not in (0, 1)]
    print(f"wrote {args.output}; {len(results)} public repositories checked")
    return 2 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
