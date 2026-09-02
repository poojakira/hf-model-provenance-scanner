#!/usr/bin/env python3
"""Post an HF Hub discussion comment with scan results (best-effort).

Reads all inputs from environment variables so no shell-quoting or YAML
block-scalar indentation hazards apply. Failures are logged and the script
exits 0 — this is a notification, not a security gate.

Environment variables:
    HF_TOKEN          HF token with discussion-write scope (required; if unset the
                      caller should skip invoking this script).
    REPO_ID           HuggingFace repo id, e.g. "org/model".
    RISK_LEVEL, RISK_SCORE, FINDINGS, CRITICAL, HIGH   Scan summary values.
    GITHUB_SERVER_URL, GITHUB_REPOSITORY, GITHUB_RUN_ID   Provided by Actions.
"""

import json
import os
import urllib.request


def main() -> int:
    token = os.environ.get("HF_TOKEN", "")
    if not token:
        print("HF_TOKEN not configured; skipping HF Hub discussion post.")
        return 0

    repo_id = os.environ.get("REPO_ID", "")
    risk_level = os.environ.get("RISK_LEVEL", "UNKNOWN")
    risk_score = os.environ.get("RISK_SCORE", "0")
    findings = os.environ.get("FINDINGS", "0")
    critical = os.environ.get("CRITICAL", "0")
    high = os.environ.get("HIGH", "0")

    server = os.environ.get("GITHUB_SERVER_URL", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    run_url = f"{server}/{repo}/actions/runs/{run_id}"

    if not repo_id:
        print("REPO_ID not provided; nothing to post.")
        return 0

    body = (
        "## Automated Security Scan Results\n\n"
        f"**Risk Level:** {risk_level} ({risk_score}/100)\n"
        f"**Total Findings:** {findings}\n"
        f"**Critical:** {critical} | **High:** {high}\n\n"
        "This scan was triggered automatically on model push via GitHub Actions.\n"
        f"View full results in the [GitHub Actions run]({run_url}).\n\n"
        "---\n"
        "*Scan performed by hf-model-provenance-scanner with gVisor sandbox validation.*\n"
    )

    url = f"https://huggingface.co/api/models/{repo_id}/discussions"
    data = json.dumps({"title": f"Security Scan: {risk_level} risk", "content": body}).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=10)  # noqa: S310
        print("Posted to HF Hub discussion")
    except Exception as e:  # noqa: BLE001 - best-effort notifier, never fatal
        print(f"Could not post to HF Hub (non-fatal): {e}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
