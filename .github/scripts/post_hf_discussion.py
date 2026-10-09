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

import ipaddress
import json
import os
import re
import urllib.request
from urllib.parse import urlsplit

_SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}")


def _discussion_url(repo_id: str) -> str:
    """Construct only the official HF discussions endpoint from two safe IDs."""
    parts = repo_id.split("/")
    if len(parts) != 2 or any(
        not _SEGMENT.fullmatch(part) or part in {".", ".."} or ".." in part for part in parts
    ):
        raise ValueError("REPO_ID must be an HF namespace/model pair")
    try:
        ipaddress.ip_address(parts[0])
    except ValueError:
        pass
    else:
        raise ValueError("REPO_ID namespace must not be an IP address")
    url = f"https://huggingface.co/api/models/{parts[0]}/{parts[1]}/discussions"
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "huggingface.co"
        or parsed.port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Invalid Hugging Face discussions endpoint")
    return url


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Block cross-origin redirects to avoid leaking HF authorization headers."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


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

    try:
        url = _discussion_url(repo_id)
    except ValueError:
        print("REPO_ID is invalid; refusing to send HF discussion notification.")
        return 0
    data = json.dumps({"title": f"Security Scan: {risk_level} risk", "content": body}).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.build_opener(_NoRedirect()).open(req, timeout=10)  # noqa: S310
        print("Posted to HF Hub discussion")
    except Exception as e:  # noqa: BLE001 - best-effort notifier, never fatal
        print(f"Could not post to HF Hub (non-fatal): {e}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
