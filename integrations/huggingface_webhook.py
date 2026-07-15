"""
HuggingFace Webhook Integration — Auto-scan models on push.

Deploy this as a serverless function (AWS Lambda, Cloudflare Worker,
Google Cloud Function) or standalone Flask/FastAPI service.

When configured as a HuggingFace webhook, it will:
1. Receive push events for model repositories
2. Automatically scan the pushed model
3. Post results back as a comment/discussion on the repo
4. Optionally block downloads if CRITICAL findings detected

Setup:
1. Go to https://huggingface.co/settings/webhooks
2. Add webhook URL: https://your-domain.com/scan
3. Select events: "Repo update"
4. Set secret (for HMAC verification)

Environment variables:
  HF_TOKEN          - HuggingFace API token (read access)
  WEBHOOK_SECRET    - Secret for HMAC verification
  NOTIFY_URL        - Optional: Slack/Teams/Discord webhook for alerts
  FAIL_ON           - Severity threshold (default: high)
"""

import hashlib
import hmac
import json
import os
import re
import sys
import tempfile
import urllib.request

# Add scanner to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

## 1 MiB is ample for HuggingFace webhook JSON.
MAX_CONTENT_LENGTH = 1024 * 1024
## HuggingFace model repo IDs are namespace/name. Reject URLs, paths, queries, and traversal before remote scan.
HF_REPO_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}/[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")


def is_valid_repo_id(repo_id: object) -> bool:
    if not isinstance(repo_id, str):
        return False
    if ".." in repo_id or "--" in repo_id:
        return False
    if repo_id.startswith(("/", "http://", "https://")):
        return False
    if not HF_REPO_ID_RE.fullmatch(repo_id):
        return False
    return all(part[-1] not in ".-" for part in repo_id.split("/"))


def verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify HuggingFace webhook HMAC-SHA256 signature."""
    expected = hmac.new(
        secret.encode(), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)


## Validate and process one HTTP webhook request.
def process_webhook_request(headers, body_reader, handler=None):
    if handler is None:
        handler = handle_webhook

    secret = os.environ.get("WEBHOOK_SECRET")
    if not secret:
        return 500, {"error": "server misconfigured"}

    raw_length = headers.get("Content-Length")
    if raw_length is None:
        return 411, {"error": "content length required"}
    try:
        content_length = int(raw_length)
    except (TypeError, ValueError):
        return 400, {"error": "invalid content length"}
    if content_length < 0:
        return 400, {"error": "invalid content length"}
    if content_length > MAX_CONTENT_LENGTH:
        return 413, {"error": "payload too large"}

    body = body_reader.read(content_length)
    signature = headers.get("X-Webhook-Secret", "")
    if not verify_signature(body, signature, secret):
        return 401, {"error": "invalid signature"}

    try:
        event = json.loads(body)
    except json.JSONDecodeError:
        return 400, {"error": "invalid json"}

    try:
        return 200, handler(event)
    except Exception:
        return 500, {"error": "internal server error"}


def scan_repo(repo_id: str) -> dict:
    """Run the scanner against a HuggingFace repo."""
    from scanner.cli import main
    import io
    from contextlib import redirect_stdout

    stdout = io.StringIO()
    with redirect_stdout(stdout):
        exit_code = main([
            repo_id,
            "--mode", "remote",
            "--format", "json",
            "--fail-on", os.environ.get("FAIL_ON", "high"),
            "--token", os.environ.get("HF_TOKEN", ""),
        ])

    try:
        result = json.loads(stdout.getvalue())
    except json.JSONDecodeError:
        result = {"error": "Failed to parse scan output"}

    result["exit_code"] = exit_code
    return result


def send_notification(repo_id: str, result: dict):
    """Send alert to Slack/Teams/Discord if findings detected."""
    notify_url = os.environ.get("NOTIFY_URL")
    if not notify_url:
        return

    risk = result.get("risk", {})
    findings_count = len(result.get("findings", []))

    if findings_count == 0:
        return

    message = {
        "text": (
            f"**HF Scanner Alert** for `{repo_id}`\n"
            f"Risk: {risk.get('level', 'UNKNOWN')} ({risk.get('score', 0)}/100)\n"
            f"Findings: {findings_count}\n"
            f"Critical: {sum(1 for f in result.get('findings', []) if f.get('severity') == 'critical')}\n"
            f"Action: Review at https://huggingface.co/{repo_id}"
        )
    }

    req = urllib.request.Request(
        notify_url,
        data=json.dumps(message).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass


def handle_webhook(event: dict) -> dict:
    """
    Main webhook handler. Call this from your serverless function.

    Args:
        event: The webhook payload from HuggingFace

    Returns:
        Response dict with status and scan results
    """
    # Extract repo info
    repo = event.get("repo", {})
    repo_id = repo.get("name", "")
    repo_type = repo.get("type", "model")

    if not repo_id:
        return {"status": "ignored", "reason": "no repo_id"}

    if not is_valid_repo_id(repo_id):
        return {"status": "ignored", "reason": "invalid repo_id"}
    if repo_type != "model":
        return {"status": "ignored", "reason": f"not a model repo (type={repo_type})"}

    # Run scan
    result = scan_repo(repo_id)

    # Send notification if findings
    send_notification(repo_id, result)

    return {
        "status": "scanned",
        "repo_id": repo_id,
        "risk_level": result.get("risk", {}).get("level", "UNKNOWN"),
        "risk_score": result.get("risk", {}).get("score", 0),
        "findings_count": len(result.get("findings", [])),
        "exit_code": result.get("exit_code", 0),
    }


# === Standalone HTTP server (for testing/small deployments) ===

def run_server(host: str = "0.0.0.0", port: int = 8080):
    """Run a simple HTTP server for webhook testing."""
    from http.server import HTTPServer, BaseHTTPRequestHandler

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            status, result = process_webhook_request(self.headers, self.rfile)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())

        def log_message(self, format, *args):
            print(f"[webhook] {args[0]}")

    server = HTTPServer((host, port), Handler)
    print(f"Webhook server running on {host}:{port}")
    print(f"Configure HuggingFace webhook to POST to http://{host}:{port}/scan")
    server.serve_forever()


if __name__ == "__main__":
    run_server()
