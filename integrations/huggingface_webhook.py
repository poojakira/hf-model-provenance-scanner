"""
HuggingFace Webhook Integration — Auto-scan models on push.

Deploy this as a serverless function (AWS Lambda, Cloudflare Worker,
Google Cloud Function) or standalone Flask/FastAPI service.

When configured as a HuggingFace webhook, it will:
1. Receive push events for model repositories
2. Automatically scan the pushed model
3. Post results back as a comment/discussion on the repo
4. Return a signed-request scan decision to the calling integration

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
import sys
import urllib.request

# Add scanner to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Webhook configuration
MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MB


def process_webhook_request(headers: dict, body_stream, handler):
    """
    Process a webhook request with signature verification.

    Args:
        headers: HTTP headers dict
        body_stream: Stream object with .read() method
        handler: Callable that takes parsed event and returns response

    Returns:
        Tuple of (status_code, response_dict)
    """
    secret = os.environ.get("WEBHOOK_SECRET")
    if not secret:
        return 500, {"error": "server misconfigured"}

    # Check content length
    content_length = headers.get("Content-Length")
    if content_length:
        try:
            if int(content_length) > MAX_CONTENT_LENGTH:
                return 413, {"error": "payload too large"}
        except ValueError:
            pass

    # Read body
    body = body_stream.read()

    # Verify signature
    signature = headers.get("X-Webhook-Secret", "")
    if not verify_signature(body, signature, secret):
        return 401, {"error": "invalid signature"}

    try:
        event = json.loads(body)
        result = handler(event)
        return 200, result
    except Exception as e:
        return 500, {"error": "internal server error"}


def verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify HuggingFace webhook HMAC-SHA256 signature."""
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)


def scan_repo(repo_id: str) -> dict:
    """Run the scanner against a HuggingFace repo."""
    import io
    from contextlib import redirect_stdout

    from scanner.cli import main

    stdout = io.StringIO()
    with redirect_stdout(stdout):
        exit_code = main(
            [
                repo_id,
                "--mode",
                "remote",
                "--format",
                "json",
                "--fail-on",
                os.environ.get("FAIL_ON", "high"),
                "--token",
                os.environ.get("HF_TOKEN", ""),
            ]
        )

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

    if repo_type != "model":
        return {"status": "ignored", "reason": f"not a model repo (type={repo_type})"}

    # Validate repo_id format (basic sanitization)
    if not isinstance(repo_id, str):
        return {"status": "ignored", "reason": "invalid repo_id"}
    if ".." in repo_id or repo_id.startswith("/") or "://" in repo_id:
        return {"status": "ignored", "reason": "invalid repo_id"}
    if "?" in repo_id or "#" in repo_id:
        return {"status": "ignored", "reason": "invalid repo_id"}
    if repo_id.count("/") != 1:
        return {"status": "ignored", "reason": "invalid repo_id"}

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


def run_server(host: str | None = None, port: int = 8080):
    """Run a simple HTTP server for webhook testing.

    Security: WEBHOOK_SECRET is mandatory. The helper binds to 127.0.0.1 by
    default; an operator must explicitly choose a non-loopback bind address.
    This server remains a small-deployment adapter, not the scanner's trust
    boundary: every accepted request is HMAC verified before scanning.
    """
    from http.server import BaseHTTPRequestHandler, HTTPServer

    if host is None:
        host = os.environ.get("WEBHOOK_BIND_HOST", "127.0.0.1")
    if not os.environ.get("WEBHOOK_SECRET"):
        raise RuntimeError("WEBHOOK_SECRET is required; unsigned webhook mode is disabled")

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path != "/scan":
                self.send_response(404)
                self.end_headers()
                return
            try:
                content_length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self.send_response(400)
                self.end_headers()
                return
            if content_length <= 0 or content_length > MAX_CONTENT_LENGTH:
                self.send_response(413 if content_length > MAX_CONTENT_LENGTH else 400)
                self.end_headers()
                return
            body = self.rfile.read(content_length)
            if len(body) > MAX_CONTENT_LENGTH:
                self.send_response(413)
                self.end_headers()
                return

            secret = os.environ["WEBHOOK_SECRET"]
            signature = self.headers.get("X-Webhook-Secret", "")
            if not verify_signature(body, signature, secret):
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b'{"error": "invalid signature"}')
                return

            try:
                event = json.loads(body)
                result = handle_webhook(event)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(result).encode())
            except Exception:
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":"internal server error"}')

        def log_message(self, format, *args):
            print(f"[webhook] {args[0]}")

    server = HTTPServer((host, port), Handler)
    print(f"Webhook server running on {host}:{port}")
    print(f"Configure HuggingFace webhook to POST to http://{host}:{port}/scan")
    server.serve_forever()


if __name__ == "__main__":
    run_server()