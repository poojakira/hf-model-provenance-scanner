import importlib.util
import io
import json
import os
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from integrations import huggingface_webhook as webhook


class TestWebhookSecurityRejects(unittest.TestCase):
    def _signed_headers(self, body: bytes, secret: str) -> dict[str, str]:
        signature = webhook.hmac.new(secret.encode(), body, webhook.hashlib.sha256).hexdigest()
        return {
            "Content-Length": str(len(body)),
            "X-Webhook-Secret": f"sha256={signature}",
        }

    def test_webhook_secret_unset_fails_closed(self):
        body = b'{"repo":{"name":"org/model","type":"model"}}'
        with patch.dict(os.environ, {}, clear=True):
            status, result = webhook.process_webhook_request(
                {"Content-Length": str(len(body))}, io.BytesIO(body), handler=lambda event: event
            )
        self.assertEqual(status, 500)
        self.assertEqual(result, {"error": "server misconfigured"})

    def test_webhook_rejects_oversized_content_length_before_reading(self):
        with patch.dict(os.environ, {"WEBHOOK_SECRET": "secret"}, clear=True):
            status, result = webhook.process_webhook_request(
                {"Content-Length": str(webhook.MAX_CONTENT_LENGTH + 1)}, io.BytesIO(b""), handler=lambda event: event
            )
        self.assertEqual(status, 413)
        self.assertEqual(result, {"error": "payload too large"})

    def test_webhook_returns_generic_500_without_exception_text(self):
        body = json.dumps({"repo": {"name": "org/model", "type": "model"}}).encode()
        with patch.dict(os.environ, {"WEBHOOK_SECRET": "secret"}, clear=True):
            status, result = webhook.process_webhook_request(
                self._signed_headers(body, "secret"),
                io.BytesIO(body),
                handler=lambda event: (_ for _ in ()).throw(RuntimeError("raw secret failure")),
            )
        self.assertEqual(status, 500)
        self.assertEqual(result, {"error": "internal server error"})
        self.assertNotIn("raw secret failure", json.dumps(result))

    def test_webhook_accepts_valid_signed_request(self):
        body = json.dumps({"repo": {"name": "org/model", "type": "model"}}).encode()
        with patch.dict(os.environ, {"WEBHOOK_SECRET": "secret"}, clear=True):
            status, result = webhook.process_webhook_request(
                self._signed_headers(body, "secret"),
                io.BytesIO(body),
                handler=lambda event: {"repo": event["repo"]["name"]},
            )
        self.assertEqual(status, 200)
        self.assertEqual(result, {"repo": "org/model"})


    def test_webhook_rejects_invalid_repo_id_without_scan(self):
        invalid_repo_ids = [
            "../etc/passwd",
            "org/model?revision=main",
            "https://huggingface.co/org/model",
            "org/model/extra",
            "org/evil..model",
            123,
        ]
        for repo_id in invalid_repo_ids:
            with self.subTest(repo_id=repo_id), patch.object(
                webhook, "scan_repo", side_effect=AssertionError("scan_repo called")
            ):
                result = webhook.handle_webhook({"repo": {"name": repo_id, "type": "model"}})
            self.assertEqual(result, {"status": "ignored", "reason": "invalid repo_id"})


class TestMaliciousFixtureSafety(unittest.TestCase):
    def test_privacy_filter_fixture_is_inert_when_called(self):
        fixture = Path(__file__).parent / "fixtures" / "malicious" / "privacy_filter_loader.py"
        spec = importlib.util.spec_from_file_location("privacy_filter_loader_fixture", fixture)
        module = importlib.util.module_from_spec(spec)
        with patch.object(subprocess, "run", side_effect=AssertionError("subprocess.run executed")):
            spec.loader.exec_module(module)
            self.assertEqual(module._post_install_hook()["blocked"], True)
            self.assertEqual(module.load_model()["fixture_payload_blocked"], True)


if __name__ == "__main__":
    unittest.main()
