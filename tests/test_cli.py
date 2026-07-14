import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from scanner import cli
from scanner.utils.hf_api import HFAccessError

# Build fixture paths portably so tests pass on Windows and POSIX (CI) alike.
# Hardcoded backslash paths ("tests\\fixtures\\...") are literal filenames on
# Linux and cause the scanner to report "not a local directory".
_FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
MALICIOUS_DIR = os.path.join(_FIXTURES_DIR, "malicious")
BENIGN_DIR = os.path.join(_FIXTURES_DIR, "benign")


class GatedClient:
    """Simulates a gated/private/nonexistent repo: the file listing 401s."""

    def __init__(self, token=None):
        self.token = token

    def get_model_info(self, repo_id):
        raise HFAccessError(401, f"https://huggingface.co/api/models/{repo_id}")

    def get_model_card(self, repo_id):
        raise HFAccessError(401, f"https://huggingface.co/{repo_id}/raw/main/README.md")

    def list_repo_files(self, repo_id):
        raise HFAccessError(401, f"https://huggingface.co/api/models/{repo_id}")

    def download_file(self, repo_id, filename):
        raise HFAccessError(401, f"https://huggingface.co/{repo_id}/resolve/main/{filename}")


class FakeClient:
    card = "Privacy Filter model card from OpenAI. Use the privacy filter for PII detection."

    def __init__(self, token=None):
        self.token = token

    def get_model_info(self, repo_id):
        return {"id": repo_id, "downloads": 244000, "createdAt": "2020-01-01T00:00:00.000Z"}

    def get_model_card(self, repo_id):
        if repo_id in {"Open-OSS/privacy-filter", "openai/privacy-filter"}:
            return self.card
        return ""

    def list_repo_files(self, repo_id):
        return ["README.md", "loader.py"]

    def download_file(self, repo_id, filename):
        if filename == "loader.py":
            path = os.path.join(os.path.dirname(__file__), "fixtures", "malicious", "privacy_filter_loader.py")
            with open(path, "rb") as f:
                return f.read()
        return self.card.encode("utf-8")


class TestCli(unittest.TestCase):
    def test_local_fail_on_high_returns_1(self):
        code = cli.main([MALICIOUS_DIR, "--mode", "local", "--quiet", "--fail-on", "high"])
        self.assertEqual(code, 1)

    def test_local_fail_on_never_returns_0(self):
        code = cli.main([MALICIOUS_DIR, "--mode", "local", "--quiet", "--fail-on", "never"])
        self.assertEqual(code, 0)

    @patch("scanner.cli.HFApiClient", FakeClient)
    def test_remote_privacy_filter_pattern_scans_files_and_policy(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = cli.main(["Open-OSS/privacy-filter", "--mode", "remote", "--format", "json", "--fail-on", "never"])
        self.assertEqual(code, 0)
        report = json.loads(stdout.getvalue())
        rule_ids = {finding["rule_id"] for finding in report["findings"]}
        self.assertIn("HFS-021", rule_ids)
        self.assertIn("HFS-025", rule_ids)
        self.assertIn("HFS-032", rule_ids)
        self.assertIn("HFS-033", rule_ids)
        self.assertIn("HFS-035", rule_ids)
        self.assertIn("HFS-001", rule_ids)
        self.assertGreaterEqual(report["files_scanned"], 1)

    @patch("scanner.cli.HFApiClient", FakeClient)
    def test_approved_publisher_policy_blocks_unknown_vendor(self):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".toml", delete=False) as f:
            f.write('[policy]\napproved_publishers = ["openai"]\n')
            config_path = f.name
        try:
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = cli.main(["Open-OSS/privacy-filter", "--mode", "remote", "--format", "json", "--fail-on", "never", "--config", config_path])
            self.assertEqual(code, 0)
            report = json.loads(stdout.getvalue())
            self.assertIn("HFS-034", {finding["rule_id"] for finding in report["findings"]})
        finally:
            os.unlink(config_path)


    @patch("scanner.cli.HFApiClient", GatedClient)
    def test_gated_repo_does_not_crash_and_emits_finding(self):
        """A gated/private/nonexistent remote repo must not crash the scanner.

        Regression test: previously list_repo_files() raised, propagated to
        main(), and exited with code 2 and a cryptic 'Request failed after 3
        retries' message. Now the scanner emits a clear HFS-096 finding, marks
        the assessment incomplete via the error field, and exits gracefully.
        """
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = cli.main(["meta-llama/Llama-3-8B", "--mode", "remote",
                             "--format", "json", "--fail-on", "high"])
        # Non-crashing exit: LOW finding does not trip --fail-on high.
        self.assertEqual(code, 0)
        report = json.loads(stdout.getvalue())
        rule_ids = {f["rule_id"] for f in report["findings"]}
        self.assertIn("HFS-096", rule_ids)
        # Assessment marked incomplete (so monitors classify SKIPPED, not CLEAN).
        self.assertIsNotNone(report["error"])
        self.assertEqual(report["files_scanned"], 0)

    def test_hf_access_error_raised_without_retry(self):
        """401/403/404 should raise HFAccessError immediately, not retry."""
        import urllib.error
        from unittest.mock import patch as _patch
        from scanner.utils.hf_api import HFApiClient

        client = HFApiClient()
        err = urllib.error.HTTPError("http://x", 401, "Unauthorized", {}, None)
        with _patch("urllib.request.urlopen", side_effect=err):
            with self.assertRaises(HFAccessError) as ctx:
                client.get_model_info("meta-llama/Llama-3-8B")
        self.assertEqual(ctx.exception.code, 401)

    def test_runtime_policy_output(self):
        with tempfile.NamedTemporaryFile("r", encoding="utf-8", suffix=".json", delete=False) as f:
            policy_path = f.name
        try:
            code = cli.main([BENIGN_DIR, "--mode", "local", "--quiet", "--fail-on", "never", "--runtime-policy", policy_path])
            self.assertEqual(code, 0)
            with open(policy_path, "r", encoding="utf-8") as f:
                policy = json.load(f)
            # The scanner emits a hardened Kubernetes-style RuntimePolicy.
            self.assertEqual(policy["kind"], "RuntimePolicy")
            self.assertFalse(policy["spec"]["container"]["allowPrivilegeEscalation"])
            self.assertTrue(policy["spec"]["container"]["runAsNonRoot"])
            self.assertEqual(policy["spec"]["network"]["egressPolicy"], "deny")
            self.assertTrue(policy["spec"]["process"]["noNewPrivileges"])
        finally:
            os.unlink(policy_path)

    def test_html_report_output(self):
        with tempfile.NamedTemporaryFile("r", encoding="utf-8", suffix=".html", delete=False) as f:
            report_path = f.name
        try:
            code = cli.main([MALICIOUS_DIR, "--mode", "local", "--format", "html", "--output", report_path, "--fail-on", "never"])
            self.assertEqual(code, 0)
            with open(report_path, "r", encoding="utf-8") as f:
                report = f.read()
            self.assertIn("HF Model Provenance Scanner Report", report)
            self.assertIn("Risk Assessment", report)
            self.assertIn("HFS-001", report)
        finally:
            os.unlink(report_path)

if __name__ == "__main__":
    unittest.main()


