import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from scanner import cli

# Fake SHA used by FakeClient — 40 hex chars, deterministic
FAKE_COMMIT_SHA = "a" * 40


class FakeClient:
    """Test double for HFApiClient implementing the immutable-revision interface.

    All methods accept the new commit_sha parameter that was added as part of
    the TOCTOU fix (FINDING-001). The SHA is ignored for test purposes but
    the signature must match so tests exercise the new code paths.
    """

    card = "Privacy Filter model card from OpenAI. Use the privacy filter for PII detection."

    def __init__(self, token=None):
        self.token = token

    def get_model_info(self, repo_id, revision=None):
        return {
            "id": repo_id,
            "downloads": 244000,
            "createdAt": "2020-01-01T00:00:00.000Z",
            "sha": FAKE_COMMIT_SHA,
        }

    def resolve_to_commit_sha(self, repo_id: str, revision: str = "main") -> str:
        """Return a deterministic fake SHA for tests."""
        return FAKE_COMMIT_SHA

    def get_model_card(self, repo_id, commit_sha=None):
        if repo_id in {"Open-OSS/privacy-filter", "openai/privacy-filter"}:
            return self.card
        return ""

    def list_repo_files(self, repo_id, commit_sha=None):
        return ["README.md", "loader.py"]

    def download_file(self, repo_id, filename, commit_sha=None):
        if filename == "loader.py":
            path = os.path.join(
                os.path.dirname(__file__), "fixtures", "malicious", "privacy_filter_loader.py"
            )
            with open(path, "rb") as f:
                return f.read()
        return self.card.encode("utf-8")


FIXTURES_DIR = Path(__file__).parent / "fixtures"
MALICIOUS_FIXTURE = FIXTURES_DIR / "malicious"
BENIGN_FIXTURE = FIXTURES_DIR / "benign"


class FailingClient:
    """Test double whose SHA resolution fails, simulating a network error.

    Used to verify that a remote scan which cannot resolve the target to an
    immutable commit SHA fails LOUD (INDETERMINATE completeness), never
    silently reporting a clean bill of health.
    """

    def __init__(self, token=None):
        self.token = token

    def resolve_to_commit_sha(self, repo_id: str, revision: str = "main") -> str:
        raise ConnectionError("simulated network failure resolving revision")

    def get_model_info(self, repo_id, revision=None):
        raise ConnectionError("simulated network failure")

    def get_model_card(self, repo_id, commit_sha=None):
        raise ConnectionError("simulated network failure")

    def list_repo_files(self, repo_id, commit_sha=None):
        raise ConnectionError("simulated network failure")

    def download_file(self, repo_id, filename, commit_sha=None):
        raise ConnectionError("simulated network failure")


class TestCli(unittest.TestCase):
    def test_local_fail_on_high_returns_1(self):
        code = cli.main([str(MALICIOUS_FIXTURE), "--mode", "local", "--quiet", "--fail-on", "high"])
        self.assertEqual(code, 1)

    def test_local_fail_on_never_returns_0(self):
        code = cli.main(
            [str(MALICIOUS_FIXTURE), "--mode", "local", "--quiet", "--fail-on", "never"]
        )
        self.assertEqual(code, 0)

    @patch("scanner.cli.HFApiClient", FakeClient)
    def test_remote_privacy_filter_pattern_scans_files_and_policy(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = cli.main(
                [
                    "Open-OSS/privacy-filter",
                    "--mode",
                    "remote",
                    "--format",
                    "json",
                    "--fail-on",
                    "never",
                ]
            )
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
                code = cli.main(
                    [
                        "Open-OSS/privacy-filter",
                        "--mode",
                        "remote",
                        "--format",
                        "json",
                        "--fail-on",
                        "never",
                        "--config",
                        config_path,
                    ]
                )
            self.assertEqual(code, 0)
            report = json.loads(stdout.getvalue())
            self.assertIn("HFS-034", {finding["rule_id"] for finding in report["findings"]})
        finally:
            os.unlink(config_path)

    @patch("scanner.cli.HFApiClient", FailingClient)
    def test_remote_network_failure_is_indeterminate_not_clean(self):
        """A remote scan that cannot resolve a commit SHA must fail LOUD.

        completeness MUST be INDETERMINATE and the error surfaced; --enforce
        MUST exit 1. This prevents a network outage from silently passing as a
        clean scan.
        """
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = cli.main(
                [
                    "some-org/some-model",
                    "--mode",
                    "remote",
                    "--format",
                    "json",
                    "--fail-on",
                    "never",
                ]
            )
        report = json.loads(stdout.getvalue())
        self.assertEqual(report["completeness"], "INDETERMINATE")
        self.assertIsNotNone(report["error"])
        # Default (no enforce) exit is 0, but the report is honestly INDETERMINATE.
        self.assertEqual(code, 0)
        # With --enforce the gate must fail closed.
        code_enforce = cli.main(
            [
                "some-org/some-model",
                "--mode",
                "remote",
                "--quiet",
                "--fail-on",
                "never",
                "--enforce",
            ]
        )
        self.assertEqual(code_enforce, 1)

    def test_aibom_output(self):
        with tempfile.NamedTemporaryFile("r", encoding="utf-8", suffix=".json", delete=False) as f:
            aibom_path = f.name
        try:
            code = cli.main(
                [
                    str(BENIGN_FIXTURE),
                    "--mode",
                    "local",
                    "--quiet",
                    "--fail-on",
                    "never",
                    "--aibom",
                    aibom_path,
                ]
            )
            self.assertEqual(code, 0)
            with open(aibom_path, encoding="utf-8") as f:
                bom = json.load(f)
            self.assertEqual(bom["bomFormat"], "CycloneDX")
            self.assertEqual(bom["specVersion"], "1.6")
            self.assertGreaterEqual(len(bom["components"]), 1)
        finally:
            os.unlink(aibom_path)

    def test_runtime_policy_output(self):
        with tempfile.NamedTemporaryFile("r", encoding="utf-8", suffix=".json", delete=False) as f:
            policy_path = f.name
        try:
            code = cli.main(
                [
                    str(BENIGN_FIXTURE),
                    "--mode",
                    "local",
                    "--quiet",
                    "--fail-on",
                    "never",
                    "--runtime-policy",
                    policy_path,
                ]
            )
            self.assertEqual(code, 0)
            with open(policy_path, encoding="utf-8") as f:
                policy = json.load(f)
            self.assertEqual(policy["kind"], "RuntimePolicy")
            self.assertFalse(policy["spec"]["process"]["noNewPrivileges"] is False)
            self.assertEqual(policy["spec"]["network"]["egressPolicy"], "deny")
        finally:
            os.unlink(policy_path)

    def test_html_report_output(self):
        with tempfile.NamedTemporaryFile("r", encoding="utf-8", suffix=".html", delete=False) as f:
            report_path = f.name
        try:
            code = cli.main(
                [
                    str(MALICIOUS_FIXTURE),
                    "--mode",
                    "local",
                    "--format",
                    "html",
                    "--output",
                    report_path,
                    "--fail-on",
                    "never",
                ]
            )
            self.assertEqual(code, 0)
            with open(report_path, encoding="utf-8") as f:
                report = f.read()
            self.assertIn("HF Model Provenance Scanner Report", report)
            self.assertIn("Risk Assessment", report)
            self.assertIn("HFS-001", report)
        finally:
            os.unlink(report_path)


if __name__ == "__main__":
    unittest.main()
