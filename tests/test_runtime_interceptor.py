"""
Tests for the runtime interceptor and policy engine.

Verifies:
- torch.load() interception works (mock torch, verify scanner runs before load)
- Critical findings block the load
- Clean models pass through
- Policy violations raise appropriate exceptions
- Environment variable activation works
"""

import json
import os
import sys
import tempfile
import types
import unittest
from unittest import mock

from scanner.models import Finding, Severity
from scanner.runtime.interceptor import RuntimeInterceptor, SecurityError
from scanner.runtime.policy_engine import (
    PolicyEngine,
    PolicyViolation,
    RuntimePolicy,
    load_policy,
)


class TestTorchLoadInterception(unittest.TestCase):
    """Test that torch.load() monkey-patching works correctly."""

    def setUp(self):
        """Set up a fake torch module in sys.modules."""
        self.fake_torch = types.ModuleType("torch")
        self.original_load_called = False
        self.original_load_args = None

        def fake_load(f, *args, **kwargs):
            self.original_load_called = True
            self.original_load_args = (f, args, kwargs)
            return {"weights": "fake_tensor_data"}

        self.fake_torch.load = fake_load
        sys.modules["torch"] = self.fake_torch

        self.interceptor = RuntimeInterceptor()

    def tearDown(self):
        """Clean up the fake torch module."""
        self.interceptor.deactivate()
        if "torch" in sys.modules and sys.modules["torch"] is self.fake_torch:
            del sys.modules["torch"]

    def test_activation_patches_torch_load(self):
        """Activating should replace torch.load."""
        original_load = self.fake_torch.load
        self.interceptor.activate()
        self.assertNotEqual(self.fake_torch.load, original_load)
        self.assertTrue(self.interceptor.active)

    def test_deactivation_restores_torch_load(self):
        """Deactivating should restore the original torch.load."""
        original_load = self.fake_torch.load
        self.interceptor.activate()
        self.interceptor.deactivate()
        self.assertEqual(self.fake_torch.load, original_load)
        self.assertFalse(self.interceptor.active)

    def test_clean_file_passes_through(self):
        """A clean pickle file should pass through to the original torch.load."""
        # Create a benign pickle file (empty dict)
        import pickle

        with tempfile.NamedTemporaryFile(suffix=".pt", delete=False) as f:
            pickle.dump({"weights": [1, 2, 3]}, f)
            tmp_path = f.name

        try:
            self.interceptor.activate()
            result = self.fake_torch.load(tmp_path)
            self.assertTrue(self.original_load_called)
            self.assertEqual(result, {"weights": "fake_tensor_data"})
            self.assertEqual(self.interceptor.stats["scanned"], 1)
            self.assertEqual(self.interceptor.stats["blocked"], 0)
        finally:
            os.unlink(tmp_path)

    def test_critical_findings_block_load(self):
        """A file with critical findings should raise SecurityError."""
        # Create a pickle file with a dangerous payload (os.system call)

        # Build a malicious pickle manually using REDUCE opcode
        # This is: os.system("echo pwned")
        malicious_pickle = (
            b"\x80\x04\x95\x1e\x00\x00\x00\x00\x00\x00\x00"
            b"\x8c\x02os\x8c\x06system\x93"
            b"\x8c\x0becho pwned\x85R."
        )

        with tempfile.NamedTemporaryFile(suffix=".pt", delete=False) as f:
            f.write(malicious_pickle)
            tmp_path = f.name

        try:
            self.interceptor.activate()
            with self.assertRaises(SecurityError) as ctx:
                self.fake_torch.load(tmp_path)

            self.assertIn("critical", str(ctx.exception).lower())
            self.assertFalse(self.original_load_called)
            self.assertEqual(self.interceptor.stats["blocked"], 1)
        finally:
            os.unlink(tmp_path)

    def test_scanner_runs_before_load(self):
        """Scanner should run BEFORE the original load is called."""
        import pickle

        call_order = []

        # Override original load to record order
        def tracking_load(f, *args, **kwargs):
            call_order.append("load")
            return {"data": "ok"}

        self.fake_torch.load = tracking_load
        # Need to re-create interceptor since we changed fake_torch.load
        sys.modules["torch"] = self.fake_torch
        self.interceptor = RuntimeInterceptor()

        # Override scanner to record order
        original_scan = self.interceptor._scan_file

        def tracking_scan(path):
            call_order.append("scan")
            return original_scan(path)

        self.interceptor._scan_file = tracking_scan

        with tempfile.NamedTemporaryFile(suffix=".pt", delete=False) as f:
            pickle.dump({"safe": True}, f)
            tmp_path = f.name

        try:
            self.interceptor.activate()
            self.fake_torch.load(tmp_path)
            self.assertEqual(call_order, ["scan", "load"])
        finally:
            os.unlink(tmp_path)

    def test_nonexistent_file_passes_through(self):
        """A nonexistent file path should pass through (scanner returns no findings)."""
        self.interceptor.activate()
        # The interceptor will scan (find nothing), then call original
        result = self.fake_torch.load("/nonexistent/model.pt")
        self.assertTrue(self.original_load_called)
        self.assertEqual(result, {"weights": "fake_tensor_data"})

    def test_stats_tracking(self):
        """Stats should track scanned and blocked counts."""
        import pickle

        self.interceptor.activate()

        # Scan a clean file
        with tempfile.NamedTemporaryFile(suffix=".pt", delete=False) as f:
            pickle.dump({"clean": True}, f)
            tmp_path = f.name

        try:
            self.fake_torch.load(tmp_path)
            self.assertEqual(self.interceptor.stats["scanned"], 1)
            self.assertEqual(self.interceptor.stats["blocked"], 0)
            self.assertTrue(self.interceptor.stats["active"])
        finally:
            os.unlink(tmp_path)


class TestTransformersInterception(unittest.TestCase):
    """Test that transformers.AutoModel.from_pretrained() interception works."""

    def setUp(self):
        """Set up a fake transformers module."""
        self.fake_transformers = types.ModuleType("transformers")
        self.from_pretrained_called = False

        class FakeAutoModel:
            @classmethod
            def from_pretrained(cls, name_or_path, *args, **kwargs):
                self.from_pretrained_called = True
                return {"model": "fake"}

        self.fake_transformers.AutoModel = FakeAutoModel
        sys.modules["transformers"] = self.fake_transformers
        self.interceptor = RuntimeInterceptor()

    def tearDown(self):
        self.interceptor.deactivate()
        if "transformers" in sys.modules and sys.modules["transformers"] is self.fake_transformers:
            del sys.modules["transformers"]

    def test_clean_model_directory_passes(self):
        """A directory with clean files should pass through."""
        import pickle

        with tempfile.TemporaryDirectory() as model_dir:
            # Create a clean .bin file
            with open(os.path.join(model_dir, "model.bin"), "wb") as f:
                pickle.dump({"layer1": [0.1, 0.2]}, f)

            self.interceptor.activate()
            result = self.fake_transformers.AutoModel.from_pretrained(model_dir)
            self.assertTrue(self.from_pretrained_called)
            self.assertEqual(result, {"model": "fake"})

    def test_malicious_model_directory_blocked(self):
        """A directory with malicious pickle should be blocked."""
        malicious_pickle = (
            b"\x80\x04\x95\x1e\x00\x00\x00\x00\x00\x00\x00"
            b"\x8c\x02os\x8c\x06system\x93"
            b"\x8c\x0becho pwned\x85R."
        )

        with tempfile.TemporaryDirectory() as model_dir:
            with open(os.path.join(model_dir, "model.bin"), "wb") as f:
                f.write(malicious_pickle)

            self.interceptor.activate()
            with self.assertRaises(SecurityError):
                self.fake_transformers.AutoModel.from_pretrained(model_dir)
            self.assertFalse(self.from_pretrained_called)


class TestPolicyEngine(unittest.TestCase):
    """Test the runtime policy enforcement engine."""

    def test_load_default_policy(self):
        """Loading with no path returns default policy."""
        policy = load_policy(None)
        self.assertIsInstance(policy, RuntimePolicy)
        self.assertEqual(policy.max_memory_mb, 4096)

    def test_load_policy_from_json(self):
        """Policy should load correctly from JSON file."""
        policy_data = {
            "network": {
                "allowed_endpoints": ["api.huggingface.co:443", "cdn-lfs.huggingface.co:443"],
                "action": "block",
            },
            "process": {
                "allow_child_processes": False,
                "action": "block",
            },
            "filesystem": {
                "allowed_write_dirs": ["/tmp", "/output"],
                "action": "alert",
            },
            "resources": {
                "max_memory_mb": 2048,
                "action": "alert",
            },
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(policy_data, f)
            policy_path = f.name

        try:
            policy = load_policy(policy_path)
            self.assertEqual(
                policy.allowed_endpoints, ["api.huggingface.co:443", "cdn-lfs.huggingface.co:443"]
            )
            self.assertEqual(policy.network_action, "block")
            self.assertFalse(policy.allow_child_processes)
            self.assertEqual(policy.max_memory_mb, 2048)
        finally:
            os.unlink(policy_path)

    def test_network_block_non_allowlisted(self):
        """Connections to non-allowlisted endpoints should raise PolicyViolation."""
        policy = RuntimePolicy(
            allowed_endpoints=["api.huggingface.co:443"],
            network_action="block",
        )
        engine = PolicyEngine(policy=policy)

        # Allowed endpoint passes
        engine.check_network_connection("api.huggingface.co", 443)

        # Non-allowlisted endpoint raises
        with self.assertRaises(PolicyViolation) as ctx:
            engine.check_network_connection("evil-server.com", 4444)
        self.assertIn("not_allowlisted", ctx.exception.rule)

    def test_network_log_action(self):
        """Log action should not raise, just record alert."""
        policy = RuntimePolicy(
            allowed_endpoints=["safe.host:443"],
            network_action="log",
        )
        engine = PolicyEngine(policy=policy)

        # Should not raise
        engine.check_network_connection("unknown.host", 80)
        alerts = engine.get_alerts()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].action, "log")

    def test_child_process_blocked(self):
        """Spawning child processes should raise when blocked."""
        policy = RuntimePolicy(
            allow_child_processes=False,
            process_action="block",
        )
        engine = PolicyEngine(policy=policy)

        with self.assertRaises(PolicyViolation) as ctx:
            engine.check_child_process("/usr/bin/curl", ["curl", "http://evil.com"])
        self.assertIn("child_spawn_blocked", ctx.exception.rule)

    def test_child_process_allowed_executable(self):
        """Allowed executables should not trigger violations."""
        policy = RuntimePolicy(
            allow_child_processes=True,
            allowed_executables=["/usr/bin/python", "python"],
            process_action="block",
        )
        engine = PolicyEngine(policy=policy)

        # Allowed executable should not raise
        engine.check_child_process("/usr/bin/python", ["python", "-c", "print('hi')"])

        # Disallowed should raise
        with self.assertRaises(PolicyViolation):
            engine.check_child_process("/usr/bin/curl", ["curl", "http://evil.com"])

    def test_file_write_outside_allowed_dirs(self):
        """Writes outside allowed directories should trigger violations."""
        policy = RuntimePolicy(
            allowed_write_dirs=[tempfile.gettempdir()],
            filesystem_action="block",
        )
        engine = PolicyEngine(policy=policy)

        # Write to temp dir is fine
        engine.check_file_write(os.path.join(tempfile.gettempdir(), "test.txt"))

        # Write outside is blocked
        with self.assertRaises(PolicyViolation) as ctx:
            engine.check_file_write("/etc/shadow")
        self.assertIn("not_allowlisted", ctx.exception.rule)

    def test_blocked_write_paths(self):
        """Writes to explicitly blocked paths should be caught."""
        policy = RuntimePolicy(
            blocked_write_paths=["/etc", "/sys"],
            filesystem_action="block",
        )
        engine = PolicyEngine(policy=policy)

        with self.assertRaises(PolicyViolation) as ctx:
            engine.check_file_write("/etc/passwd")
        self.assertIn("blocked_path", ctx.exception.rule)

    def test_memory_limit_exceeded(self):
        """Memory exceeding limit should trigger violation."""
        policy = RuntimePolicy(
            max_memory_mb=1024,
            resource_action="block",
        )
        engine = PolicyEngine(policy=policy)

        # Under limit is fine
        engine.check_memory_usage(512)

        # Over limit raises
        with self.assertRaises(PolicyViolation) as ctx:
            engine.check_memory_usage(2048)
        self.assertIn("memory_exceeded", ctx.exception.rule)

    def test_alert_action_records_without_raising(self):
        """Alert action should record alert but not raise."""
        policy = RuntimePolicy(
            allow_child_processes=False,
            process_action="alert",
        )
        engine = PolicyEngine(policy=policy)

        # Should not raise, but record alert
        engine.check_child_process("/usr/bin/wget", ["wget", "http://evil.com"])
        alerts = engine.get_alerts()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule, "process.child_spawn_blocked")
        self.assertEqual(alerts[0].action, "alert")

    def test_clear_alerts(self):
        """clear_alerts should empty the alert list."""
        policy = RuntimePolicy(
            allow_child_processes=False,
            process_action="alert",
        )
        engine = PolicyEngine(policy=policy)
        engine.check_child_process("/bin/sh", ["sh"])
        self.assertEqual(len(engine.get_alerts()), 1)
        engine.clear_alerts()
        self.assertEqual(len(engine.get_alerts()), 0)

    def test_nonexistent_policy_file_returns_defaults(self):
        """Nonexistent policy file should return default policy."""
        policy = load_policy("/nonexistent/policy.json")
        self.assertIsInstance(policy, RuntimePolicy)
        self.assertEqual(policy.max_memory_mb, 4096)


class TestEnvironmentVariableActivation(unittest.TestCase):
    """Test that the HF_SCANNER_PROTECT env var activates protection."""

    def test_env_var_activation(self):
        """Setting HF_SCANNER_PROTECT=1 should activate protection."""
        # We test this by importing the module with the env var set
        # First, remove any cached module
        for mod_name in list(sys.modules.keys()):
            if mod_name.startswith("scanner.runtime"):
                del sys.modules[mod_name]

        # Set up fake torch before import
        fake_torch = types.ModuleType("torch")
        fake_torch.load = lambda f, *a, **k: None
        sys.modules["torch"] = fake_torch

        try:
            with mock.patch.dict(os.environ, {"HF_SCANNER_PROTECT": "1"}):
                # Force re-import of the module
                import importlib

                import scanner.runtime

                importlib.reload(scanner.runtime)

                self.assertTrue(scanner.runtime.is_protected())

            # Clean up: disable and remove env influence
            scanner.runtime.disable_protection()
        finally:
            if "torch" in sys.modules and sys.modules["torch"] is fake_torch:
                del sys.modules["torch"]
            # Reload without env var to reset state
            for mod_name in list(sys.modules.keys()):
                if mod_name.startswith("scanner.runtime"):
                    del sys.modules[mod_name]

    def test_env_var_not_set_no_activation(self):
        """Without the env var, protection should not auto-activate."""
        for mod_name in list(sys.modules.keys()):
            if mod_name.startswith("scanner.runtime"):
                del sys.modules[mod_name]

        try:
            with mock.patch.dict(os.environ, {}, clear=False):
                # Ensure env var is NOT set
                os.environ.pop("HF_SCANNER_PROTECT", None)
                import importlib

                import scanner.runtime

                importlib.reload(scanner.runtime)
                self.assertFalse(scanner.runtime.is_protected())
        finally:
            for mod_name in list(sys.modules.keys()):
                if mod_name.startswith("scanner.runtime"):
                    del sys.modules[mod_name]


class TestEnableDisableAPI(unittest.TestCase):
    """Test the enable_protection/disable_protection API."""

    def setUp(self):
        # Set up fake torch
        self.fake_torch = types.ModuleType("torch")
        self.fake_torch.load = lambda f, *a, **k: {"result": "ok"}
        sys.modules["torch"] = self.fake_torch

    def tearDown(self):
        if "torch" in sys.modules and sys.modules["torch"] is self.fake_torch:
            del sys.modules["torch"]
        # Reset module state
        for mod_name in list(sys.modules.keys()):
            if mod_name.startswith("scanner.runtime"):
                del sys.modules[mod_name]

    def test_enable_disable_cycle(self):
        """enable -> disable should cleanly toggle protection."""
        from scanner.runtime import disable_protection, enable_protection, is_protected

        interceptor = enable_protection()
        self.assertTrue(is_protected())
        self.assertTrue(interceptor.active)

        disable_protection()
        self.assertFalse(is_protected())

    def test_enable_with_policy_path(self):
        """enable_protection should accept a policy_path argument."""
        from scanner.runtime import disable_protection, enable_protection

        policy_data = {"network": {"allowed_endpoints": ["safe.host:443"], "action": "block"}}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(policy_data, f)
            policy_path = f.name

        try:
            interceptor = enable_protection(policy_path=policy_path)
            self.assertTrue(interceptor.active)
            self.assertEqual(interceptor.policy_path, policy_path)
            disable_protection()
        finally:
            os.unlink(policy_path)

    def test_double_enable_is_idempotent(self):
        """Calling enable_protection twice should not double-patch."""
        from scanner.runtime import disable_protection, enable_protection

        i1 = enable_protection()
        i2 = enable_protection()
        self.assertIs(i1, i2)
        disable_protection()


class TestSecurityErrorDetails(unittest.TestCase):
    """Test SecurityError carries finding details."""

    def test_security_error_has_findings(self):
        """SecurityError should carry the findings that triggered it."""
        findings = [
            Finding(
                rule_id="PKL001",
                severity=Severity.CRITICAL,
                file_path="model.pt",
                line_number=0,
                column=0,
                message="os.system detected",
                evidence="os.system",
                remediation="Remove the payload",
                cwe="CWE-502",
            )
        ]
        err = SecurityError("Blocked!", findings=findings)
        self.assertEqual(len(err.findings), 1)
        self.assertEqual(err.findings[0].rule_id, "PKL001")
        self.assertIn("Blocked!", str(err))


if __name__ == "__main__":
    unittest.main()
