"""
Tests for the real-time Hub monitor.

The monitor talks to the live Hub in production, so these tests stub out both
the "what's new" feed and the per-repo scan. We're testing the WATCHTOWER
LOGIC — dedup, hit/clean/skip classification, escalation firing — not the
scanner itself (that's covered elsewhere).
"""

import json
import os
import tempfile
import unittest
from unittest import mock

from scanner import monitor
from scanner.monitor import MonitorConfig, classify, watch


class TestClassify(unittest.TestCase):
    """The classifier is the operator's signal-vs-noise filter. If it's wrong,
    a real hit gets buried or a clean repo pages someone at 3am."""

    def test_hit_when_exit_code_1(self):
        report = {"exit_code": 1, "risk": {"level": "CRITICAL", "score": 100},
                  "findings": [{"severity": "critical"}]}
        self.assertEqual(classify(report), "HIT")

    def test_clean_when_exit_0_and_has_risk(self):
        report = {"exit_code": 0, "risk": {"level": "LOW", "score": 0}, "findings": []}
        self.assertEqual(classify(report), "CLEAN")

    def test_skipped_on_error(self):
        report = {"exit_code": 2, "error": "HTTP 404"}
        self.assertEqual(classify(report), "SKIPPED")

    def test_skipped_when_no_risk_key(self):
        # Empty repo: scan produced nothing parseable.
        report = {"exit_code": 2}
        self.assertEqual(classify(report), "SKIPPED")

    def test_hit_takes_priority_even_if_error_present(self):
        # If the scan tripped the threshold, that's a hit regardless of any
        # partial error noise in the report.
        report = {"exit_code": 1, "risk": {"level": "HIGH", "score": 60},
                  "findings": [{"severity": "high"}], "error": ""}
        self.assertEqual(classify(report), "HIT")


class TestWatchLoop(unittest.TestCase):
    """End-to-end loop behavior with the network stubbed."""

    def setUp(self):
        # Point the state file at a throwaway path so tests don't touch the
        # real ~/.cache dedupe file.
        self._tmp = tempfile.mkdtemp()
        self._state_patch = mock.patch.object(
            monitor, "STATE_FILE", os.path.join(self._tmp, "seen.json"))
        self._state_patch.start()

    def tearDown(self):
        self._state_patch.stop()

    def test_malicious_repo_fires_hit_and_escalation(self):
        """The whole point: a new repo that scans dirty must page the operator."""
        malicious_report = {
            "exit_code": 1,
            "risk": {"level": "CRITICAL", "score": 100},
            "findings": [{"severity": "critical", "rule_id": "HFS-001"}],
        }
        fired = []

        with mock.patch.object(monitor, "fetch_newest",
                               return_value=["evil-org/fake-openai-model"]), \
             mock.patch.object(monitor, "scan_one", return_value=malicious_report):
            cfg = MonitorConfig(poll_interval_sec=0)
            watch(cfg, on_hit=fired.append, max_iterations=1)

        # Escalation hook must have fired exactly once for the malicious repo.
        self.assertEqual(len(fired), 1)
        self.assertEqual(fired[0]["risk"]["level"], "CRITICAL")

    def test_clean_repo_does_not_escalate(self):
        clean_report = {"exit_code": 0, "risk": {"level": "LOW", "score": 0},
                        "findings": []}
        fired = []
        with mock.patch.object(monitor, "fetch_newest",
                               return_value=["good-org/legit-model"]), \
             mock.patch.object(monitor, "scan_one", return_value=clean_report):
            cfg = MonitorConfig(poll_interval_sec=0)
            watch(cfg, on_hit=lambda r: fired.append(r), max_iterations=1)
        self.assertEqual(len(fired), 0)

    def test_dedup_does_not_rescan_same_repo(self):
        """A repo seen on tick 1 must not be scanned again on tick 2. Without
        this the monitor would re-scan the same 50 repos every minute forever."""
        scan_calls = []

        def fake_scan(repo_id, cfg):
            scan_calls.append(repo_id)
            return {"exit_code": 0, "risk": {"level": "LOW", "score": 0}, "findings": []}

        # Same repo returned on both polls.
        with mock.patch.object(monitor, "fetch_newest",
                               return_value=["org/same-model"]), \
             mock.patch.object(monitor, "scan_one", side_effect=fake_scan):
            cfg = MonitorConfig(poll_interval_sec=0)
            watch(cfg, max_iterations=3)

        # Scanned once, not three times.
        self.assertEqual(scan_calls, ["org/same-model"])

    def test_state_persists_across_restart(self):
        """A repo cleared before a restart must not be rescanned after it."""
        clean = {"exit_code": 0, "risk": {"level": "LOW", "score": 0}, "findings": []}
        calls = []

        def fake_scan(repo_id, cfg):
            calls.append(repo_id)
            return clean

        with mock.patch.object(monitor, "fetch_newest", return_value=["org/m1"]), \
             mock.patch.object(monitor, "scan_one", side_effect=fake_scan):
            watch(MonitorConfig(poll_interval_sec=0), max_iterations=1)

        # "Restart": fresh watch() call, same repo in feed. Should NOT rescan
        # because state was persisted to disk.
        with mock.patch.object(monitor, "fetch_newest", return_value=["org/m1"]), \
             mock.patch.object(monitor, "scan_one", side_effect=fake_scan):
            watch(MonitorConfig(poll_interval_sec=0), max_iterations=1)

        self.assertEqual(calls, ["org/m1"])  # scanned once total, across both runs

    def test_fetch_failure_does_not_crash_loop(self):
        """A network blip returns [] from fetch_newest; the loop must survive."""
        with mock.patch.object(monitor, "fetch_newest", return_value=[]):
            # If this raised, the test would fail. Surviving is the assertion.
            watch(MonitorConfig(poll_interval_sec=0), max_iterations=2)


class TestFetchNewest(unittest.TestCase):
    """fetch_newest parses the live API shape and degrades gracefully."""

    def test_parses_model_ids(self):
        fake_payload = json.dumps([
            {"id": "org/a"}, {"id": "org/b"}, {"not_id": "junk"}
        ]).encode()
        fake_resp = mock.MagicMock()
        fake_resp.read.return_value = fake_payload
        fake_resp.__enter__ = lambda s: fake_resp
        fake_resp.__exit__ = lambda s, *a: False
        with mock.patch("urllib.request.urlopen", return_value=fake_resp):
            ids = monitor.fetch_newest(MonitorConfig())
        # The junk entry with no "id" is dropped, not crashed on.
        self.assertEqual(ids, ["org/a", "org/b"])

    def test_network_error_returns_empty(self):
        import urllib.error
        with mock.patch("urllib.request.urlopen",
                        side_effect=urllib.error.URLError("boom")):
            self.assertEqual(monitor.fetch_newest(MonitorConfig()), [])


if __name__ == "__main__":
    unittest.main()
