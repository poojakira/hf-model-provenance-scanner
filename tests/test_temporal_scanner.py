"""
Tests for temporal analysis / rug-pull detection.
Verifies baseline creation, comparison, and drift detection.
"""
import json
import os
import tempfile
import time
import unittest

from scanner.analyzer.temporal_scanner import (
    ScanBaseline,
    FileBaseline,
    compare_with_baseline,
    create_baseline,
    load_baseline,
    save_baseline,
)
from scanner.models import Finding, OrgCheckResult, RiskSummary, ScanResult, Severity


def _make_result(findings=None, risk_score=0, risk_level="LOW",
                 org_verified=True) -> ScanResult:
    result = ScanResult("test/model", "local", "0.2.0")
    result.findings = findings or []
    result.risk = RiskSummary(score=risk_score, level=risk_level, reasons=[])
    if org_verified is not None:
        result.org_check = OrgCheckResult(
            "test/model", "test", org_verified, [], 0.0, 100.0, 10.0)
    return result


class TestBaselineCreation(unittest.TestCase):
    def test_create_baseline_from_result(self):
        """Create a baseline from scan result with file hashes."""
        result = _make_result(risk_score=25, risk_level="MEDIUM")
        hashes = {
            "loader.py": ("abc123" * 6 + "ab", 1024),
            "model.safetensors": ("def456" * 6 + "de", 50_000_000),
        }
        baseline = create_baseline(result, hashes)
        self.assertEqual(baseline.scan_target, "test/model")
        self.assertEqual(baseline.risk_score, 25)
        self.assertEqual(baseline.risk_level, "MEDIUM")
        self.assertEqual(len(baseline.files), 2)

    def test_baseline_serialization_roundtrip(self):
        """Baseline can be saved to JSON and loaded back."""
        result = _make_result(risk_score=10)
        hashes = {"file.py": ("a" * 64, 512)}
        baseline = create_baseline(result, hashes)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                         delete=False) as f:
            path = f.name

        try:
            save_baseline(baseline, path)
            loaded = load_baseline(path)
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded.scan_target, "test/model")
            self.assertEqual(loaded.risk_score, 10)
            self.assertEqual(len(loaded.files), 1)
        finally:
            os.unlink(path)


class TestBaselineComparison(unittest.TestCase):
    def test_no_changes_no_findings(self):
        """Identical scan should produce no temporal findings."""
        baseline = ScanBaseline(
            scan_target="test/model",
            scanned_at=time.time() - 3600,
            scanner_version="0.2.0",
            risk_score=10,
            risk_level="LOW",
            total_findings=0,
            files=[FileBaseline("file.py", "a" * 64, 512, 0, None)],
            finding_rule_ids=[],
        )
        result = _make_result(risk_score=10)
        hashes = {"file.py": ("a" * 64, 512)}
        findings = compare_with_baseline(baseline, result, hashes)
        self.assertEqual(len(findings), 0)

    def test_risk_escalation_detected(self):
        """Significant risk score increase triggers finding."""
        baseline = ScanBaseline(
            scan_target="test/model",
            scanned_at=time.time() - 3600,
            scanner_version="0.2.0",
            risk_score=10,
            risk_level="LOW",
            total_findings=0,
            files=[],
            finding_rule_ids=[],
        )
        result = _make_result(risk_score=55, risk_level="HIGH")
        findings = compare_with_baseline(baseline, result, {})
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("HFS-062", rule_ids,
                      "Should detect risk escalation")

    def test_file_hash_change_with_findings(self):
        """File hash change combined with new findings = rug pull."""
        from scanner.rules.definitions import get_rule
        baseline = ScanBaseline(
            scan_target="test/model",
            scanned_at=time.time() - 3600,
            scanner_version="0.2.0",
            risk_score=10,
            risk_level="LOW",
            total_findings=0,
            files=[FileBaseline("loader.py", "a" * 64, 100, 0, None)],
            finding_rule_ids=[],
        )
        # New scan has findings in the changed file
        rule = get_rule("HFS-001")
        finding = Finding("HFS-001", Severity.CRITICAL, "loader.py",
                          5, 0, rule.description, "evidence", rule.remediation, rule.cwe)
        result = _make_result(findings=[finding], risk_score=50)
        hashes = {"loader.py": ("b" * 64, 200)}  # Hash changed
        temporal_findings = compare_with_baseline(baseline, result, hashes)
        rule_ids = [f.rule_id for f in temporal_findings]
        self.assertIn("HFS-061", rule_ids,
                      "Changed file with critical finding = rug pull")

    def test_new_file_with_critical_finding(self):
        """New file appearing with critical findings = suspicious."""
        from scanner.rules.definitions import get_rule
        baseline = ScanBaseline(
            scan_target="test/model",
            scanned_at=time.time() - 3600,
            scanner_version="0.2.0",
            risk_score=5,
            risk_level="LOW",
            total_findings=0,
            files=[],
            finding_rule_ids=[],
        )
        rule = get_rule("HFS-050")
        finding = Finding("HFS-050", Severity.CRITICAL, "evil.pkl",
                          0, 0, rule.description, "os.system", rule.remediation, rule.cwe)
        result = _make_result(findings=[finding], risk_score=50)
        hashes = {"evil.pkl": ("c" * 64, 5000)}
        temporal_findings = compare_with_baseline(baseline, result, hashes)
        rule_ids = [f.rule_id for f in temporal_findings]
        self.assertIn("HFS-061", rule_ids)

    def test_removed_security_artifact(self):
        """Removed signature/SBOM file triggers finding."""
        baseline = ScanBaseline(
            scan_target="test/model",
            scanned_at=time.time() - 3600,
            scanner_version="0.2.0",
            risk_score=5,
            risk_level="LOW",
            total_findings=0,
            files=[
                FileBaseline("model.sig", "d" * 64, 256, 0, None),
                FileBaseline("sbom.json", "e" * 64, 1024, 0, None),
            ],
            finding_rule_ids=[],
        )
        result = _make_result(risk_score=5)
        # No files present anymore
        findings = compare_with_baseline(baseline, result, {})
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("HFS-062", rule_ids,
                      "Should detect removed security artifacts")

    def test_org_verification_loss(self):
        """Loss of org verification status triggers finding."""
        baseline = ScanBaseline(
            scan_target="test/model",
            scanned_at=time.time() - 3600,
            scanner_version="0.2.0",
            risk_score=5,
            risk_level="LOW",
            total_findings=0,
            files=[],
            finding_rule_ids=[],
            org_verified=True,
            org_name="test",
        )
        result = _make_result(risk_score=5, org_verified=False)
        findings = compare_with_baseline(baseline, result, {})
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("HFS-062", rule_ids)


class TestBaselineLoadNonexistent(unittest.TestCase):
    def test_load_missing_file_returns_none(self):
        """Loading non-existent baseline returns None."""
        result = load_baseline("/nonexistent/path/baseline.json")
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
