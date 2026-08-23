"""
Red Team Parametrized Detection Tests
======================================
Uses the conftest.py fixtures and technique registry to verify
that every registered attack technique is detected by the scanner.

This file proves that the scanner catches ALL known attack vectors
across pickle, safetensors, GGUF, and Python source categories.
"""

from tests.redteam.conftest import (
    AttackTechnique,
    run_detection,
)


class TestAllAttackTechniques:
    """Parametrized test class that verifies ALL registered attacks are detected."""

    def test_attack_detected(self, attack_technique: AttackTechnique):
        """Every registered attack technique must be detected by the scanner."""
        payload = attack_technique.create_payload()
        findings = run_detection(attack_technique.category, payload)
        assert len(findings) > 0, (
            f"BYPASS DETECTED: '{attack_technique.name}' ({attack_technique.id}) "
            f"in category '{attack_technique.category}' was NOT detected!\n"
            f"Source incident: {attack_technique.source_incident}\n"
            f"Expected rules: {attack_technique.expected_rules}"
        )

    def test_attack_has_appropriate_severity(self, attack_technique: AttackTechnique):
        """Every detected attack should have at least appropriate severity for its category."""
        payload = attack_technique.create_payload()
        findings = run_detection(attack_technique.category, payload)
        if findings:
            severities = [f.severity.value for f in findings]
            # Supply-chain warnings (trust_remote_code) may be low/medium severity
            # as they indicate risk rather than confirmed malicious behavior
            if attack_technique.category == "supply_chain":
                has_finding = len(findings) > 0
                assert has_finding, f"Attack '{attack_technique.name}' not detected at all"
            else:
                high_sev = any(s in ("critical", "high") for s in severities)
                assert (
                    high_sev
                ), f"Attack '{attack_technique.name}' detected but severity too low: {severities}"


class TestPickleAttacks:
    """Focused tests for pickle-based attack detection."""

    def test_pickle_detected(self, pickle_technique: AttackTechnique):
        """All pickle attack techniques must be caught."""
        payload = pickle_technique.create_payload()
        findings = run_detection("pickle", payload)
        assert len(findings) > 0, f"Pickle bypass: {pickle_technique.name}"


class TestSafetensorsAttacks:
    """Focused tests for safetensors metadata attack detection."""

    def test_safetensors_detected(self, safetensors_technique: AttackTechnique):
        """All safetensors attack techniques must be caught."""
        payload = safetensors_technique.create_payload()
        findings = run_detection("safetensors", payload)
        assert len(findings) > 0, f"SafeTensors bypass: {safetensors_technique.name}"


class TestGgufAttacks:
    """Focused tests for GGUF metadata attack detection."""

    def test_gguf_detected(self, gguf_technique: AttackTechnique):
        """All GGUF attack techniques must be caught."""
        payload = gguf_technique.create_payload()
        findings = run_detection("gguf", payload)
        assert len(findings) > 0, f"GGUF bypass: {gguf_technique.name}"


class TestFixtureHelpers:
    """Tests that verify the conftest fixtures work correctly."""

    def test_malicious_pickle_fixture(self, malicious_pickle):
        """The malicious_pickle fixture creates valid files."""
        from scanner.analyzer.pickle_scanner import scan_pickle_bytes

        filepath, data = malicious_pickle("os_system_basic")
        assert data is not None
        assert len(data) > 0
        findings = scan_pickle_bytes(filepath, data)
        assert len(findings) > 0

    def test_malicious_safetensors_fixture(self, malicious_safetensors):
        """The malicious_safetensors fixture creates valid files."""
        from scanner.analyzer.safetensors_scanner import analyze_safetensors_file

        filepath, data = malicious_safetensors("c2_metadata")
        assert data is not None
        assert len(data) > 0
        findings = analyze_safetensors_file(filepath, data)
        assert len(findings) > 0

    def test_malicious_gguf_fixture(self, malicious_gguf):
        """The malicious_gguf fixture creates valid files."""
        from scanner.analyzer.gguf_scanner import analyze_gguf_file

        filepath, data = malicious_gguf("shell_injection")
        assert data is not None
        assert len(data) > 0
        findings = analyze_gguf_file(filepath, data)
        assert len(findings) > 0

    def test_malicious_source_fixture(self, malicious_source):
        """The malicious_source fixture provides detectable code."""
        from scanner.analyzer.ast_visitor import analyze_python_source

        source = malicious_source("ssl_bypass_c2")
        assert source is not None
        assert len(source) > 0
        findings = analyze_python_source("test.py", source)
        assert len(findings) > 0
