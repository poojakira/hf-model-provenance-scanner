"""
Tests for advanced obfuscation detection.
Verifies detection of Unicode confusables, zero-width chars, bidi overrides, polyglots.
"""
import unittest

from scanner.analyzer.obfuscation_scanner import (
    analyze_obfuscation,
    scan_polyglot_header,
    scan_unicode_obfuscation,
)


class TestZeroWidthDetection(unittest.TestCase):
    def test_zero_width_space_detected(self):
        """Detect zero-width space characters in source."""
        source = 'x = "hello\u200bworld"  # hidden zero-width space\n'
        findings = scan_unicode_obfuscation("test.py", source)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("HFS-065", rule_ids)

    def test_zero_width_joiner_detected(self):
        """Detect zero-width joiner."""
        source = 'password\u200d = "secret"\n'
        findings = scan_unicode_obfuscation("test.py", source)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("HFS-065", rule_ids)

    def test_clean_source_no_findings(self):
        """Normal ASCII source should not trigger."""
        source = 'x = 42\ny = "hello world"\nprint(x + y)\n'
        findings = scan_unicode_obfuscation("test.py", source)
        self.assertEqual(len(findings), 0)


class TestBidiOverrideDetection(unittest.TestCase):
    def test_rlo_detected(self):
        """Detect RIGHT-TO-LEFT OVERRIDE character."""
        # RLO can make 'malicious' read as 'suoicilam' in display
        source = 'access = "\u202eguest\u202c"  # displays differently\n'
        findings = scan_unicode_obfuscation("test.py", source)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("HFS-064", rule_ids)

    def test_lro_detected(self):
        """Detect LEFT-TO-RIGHT OVERRIDE."""
        source = 'x = "\u202dtest"\n'
        findings = scan_unicode_obfuscation("test.py", source)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("HFS-064", rule_ids)


class TestConfusableDetection(unittest.TestCase):
    def test_cyrillic_a_in_identifier(self):
        """Detect Cyrillic 'а' mixed with Latin in same token."""
        # "p\u0430ss" — Cyrillic а looks like Latin a
        source = 'p\u0430ss = "secret"  # Cyrillic a in identifier\n'
        findings = scan_unicode_obfuscation("test.py", source)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("HFS-064", rule_ids)

    def test_cyrillic_o_in_identifier(self):
        """Detect Cyrillic 'о' in identifier."""
        source = 'imp\u043ert_m\u043edule = __import__  # fake import\n'
        findings = scan_unicode_obfuscation("test.py", source)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("HFS-064", rule_ids)

    def test_pure_ascii_no_confusable(self):
        """Pure ASCII identifiers should not trigger."""
        source = 'password = "secret"\nimport os\n'
        findings = scan_unicode_obfuscation("test.py", source)
        confusable = [f for f in findings if f.rule_id == "HFS-064"]
        self.assertEqual(len(confusable), 0)


class TestUnicodeEscapeDetection(unittest.TestCase):
    def test_long_unicode_escape_sequence(self):
        """Detect long Unicode escape sequences that may hide payloads."""
        source = r'cmd = "\u006f\u0073\u002e\u0073\u0079\u0073\u0074\u0065\u006d"' + "\n"
        findings = scan_unicode_obfuscation("test.py", source)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("HFS-066", rule_ids)


class TestPolyglotDetection(unittest.TestCase):
    def test_pdf_html_polyglot(self):
        """Detect PDF+HTML polyglot."""
        data = b"%PDF-1.4 " + b"\x00" * 100 + b"<script>alert(1)</script>"
        findings = scan_polyglot_header("test.pdf", data)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("HFS-067", rule_ids)

    def test_zip_html_polyglot(self):
        """Detect ZIP+HTML polyglot."""
        data = b"PK\x03\x04" + b"\x00" * 100 + b"<script>document.cookie</script>"
        findings = scan_polyglot_header("model.zip", data)
        rule_ids = [f.rule_id for f in findings]
        self.assertIn("HFS-067", rule_ids)

    def test_normal_file_no_polyglot(self):
        """Normal file should not trigger polyglot detection."""
        data = b"# This is a normal Python file\nimport os\n"
        findings = scan_polyglot_header("test.py", data)
        self.assertEqual(len(findings), 0)


class TestAnalyzeObfuscationIntegration(unittest.TestCase):
    def test_combined_detection(self):
        """Integration test: multiple obfuscation techniques."""
        source = (
            'p\u0430ssword = "sec\u200bret"  # Cyrillic a + zero-width\n'
            'x = "\u202eadmin\u202c"  # bidi override\n'
        )
        findings = analyze_obfuscation("test.py", source)
        rule_ids = set(f.rule_id for f in findings)
        # Should detect confusable, zero-width, and bidi
        self.assertTrue(len(rule_ids) >= 2,
                        f"Should detect multiple techniques, got: {rule_ids}")


if __name__ == "__main__":
    unittest.main()
