"""
Tests for the dynamic IOC feed system.
Verifies local loading, merging, caching, and IOC checking.
"""
import json
import os
import tempfile
import unittest

from scanner.analyzer.ioc_feed import (
    IOCDatabase,
    build_ioc_database,
    check_ioc,
    _load_local_iocs,
    _merge_feed,
)


class TestLocalIOCLoading(unittest.TestCase):
    def test_load_bundled_iocs(self):
        """Should load the bundled iocs.json file."""
        iocs = _load_local_iocs()
        self.assertIn("domains", iocs)
        self.assertIn("jsonkeeper.com", iocs["domains"])
        self.assertIn("dangerous_packages", iocs)
        self.assertIn("vulnerable_versions", iocs)

    def test_build_database_offline(self):
        """Build database in no-network mode uses local data."""
        db = build_ioc_database(no_network=True)
        self.assertIn("jsonkeeper.com", db.domains)
        self.assertIn("pastebin.com", db.domains)
        self.assertIn(".top", db.suspicious_tlds)
        self.assertIn("pickle5", db.dangerous_packages)
        self.assertIn("transformers", db.vulnerable_versions)


class TestIOCMerging(unittest.TestCase):
    def test_merge_feed_into_database(self):
        """Remote feed data should merge into the database."""
        db = IOCDatabase()
        feed = {
            "domains": ["new-evil.com", "c2-server.xyz"],
            "suspicious_tlds": [".evil"],
            "dangerous_packages": ["evil-package"],
            "ip_addresses": ["1.2.3.4"],
            "sha256_hashes": ["AABB" * 16],
            "urls": ["https://evil.com/payload"],
            "vulnerable_versions": {"newpkg": "1.0.0"},
        }
        _merge_feed(db, feed)
        self.assertIn("new-evil.com", db.domains)
        self.assertIn("c2-server.xyz", db.domains)
        self.assertIn(".evil", db.suspicious_tlds)
        self.assertIn("evil-package", db.dangerous_packages)
        self.assertIn("1.2.3.4", db.ip_addresses)
        self.assertIn("aabb" * 16, db.sha256_hashes)  # lowercased
        self.assertIn("https://evil.com/payload", db.urls)
        self.assertEqual(db.vulnerable_versions["newpkg"], "1.0.0")

    def test_merge_deduplicates(self):
        """Merging same data twice should not create duplicates."""
        db = IOCDatabase()
        feed = {"domains": ["evil.com", "evil.com"]}
        _merge_feed(db, feed)
        _merge_feed(db, feed)
        self.assertEqual(len([d for d in db.domains if d == "evil.com"]), 1)

    def test_merge_keeps_higher_version(self):
        """Should keep the higher minimum version."""
        db = IOCDatabase()
        db.vulnerable_versions["pkg"] = "1.0.0"
        feed = {"vulnerable_versions": {"pkg": "2.0.0"}}
        _merge_feed(db, feed)
        self.assertEqual(db.vulnerable_versions["pkg"], "2.0.0")

    def test_merge_does_not_downgrade_version(self):
        """Should not downgrade an existing version."""
        db = IOCDatabase()
        db.vulnerable_versions["pkg"] = "3.0.0"
        feed = {"vulnerable_versions": {"pkg": "1.0.0"}}
        _merge_feed(db, feed)
        self.assertEqual(db.vulnerable_versions["pkg"], "3.0.0")


class TestIOCChecking(unittest.TestCase):
    def setUp(self):
        self.db = IOCDatabase()
        self.db.domains = {"evil.com", "malware.xyz"}
        self.db.suspicious_tlds = {".top", ".xyz"}
        self.db.ip_addresses = {"192.168.1.100"}
        self.db.sha256_hashes = {"a" * 64}
        self.db.urls = {"https://evil.com/payload.sh"}

    def test_exact_domain_match(self):
        """Exact domain match should return 'domain'."""
        result = check_ioc("evil.com", self.db)
        self.assertEqual(result, "domain")

    def test_subdomain_match(self):
        """Subdomain of known domain should match."""
        result = check_ioc("staging.evil.com", self.db)
        self.assertEqual(result, "domain")

    def test_suspicious_tld_match(self):
        """Domain with suspicious TLD should match."""
        result = check_ioc("random-domain.top", self.db)
        self.assertEqual(result, "suspicious_tld")

    def test_ip_match(self):
        """Known malicious IP should match."""
        result = check_ioc("192.168.1.100", self.db)
        self.assertEqual(result, "ip_address")

    def test_hash_match(self):
        """Known malicious hash should match."""
        result = check_ioc("a" * 64, self.db)
        self.assertEqual(result, "known_malicious_hash")

    def test_url_match(self):
        """Known malicious URL should match."""
        result = check_ioc("https://evil.com/payload.sh", self.db)
        self.assertEqual(result, "known_malicious_url")

    def test_clean_domain_no_match(self):
        """Legitimate domain should not match."""
        result = check_ioc("google.com", self.db)
        self.assertIsNone(result)

    def test_case_insensitive(self):
        """Matching should be case-insensitive."""
        result = check_ioc("EVIL.COM", self.db)
        self.assertEqual(result, "domain")


class TestIOCDatabaseSerialization(unittest.TestCase):
    def test_to_dict(self):
        """Database should serialize to sorted dict."""
        db = IOCDatabase()
        db.domains = {"b.com", "a.com"}
        d = db.to_dict()
        self.assertEqual(d["domains"], ["a.com", "b.com"])


if __name__ == "__main__":
    unittest.main()
