import json
import re
import unittest
from pathlib import Path


class TestRealtimeDashboard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html_path = Path(__file__).resolve().parents[1] / "dashboard" / "realtime" / "index.html"
        cls.html = cls.html_path.read_text(encoding="utf-8")

    def _js_array(self, name):
        match = re.search(rf"\b{name}=(\[[^\]]+\])", self.html)
        self.assertIsNotNone(match, f"missing {name} array")
        return json.loads(match.group(1))

    def test_dashboard_is_single_file_soc_experience(self):
        self.assertEqual(self.html.count("</html>"), 1)
        self.assertIn("SENTINEL HQ", self.html)
        self.assertIn("THREAT LEVEL: ELEVATED", self.html)
        self.assertIn("Simulated real-time attacks", self.html)
        self.assertIn("Chart.js/4.4.1/chart.umd.min.js", self.html)

    def test_dashboard_has_eight_required_pages(self):
        for page_id in [
            "command",
            "matrix",
            "products",
            "feed",
            "analytics",
            "actors",
            "incidents",
            "executive",
        ]:
            self.assertRegex(self.html, rf'<(?:section|nav|div)[^>]+id="{page_id}"')
        for label in [
            "Command Center",
            "ATT&CK Matrix",
            "Product Security Hub",
            "Live Threat Feed",
            "Analytics & Graphs",
            "Threat Actors",
            "Incident Response",
            "CEO Summary",
        ]:
            self.assertIn(label, self.html)

    def test_product_security_hub_uses_exact_product_names(self):
        self.assertEqual(
            self._js_array("products"),
            [
                "Web App",
                "Mobile App",
                "REST API Gateway",
                "Admin Dashboard",
                "Payment Processing Service",
                "Customer Database",
                "Email / Messaging Service",
                "Cloud Storage",
                "CI/CD Pipeline",
                "Internal HR / ERP System",
            ],
        )

    def test_threat_actors_use_exact_known_names_and_visible_fields(self):
        self.assertEqual(
            self._js_array("actors"),
            [
                "APT28",
                "Lazarus",
                "Volt Typhoon",
                "Sandworm",
                "Fancy Bear",
                "Cozy Bear",
                "REvil",
                "Conti",
                "LockBit",
                "Scattered Spider",
                "Kimsuky",
                "MuddyWater",
            ],
        )
        for marker in [
            "actorProfiles=",
            "Origin flag/country:",
            "T-IDs:",
            "Industries targeted:",
            "Last seen:",
            '?"active":"inactive"',
            "openActor(name)",
        ]:
            self.assertIn(marker, self.html)

    def test_dashboard_simulation_and_matrix_markers_are_present(self):
        for marker in [
            "Array.from({ length: 540 }",
            "30+ countries observed",
            "15 tactics",
            "222 techniques",
            "475 sub-techniques",
            "enterpriseTechniqueCatalog=Array.from({length:222}",
            "catalog=mode===\"Enterprise\"?enterpriseTechniqueCatalog",
            "T1566 Phishing",
            "T1059 Command and Scripting Interpreter",
            "T1055 Process Injection",
            "T1078 Valid Accounts",
            "T1190 Exploit Public-Facing Application",
            "T1133 External Remote Services",
            "T1071 Application Layer Protocol",
            "T1486 Data Encrypted for Impact",
            "T1003 OS Credential Dumping",
            "T1021 Remote Services",
            "setInterval(streamFeed,2000)",
            "setInterval(renderStats,3000)",
            "setInterval(updateCharts,10000)",
            "localStorage.setItem(\"sentinel-page\"",
        ]:
            self.assertIn(marker, self.html)

    def test_no_top_helper_or_direct_backend_api_dependency_or_attacker_contact(self):
        self.assertNotRegex(self.html, r"\b(?:const|let|var)\s+top\b|\btop\s*=\s*\(")
        forbidden = [
            "https://huggingface.co/api/",
            "https://api.github.com/",
            "fetch(",
            "XMLHttpRequest",
            "WebSocket",
            "EventSource",
            "navigator.sendBeacon",
            "mailto:",
            "smtp",
            "emailjs",
            "sendgrid",
        ]
        lower = self.html.lower()
        for marker in forbidden:
            self.assertNotIn(marker.lower(), lower)
        self.assertIn("CSV Mock Export", self.html)
        self.assertIn("window.print()", self.html)

    def test_dashboard_removes_old_live_scanner_surface(self):
        for marker in [
            "Scan live repository",
            "Load real scanner JSON",
            "HF Scanner Realtime Console",
            "No synthetic data is loaded",
            "Platform Abuse Report",
        ]:
            self.assertNotIn(marker, self.html)


if __name__ == "__main__":
    unittest.main()
