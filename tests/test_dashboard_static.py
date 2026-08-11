import json
import re
import unittest
from pathlib import Path


class TestStaticDashboard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html_path = (
            Path(__file__).resolve().parents[1] / "dashboard" / "realtime" / "index.html"
        )
        cls.html = cls.html_path.read_text(encoding="utf-8")

    def _js_array(self, name):
        match = re.search(rf"\b{name}=(\[[^\]]+\])", self.html)
        self.assertIsNotNone(match, f"missing {name} array")
        return json.loads(match.group(1))

    def test_dashboard_is_single_file_static_soc_experience(self):
        self.assertEqual(self.html.count("</html>"), 1)
        self.assertIn("HF Model Provenance Scanner / Static Security Ops", self.html)
        self.assertIn("Telemetry is deterministic synthetic data", self.html)
        self.assertIn("Chart.js/4.4.1/chart.umd.min.js", self.html)
        self.assertIn("three.js/0.160.0/three.min.js", self.html)

    def test_dashboard_has_expected_static_surface(self):
        for element_id in [
            "sceneHost",
            "threatScene",
            "fallbackMap",
            "metrics",
            "stages",
            "queue",
            "matrix",
            "feed",
            "severityChart",
            "blocksChart",
            "coverageChart",
        ]:
            self.assertRegex(self.html, rf'<(?:canvas|section|nav|div)[^>]+id="{element_id}"')
        for label in [
            "Model Intake Replay",
            "Supply Chain Stages",
            "Containment Queue",
            "3D Threat Map / Model Provenance Graph",
            "ATT&CK And ML Supply-Chain Pressure",
            "Threat Feed",
            "Risk Distribution",
            "Scanner Coverage",
            "Operator Notes",
        ]:
            self.assertIn(label, self.html)

    def test_dashboard_uses_expected_model_supply_chain_fixture_values(self):
        self.assertEqual(
            self._js_array("models"),
            [
                "llama-guard-ops",
                "bert-phish-detector",
                "clip-safety-gate",
                "fraud-xgb-prod",
                "mistral-rag-filter",
                "resnet-malware-v2",
                "tabular-risk-lgbm",
                "voice-id-encoder",
            ],
        )
        self.assertEqual(
            self._js_array("sources"),
            [
                "hf://community",
                "s3://model-drop",
                "ghcr.io/runner",
                "registry.internal",
                "notebook-upload",
                "partner-sftp",
                "ci-artifact",
                "mirror-cache",
            ],
        )

    def test_dashboard_simulation_and_matrix_markers_are_present(self):
        for marker in [
            "const tactics=",
            "const signals=",
            "const stages=",
            "const events=Array.from({length:96}",
            "pickle opcode chain",
            "unsigned safetensors",
            "model card drift",
            "hash mismatch",
            "dependency confusion",
            "weight poisoning",
            "setInterval(stream,2400)",
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
        self.assertIn("No build step required", self.html)

    def test_dashboard_avoids_live_scanner_claims(self):
        for marker in [
            "Realtime Security Ops",
            "Realtime SOC",
            "real-time",
            "live-looking",
            "Scanner Online",
            "Scan live repository",
            "Load real scanner JSON",
            "HF Scanner Realtime Console",
            "No synthetic data is loaded",
            "Platform Abuse Report",
        ]:
            self.assertNotIn(marker, self.html)


if __name__ == "__main__":
    unittest.main()
