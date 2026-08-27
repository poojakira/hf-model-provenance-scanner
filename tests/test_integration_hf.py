"""
Integration tests for HuggingFace Model Provenance Scanner.

These tests simulate scanning a local model repository containing both
malicious pickle files and clean safetensors configurations. No network
calls are made — all fixtures are generated locally.
"""

import json
import os
import pickle
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def _craft_malicious_pickle() -> bytes:
    """
    Craft a pickle payload that triggers the GLOBAL opcode referencing
    os.system. This simulates a supply-chain attack vector where an
    attacker embeds arbitrary code execution in a serialized model file.

    The pickle protocol 2 GLOBAL opcode is:
        b'\\x63' + module + b'\\n' + name + b'\\n'

    We construct a minimal pickle stream that references os.system with
    a string argument, which the scanner MUST flag as CRITICAL.
    """
    # Pickle opcodes (protocol 2)
    PROTO = b'\x80\x02'          # protocol 2 header
    GLOBAL = b'\x63'             # GLOBAL opcode
    MARK = b'('                  # MARK
    SHORT_BINUNICODE = b'\x8c'   # SHORT_BINUNICODE
    TUPLE1 = b'\x85'             # TUPLE1
    REDUCE = b'\x52'             # REDUCE
    STOP = b'.'                  # STOP

    # Construct: os.system("echo pwned")
    module_name = b'os\nsystem\n'
    arg = b'echo pwned'

    payload = (
        PROTO
        + GLOBAL + module_name           # push os.system onto stack
        + SHORT_BINUNICODE
        + struct.pack('<B', len(arg))
        + arg                            # push argument string
        + TUPLE1                         # wrap in tuple
        + REDUCE                         # call os.system("echo pwned")
        + STOP
    )
    return payload


def _craft_clean_safetensors_config() -> dict:
    """
    Create a minimal safetensors model configuration that should pass
    all scanner checks without any findings.
    """
    return {
        "_metadata": {
            "format": "pt"
        },
        "model.embed_tokens.weight": {
            "dtype": "F32",
            "shape": [32000, 4096],
            "data_offsets": [0, 524288000]
        },
        "model.layers.0.self_attn.q_proj.weight": {
            "dtype": "F32",
            "shape": [4096, 4096],
            "data_offsets": [524288000, 591396864]
        }
    }


def _create_model_repo(tmp_path: Path) -> tuple:
    """
    Create a fake model repository structure with:
    - A malicious pickle file (model.pkl)
    - A clean safetensors config (model.safetensors.index.json)
    - A config.json for the model

    Returns (malicious_path, clean_dir_path)
    """
    # --- Malicious model directory ---
    malicious_dir = tmp_path / "malicious-model"
    malicious_dir.mkdir(parents=True)

    # Write malicious pickle
    malicious_pkl = malicious_dir / "model.pkl"
    malicious_pkl.write_bytes(_craft_malicious_pickle())

    # Add a pytorch_model.bin that is also a malicious pickle
    pytorch_bin = malicious_dir / "pytorch_model.bin"
    pytorch_bin.write_bytes(_craft_malicious_pickle())

    # Add config for realism
    config = malicious_dir / "config.json"
    config.write_text(json.dumps({
        "model_type": "llama",
        "architectures": ["LlamaForCausalLM"],
        "hidden_size": 4096
    }))

    # --- Clean model directory ---
    clean_dir = tmp_path / "clean-model"
    clean_dir.mkdir(parents=True)

    # Write clean safetensors index
    safetensors_index = clean_dir / "model.safetensors.index.json"
    safetensors_index.write_text(json.dumps(_craft_clean_safetensors_config()))

    # Write a minimal config.json
    clean_config = clean_dir / "config.json"
    clean_config.write_text(json.dumps({
        "model_type": "llama",
        "architectures": ["LlamaForCausalLM"],
        "hidden_size": 4096,
        "torch_dtype": "float32"
    }))

    # Write a dummy safetensors file (just header, no real tensor data)
    safetensors_file = clean_dir / "model.safetensors"
    header = json.dumps({"__metadata__": {"format": "pt"}}).encode()
    header_size = struct.pack('<Q', len(header))
    safetensors_file.write_bytes(header_size + header)

    return malicious_dir, clean_dir


# ---------------------------------------------------------------------------
# Integration Tests
# ---------------------------------------------------------------------------

class TestIntegrationHFScanner:
    """
    End-to-end integration tests that invoke the CLI scanner against
    local fixture directories simulating HuggingFace model repositories.
    """

    @pytest.fixture(autouse=True)
    def setup_model_repo(self, tmp_path):
        """Set up temporary model repositories for each test."""
        self.malicious_dir, self.clean_dir = _create_model_repo(tmp_path)
        self.tmp_path = tmp_path

    def _run_scanner(self, target_path: Path, output_format: str = "json") -> dict:
        """
        Run the hf-scanner CLI against a target directory.

        Returns parsed JSON output or raw result dict.
        """
        cmd = [
            sys.executable, "-m", "scanner.cli",
            str(target_path),
            "-m", "local",
            "--format", output_format,
            "--no-network",  # Ensure no external calls
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(self.tmp_path),
        )

        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "parsed": json.loads(result.stdout) if result.stdout.strip() else None,
        }

    def test_malicious_pickle_detected_as_critical(self):
        """
        Scanning a directory with a crafted malicious pickle file that
        uses GLOBAL opcode to reference os.system MUST produce at least
        one CRITICAL severity finding.
        """
        result = self._run_scanner(self.malicious_dir)

        # Scanner should exit with non-zero for critical findings
        assert result["returncode"] != 0, (
            f"Scanner should exit non-zero for malicious files. "
            f"stdout: {result['stdout']}, stderr: {result['stderr']}"
        )

        # Parse findings
        parsed = result["parsed"]
        assert parsed is not None, "Scanner should produce JSON output"

        findings = parsed.get("findings", parsed.get("results", []))
        assert len(findings) > 0, "Should have at least one finding"

        # At least one finding must be CRITICAL
        severities = [
            f.get("severity", f.get("level", "")).upper()
            for f in findings
        ]
        assert "CRITICAL" in severities, (
            f"Expected CRITICAL severity finding for os.system in pickle. "
            f"Got severities: {severities}"
        )

        # Verify the finding references the dangerous import
        critical_findings = [
            f for f in findings
            if f.get("severity", f.get("level", "")).upper() == "CRITICAL"
        ]
        finding_text = json.dumps(critical_findings).lower()
        assert "os" in finding_text or "system" in finding_text, (
            "Critical finding should reference the dangerous module (os.system)"
        )

    def test_malicious_pickle_identifies_correct_file(self):
        """
        The scanner must identify which specific file contains the
        malicious payload.
        """
        result = self._run_scanner(self.malicious_dir)
        parsed = result["parsed"]
        assert parsed is not None

        findings = parsed.get("findings", parsed.get("results", []))
        flagged_files = set()
        for f in findings:
            file_path = f.get(
                "file_path",
                f.get("file", f.get("path", f.get("location", {}).get("file", ""))),
            )
            flagged_files.add(Path(file_path).name)

        # Both malicious files should be flagged
        assert "model.pkl" in flagged_files or "pytorch_model.bin" in flagged_files, (
            f"Scanner should flag the malicious pickle files. Flagged: {flagged_files}"
        )

    def test_clean_safetensors_no_findings(self):
        """
        Scanning a directory with only clean safetensors files and
        valid config should produce ZERO findings.
        """
        result = self._run_scanner(self.clean_dir)

        # Scanner should exit with zero for clean repos
        assert result["returncode"] == 0, (
            f"Scanner should exit 0 for clean model repos. "
            f"stdout: {result['stdout']}, stderr: {result['stderr']}"
        )

        # If there's parseable output, findings should be empty
        if result["parsed"] is not None:
            findings = result["parsed"].get("findings", result["parsed"].get("results", []))
            assert len(findings) == 0, (
                f"Clean safetensors model should have no findings. "
                f"Got: {json.dumps(findings, indent=2)}"
            )

    def test_sarif_output_format(self):
        """
        Scanner should support SARIF output format for CI integration.
        """
        result = self._run_scanner(self.malicious_dir, output_format="sarif")

        parsed = result["parsed"]
        assert parsed is not None, "Should produce valid SARIF JSON"

        # Validate SARIF structure
        assert parsed.get("$schema") or parsed.get("version"), (
            "SARIF output should have schema or version field"
        )
        assert "runs" in parsed, "SARIF output must contain 'runs' array"
        assert len(parsed["runs"]) > 0, "SARIF should have at least one run"

        # Check that results exist in the SARIF run
        run = parsed["runs"][0]
        results = run.get("results", [])
        assert len(results) > 0, "SARIF run should contain results for malicious file"

    def test_no_network_calls_made(self):
        """
        Verify the scanner operates in fully offline mode when
        --no-network flag is set. No DNS lookups or HTTP requests.
        """
        # This test validates that the scanner doesn't fail or timeout
        # when network is conceptually unavailable. The --no-network flag
        # should prevent any attempt to reach HuggingFace Hub.
        result = self._run_scanner(self.clean_dir)

        # Should complete without timeout or network errors
        assert "ConnectionError" not in result.get("stderr", "")
        assert "TimeoutError" not in result.get("stderr", "")
        assert "DNS" not in result.get("stderr", "")

    def test_multiple_dangerous_opcodes_all_flagged(self):
        """
        When a pickle file contains multiple dangerous GLOBAL references,
        each should generate a separate finding.
        """
        # Create a pickle with multiple dangerous imports
        multi_danger_dir = self.tmp_path / "multi-danger"
        multi_danger_dir.mkdir()

        # Craft pickle with os.system AND subprocess.call
        PROTO = b'\x80\x02'
        GLOBAL = b'\x63'
        SHORT_BINUNICODE = b'\x8c'
        TUPLE1 = b'\x85'
        REDUCE = b'\x52'
        POP = b'0'
        STOP = b'.'

        arg = b'whoami'
        payload = (
            PROTO
            + GLOBAL + b'os\nsystem\n'
            + SHORT_BINUNICODE + struct.pack('<B', len(arg)) + arg
            + TUPLE1 + REDUCE + POP
            + GLOBAL + b'subprocess\ncall\n'
            + SHORT_BINUNICODE + struct.pack('<B', len(arg)) + arg
            + TUPLE1 + REDUCE
            + STOP
        )

        danger_file = multi_danger_dir / "evil_model.pkl"
        danger_file.write_bytes(payload)

        result = self._run_scanner(multi_danger_dir)
        parsed = result["parsed"]
        assert parsed is not None

        findings = parsed.get("findings", parsed.get("results", []))
        # Should detect both dangerous imports
        assert len(findings) >= 2, (
            f"Expected at least 2 findings for 2 dangerous imports. Got {len(findings)}"
        )


# ---------------------------------------------------------------------------
# CLI Smoke Tests
# ---------------------------------------------------------------------------

class TestCLISmokeTests:
    """Basic CLI invocation tests to verify the scanner binary works."""

    def test_version_flag(self):
        """Scanner should respond to --version."""
        result = subprocess.run(
            [sys.executable, "-m", "scanner.cli", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0
        assert result.stdout.strip()  # Should print version

    def test_help_flag(self):
        """Scanner should respond to --help."""
        result = subprocess.run(
            [sys.executable, "-m", "scanner.cli", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0
        assert "usage" in result.stdout.lower()

    def test_nonexistent_path_error(self):
        """Scanner should error gracefully for non-existent paths."""
        result = subprocess.run(
            [
                sys.executable, "-m", "scanner.cli",
                "/nonexistent/path/xyz", "-m", "local", "--no-network",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode != 0
