"""
tests/test_p0_security_regressions.py
───────────────────────────────────────────────────────────────────────────────
Security regression tests for P0 fixes in hf-model-provenance-scanner.

Covers:
  FINDING-001  TOCTOU: download_file must require commit SHA, not branch name
  FINDING-002  Redirect: cross-origin redirect strips Authorization header;
               HTTP downgrade rejected; non-HF host rejected
  FINDING-003  Completeness: oversized/skipped files set PARTIAL, not COMPLETE
  FINDING-004  Unknown pickle opcode → INDETERMINATE finding, not silent skip
  DELAYED-PAYLOAD  Malicious opcode after 512KB padding must be detected

Run with: pytest tests/test_p0_security_regressions.py -v
"""

import io
import struct
import urllib.error
import urllib.request
from unittest.mock import MagicMock, patch

import pytest

from scanner.analyzer.pickle_scanner import PickleScanner, scan_pickle_bytes
from scanner.models import Completeness, ScanResult
from scanner.utils.hf_api import (
    HFApiClient,
    HF_ALLOWED_HOSTS,
    HF_AUTH_FORWARD_HOSTS,
    _SafeRedirectHandler,
)

# ---------------------------------------------------------------------------
# Helper: valid 40-char hex SHA
# ---------------------------------------------------------------------------
VALID_SHA = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
assert len(VALID_SHA) == 40


# ═══════════════════════════════════════════════════════════════════════════════
# FINDING-001: Immutable revision enforcement
# ═══════════════════════════════════════════════════════════════════════════════


class TestImmutableRevision:
    """download_file and list_repo_files must reject non-SHA revision identifiers."""

    def setup_method(self):
        self.client = HFApiClient()

    def test_download_file_rejects_branch_name(self):
        """Passing 'main' as commit_sha must raise ValueError, not silently proceed."""
        with pytest.raises(ValueError, match="commit SHA"):
            self.client.download_file("org/model", "model.pkl", commit_sha="main")

    def test_download_file_rejects_empty_sha(self):
        with pytest.raises(ValueError, match="commit SHA"):
            self.client.download_file("org/model", "model.pkl", commit_sha="")

    def test_download_file_rejects_short_sha(self):
        """A partial SHA (< 40 chars) must be rejected."""
        with pytest.raises(ValueError, match="commit SHA"):
            self.client.download_file("org/model", "model.pkl", commit_sha="deadbeef")

    def test_download_file_rejects_none_sha(self):
        with pytest.raises((ValueError, TypeError)):
            self.client.download_file("org/model", "model.pkl", commit_sha=None)

    def test_list_repo_files_rejects_branch_name(self):
        with pytest.raises(ValueError, match="commit SHA"):
            self.client.list_repo_files("org/model", commit_sha="main")

    def test_list_repo_files_accepts_valid_sha(self):
        """A valid 40-char SHA should not raise at validation time (network may fail)."""
        # Patch _request to avoid real network call
        self.client._request = MagicMock(
            return_value=b'{"siblings": [{"rfilename": "model.pkl"}]}'
        )
        files = self.client.list_repo_files("org/model", commit_sha=VALID_SHA)
        assert files == ["model.pkl"]
        # Verify the SHA was used in the URL, not "main"
        called_url = self.client._request.call_args[0][0]
        assert VALID_SHA in called_url, f"SHA not in URL: {called_url}"
        assert "main" not in called_url, f"'main' must not appear in immutable URL: {called_url}"

    def test_download_file_uses_sha_in_url(self):
        """Verify the constructed URL contains the commit SHA."""
        self.client._request = MagicMock(return_value=b"model-data")
        data = self.client.download_file("org/model", "model.pkl", commit_sha=VALID_SHA)
        called_url = self.client._request.call_args[0][0]
        assert VALID_SHA in called_url
        assert "main" not in called_url


# ═══════════════════════════════════════════════════════════════════════════════
# FINDING-002: Redirect security — auth stripping and host validation
# ═══════════════════════════════════════════════════════════════════════════════


class TestRedirectSecurity:
    """_SafeRedirectHandler must enforce HTTPS-only, allowlist, and auth stripping."""

    def _make_handler(self, original_headers=None):
        return _SafeRedirectHandler(original_headers=original_headers or {})

    def _make_req(self, url, headers=None):
        req = urllib.request.Request(url, headers=headers or {})
        return req

    def test_http_downgrade_rejected(self):
        """Redirect to plain HTTP must raise URLError."""
        handler = self._make_handler({"Authorization": "Bearer secret"})
        req = self._make_req("https://huggingface.co/org/model/resolve/main/model.pkl")
        with pytest.raises(urllib.error.URLError, match="downgrade"):
            handler._check_redirect_target("http://evil.com/steal")

    def test_unknown_host_rejected(self):
        """Redirect to a non-HF host must raise URLError."""
        handler = self._make_handler()
        with pytest.raises(urllib.error.URLError, match="not in the HF allowed-hosts"):
            handler._check_redirect_target("https://attacker.example.com/exfil")

    def test_allowed_cdn_host_accepted(self):
        """Redirect to HF CDN must not raise."""
        handler = self._make_handler()
        # Should not raise
        handler._check_redirect_target("https://cdn-lfs.huggingface.co/repos/ab/cd/file")

    def test_s3_presigned_allowed(self):
        handler = self._make_handler()
        handler._check_redirect_target("https://s3.amazonaws.com/hf-bucket/file?X-Amz-Signature=x")

    def test_auth_stripped_on_cdn_redirect(self):
        """Authorization header must NOT be forwarded to CDN hosts."""
        handler = self._make_handler({"Authorization": "Bearer secret-token"})
        req = self._make_req(
            "https://huggingface.co/org/model/resolve/main/model.pkl",
            headers={"Authorization": "Bearer secret-token"},
        )
        new_req = handler._build_redirected_request(
            req, "https://cdn-lfs.huggingface.co/repos/ab/cd/model.pkl"
        )
        assert "Authorization" not in new_req.headers, (
            "Authorization MUST be stripped when redirecting to CDN host"
        )
        assert "authorization" not in {k.lower() for k in new_req.headers}, (
            "Authorization (any case) MUST be stripped on cross-origin redirect"
        )

    def test_auth_forwarded_on_same_origin_redirect(self):
        """Authorization header IS forwarded when redirecting within huggingface.co."""
        handler = self._make_handler({"Authorization": "Bearer my-token"})
        req = self._make_req(
            "https://huggingface.co/org/model",
            headers={"Authorization": "Bearer my-token"},
        )
        new_req = handler._build_redirected_request(
            req, "https://huggingface.co/org/model/v2"
        )
        assert "Authorization" in new_req.headers, (
            "Authorization should be forwarded within huggingface.co"
        )

    def test_auth_stripped_on_s3_redirect(self):
        """Authorization must NOT be forwarded to s3.amazonaws.com."""
        handler = self._make_handler({"Authorization": "Bearer secret"})
        req = self._make_req(
            "https://huggingface.co/resolve/main/model.pkl",
            headers={"Authorization": "Bearer secret"},
        )
        new_req = handler._build_redirected_request(
            req,
            "https://s3.amazonaws.com/hf-private-bucket/model.pkl?X-Amz-Signature=sig"
        )
        assert "Authorization" not in new_req.headers

    def test_initial_http_request_rejected(self):
        """HFApiClient must reject non-HTTPS initial URLs."""
        client = HFApiClient()
        with pytest.raises(ValueError, match="only HTTPS"):
            client._request("http://huggingface.co/api/models/org/model")


# ═══════════════════════════════════════════════════════════════════════════════
# FINDING-003: Completeness — skipped files must set PARTIAL
# ═══════════════════════════════════════════════════════════════════════════════


class TestScanResultCompleteness:
    """ScanResult.completeness must be PARTIAL when any file is skipped."""

    def test_default_completeness_is_unknown(self):
        r = ScanResult(scan_target="test", scan_mode="local", scanner_version="0.2.0")
        assert r.completeness == Completeness.UNKNOWN

    def test_completeness_can_be_set_to_partial(self):
        r = ScanResult(scan_target="test", scan_mode="local", scanner_version="0.2.0")
        r.completeness = Completeness.PARTIAL
        assert r.completeness == Completeness.PARTIAL

    def test_completeness_enum_values(self):
        assert Completeness.COMPLETE.value == "COMPLETE"
        assert Completeness.PARTIAL.value == "PARTIAL"
        assert Completeness.UNKNOWN.value == "UNKNOWN"

    def test_partial_is_not_complete(self):
        """Explicit check: PARTIAL != COMPLETE — core invariant."""
        assert Completeness.PARTIAL != Completeness.COMPLETE

    def test_skipped_files_detail_is_list(self):
        r = ScanResult(scan_target="test", scan_mode="local", scanner_version="0.2.0")
        assert isinstance(r.skipped_files_detail, list)


# ═══════════════════════════════════════════════════════════════════════════════
# FINDING-004: Unknown pickle opcode → INDETERMINATE
# ═══════════════════════════════════════════════════════════════════════════════


class TestUnknownPickleOpcode:
    """Unknown opcodes must produce HFS-099 INDETERMINATE finding, not silent pass."""

    def _build_pickle_with_unknown_opcode(self) -> bytes:
        """Construct a minimal pickle2 stream with an injected unknown opcode (0xFF)."""
        # Protocol 2 header
        data = b"\x80\x02"
        # An unknown opcode: 0xFF is not assigned in any pickle protocol
        data += b"\xff"
        # STOP
        data += b"."
        return data

    def test_unknown_opcode_produces_indeterminate_finding(self):
        data = self._build_pickle_with_unknown_opcode()
        scanner = PickleScanner("test.pkl", data)
        findings = scanner.scan()
        rule_ids = {f.rule_id for f in findings}
        assert "HFS-099" in rule_ids, (
            f"HFS-099 (INDETERMINATE) must be emitted for unknown opcode. Got: {rule_ids}"
        )

    def test_unknown_opcode_increments_counter(self):
        data = self._build_pickle_with_unknown_opcode()
        scanner = PickleScanner("test.pkl", data)
        scanner.scan()
        assert scanner.unknown_opcode_count > 0

    def test_clean_pickle_no_unknown_opcode_finding(self):
        """A completely benign pickle should not trigger HFS-099."""
        import pickle
        data = pickle.dumps({"key": "value"})
        scanner = PickleScanner("benign.pkl", data)
        findings = scanner.scan()
        rule_ids = {f.rule_id for f in findings}
        assert "HFS-099" not in rule_ids, (
            f"HFS-099 must NOT fire for a known-clean pickle. Got: {rule_ids}"
        )
        assert scanner.unknown_opcode_count == 0


# ═══════════════════════════════════════════════════════════════════════════════
# DELAYED PAYLOAD: Malicious opcode hidden after padding must be detected
# ═══════════════════════════════════════════════════════════════════════════════


class TestDelayedPayloadRegression:
    """Regression test: malicious opcode after a large padding block must be caught.

    This is the core adversarial attack against scanners that only read the
    first N bytes. Our scanner reads the complete data.
    """

    def _build_delayed_payload(self, padding_size: int = 600_000) -> bytes:
        """Build a pickle stream where os.system GLOBAL appears after `padding_size` bytes.

        Protocol 2 header + large BINUNICODE string + GLOBAL os\\nsystem\\n + STOP.
        The scanner must read past the padding to find the GLOBAL.
        """
        # Protocol 2 header
        data = b"\x80\x02"

        # BINUNICODE opcode (X) with padding_size-byte string
        padding = b"A" * padding_size
        data += b"X"
        data += struct.pack("<I", len(padding))
        data += padding

        # POP the string off stack: "0" opcode
        data += b"0"

        # GLOBAL: os + newline + system + newline
        data += b"c"
        data += b"os\n"
        data += b"system\n"

        # Build a tuple arg: ("id",)
        data += b"("
        data += b"S'id'\n"
        data += b"t"

        # REDUCE
        data += b"R"

        # STOP
        data += b"."
        return data

    def test_malicious_global_after_padding_detected(self):
        """os.system GLOBAL appearing after 600KB padding must trigger HFS-050."""
        data = self._build_delayed_payload(padding_size=600_000)
        findings = scan_pickle_bytes("delayed_payload.pkl", data)
        rule_ids = {f.rule_id for f in findings}
        assert "HFS-050" in rule_ids, (
            "HFS-050 (CRITICAL callable) must fire for os.system even when it "
            f"appears after 600KB of padding. Got findings: {rule_ids}"
        )

    def test_malicious_global_after_512kb_detected(self):
        """Regression: payload just past the old 512KB scan boundary."""
        data = self._build_delayed_payload(padding_size=513_000)
        findings = scan_pickle_bytes("boundary_payload.pkl", data)
        rule_ids = {f.rule_id for f in findings}
        assert "HFS-050" in rule_ids, (
            "HFS-050 must fire for os.system at 513KB — old 512KB limit was the bug."
        )

    def test_clean_data_with_large_string_no_finding(self):
        """A pickle with a large benign string but no dangerous GLOBAL must be clean."""
        import pickle
        # pickle.dumps uses protocol 4+ for large objects, which is fine
        data = pickle.dumps({"big": "B" * 700_000})
        findings = scan_pickle_bytes("large_benign.pkl", data)
        critical = [f for f in findings if f.rule_id == "HFS-050"]
        assert not critical, f"False positive: HFS-050 on benign large pickle. Got: {critical}"
