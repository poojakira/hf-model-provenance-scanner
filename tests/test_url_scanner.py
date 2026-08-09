"""
Tests for real-time URL scanning (scan a model link before downloading weights).

Uses a fake HFApiClient so tests are deterministic and need no network. The
fake serves file listings and byte ranges from in-memory content, exactly like
the real Range-request path, so we exercise the true scanning logic.
"""

import pickle  # noqa: S403

import pytest

from scanner.url_scanner import parse_hf_reference, scan_hf_url


class _FakeHFClient:
    """In-memory stand-in for HFApiClient. Serves listings and byte ranges."""

    def __init__(self, files: dict[str, bytes]):
        self._files = files

    def list_repo_files(self, repo_id: str) -> list:
        return list(self._files.keys())

    def fetch_range(self, repo_id: str, filename: str, n_bytes: int) -> bytes:
        return self._files.get(filename, b"")[:n_bytes]

    def head_file_size(self, repo_id: str, filename: str):
        return len(self._files.get(filename, b""))


class _MaliciousReduce:
    """Pickle payload that runs os.system on load - the exact supply-chain threat."""

    def __reduce__(self):
        import os

        return (os.system, ("echo pwned",))


class TestParseReference:
    def test_full_url(self):
        assert (
            parse_hf_reference("https://huggingface.co/meta-llama/Llama-3.1-8B")
            == "meta-llama/Llama-3.1-8B"
        )

    def test_url_with_tree_path(self):
        assert parse_hf_reference("https://huggingface.co/org/model/tree/main") == "org/model"

    def test_bare_id(self):
        assert parse_hf_reference("mistralai/Mistral-7B-v0.3") == "mistralai/Mistral-7B-v0.3"

    def test_non_hf_url_returns_none(self):
        assert parse_hf_reference("https://example.com/foo/bar") is None

    def test_garbage_returns_none(self):
        assert parse_hf_reference("not a repo") is None


class TestURLScanning:
    def test_detects_malicious_pickle_without_full_download(self):
        # A malicious pickle "weights" file alongside a benign config.
        malicious = pickle.dumps(_MaliciousReduce.__new__(_MaliciousReduce))
        files = {
            "pytorch_model.bin": malicious,
            "config.json": b'{"model_type": "bert", "hidden_size": 768}',
        }
        client = _FakeHFClient(files)
        result = scan_hf_url("https://huggingface.co/evil/backdoored", client=client)

        assert result.is_malicious, "malicious pickle must be flagged"
        assert result.files_scanned >= 1
        # We only fetched the header range, not the whole file.
        assert result.bytes_fetched <= len(malicious) + 4096
        rule_ids = {f.rule_id for f in result.findings}
        assert any(r.startswith("HFS") for r in rule_ids)

    def test_clean_repo_no_findings(self):
        # Legit safetensors header + benign config = clean.
        header = b'{"__metadata__": {"format": "pt"}, "w": {"dtype": "F32", "shape": [2,2], "data_offsets": [0,16]}}'
        st = len(header).to_bytes(8, "little") + header + b"\x00" * 16
        files = {
            "model.safetensors": st,
            "config.json": b'{"model_type": "llama", "hidden_size": 4096}',
        }
        client = _FakeHFClient(files)
        result = scan_hf_url("google/gemma-2-9b", client=client)

        severe = [f for f in result.findings if f.severity.value in ("critical", "high")]
        assert severe == [], f"clean repo should have no severe findings: {severe}"
        assert not result.is_malicious

    def test_invalid_url_raises(self):
        with pytest.raises(ValueError, match="Could not parse"):
            scan_hf_url("https://example.com/not/hf", client=_FakeHFClient({}))

    def test_result_serializes(self):
        files = {"config.json": b'{"model_type": "gpt2"}'}
        result = scan_hf_url("openai-community/gpt2", client=_FakeHFClient(files))
        d = result.to_dict()
        assert d["repo_id"] == "openai-community/gpt2"
        assert d["verdict"] in ("clean", "MALICIOUS")
        assert "megabytes_fetched" in d
