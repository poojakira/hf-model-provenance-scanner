"""Guard HF discussion posts against host/path spoofing and token redirects."""

import importlib.util
from pathlib import Path

import pytest


def _module():
    path = Path(__file__).resolve().parents[1] / ".github" / "scripts" / "post_hf_discussion.py"
    spec = importlib.util.spec_from_file_location("post_hf_discussion", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_expected_hf_discussion_url():
    assert _module()._discussion_url("example-org/example-model") == (
        "https://huggingface.co/api/models/example-org/example-model/discussions"
    )


@pytest.mark.parametrize(
    "repo_id",
    [
        "",
        "org",
        "/model",
        "org/",
        "org/model/extra",
        "org/../model",
        "../model",
        "org/%2e%2e",
        "org/model?token=secret",
        "org@evil.example/model",
        "https://evil.example/model",
        "file:///etc/passwd",
        "127.0.0.1/model",
        "169.254.169.254/model",
        "org/model#fragment",
    ],
)
def test_untrusted_repo_ids_are_rejected(repo_id):
    with pytest.raises(ValueError):
        _module()._discussion_url(repo_id)


def test_redirect_requests_are_never_followed():
    handler = _module()._NoRedirect()
    assert handler.redirect_request(None, None, 302, "redirect", {}, "https://evil.test/") is None


def test_invalid_destination_never_constructs_opener(monkeypatch):
    module = _module()
    monkeypatch.setenv("HF_TOKEN", "offline-dummy-token")
    monkeypatch.setenv("REPO_ID", "org/model?redirect=elsewhere")

    def unexpected_opener(*args, **kwargs):
        pytest.fail("Invalid destination must be rejected before creating a network opener")

    monkeypatch.setattr(module.urllib.request, "build_opener", unexpected_opener)
    assert module.main() == 0


def test_valid_destination_uses_redirect_blocker_without_network(monkeypatch):
    module = _module()
    monkeypatch.setenv("HF_TOKEN", "offline-dummy-token")
    monkeypatch.setenv("REPO_ID", "example-org/example-model")
    requests = []

    class OfflineOpener:
        def open(self, request, timeout):
            requests.append((request, timeout))

    def mocked_opener(handler):
        assert isinstance(handler, module._NoRedirect)
        return OfflineOpener()

    monkeypatch.setattr(module.urllib.request, "build_opener", mocked_opener)
    assert module.main() == 0
    request, timeout = requests[0]
    assert request.full_url == module._discussion_url("example-org/example-model")
    assert request.get_method() == "POST"
    assert request.get_header("Authorization") == "Bearer offline-dummy-token"
    assert timeout == 10
