import asyncio
import threading
import urllib.error

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from scanner import service
from scanner.utils.hf_api import HFApiClient, _SafeRedirectHandler


def test_private_token_requires_resource_allowlist(monkeypatch):
    monkeypatch.setenv("HF_TOKEN", "test-token")
    monkeypatch.delenv("SCAN_ALLOWED_REPOS", raising=False)
    with pytest.raises(HTTPException) as exc:
        service._validate_target(service.ScanRequest(repo_id="org/private"))
    assert exc.value.status_code == 503
    monkeypatch.setenv("SCAN_ALLOWED_REPOS", "org/allowed")
    with pytest.raises(HTTPException) as exc:
        service._validate_target(service.ScanRequest(repo_id="org/private"))
    assert exc.value.status_code == 403
    service._validate_target(service.ScanRequest(repo_id="org/allowed"))


def test_validation_response_does_not_echo_input(monkeypatch):
    key = "service-key-at-least-32-characters-long"
    monkeypatch.setenv("API_KEY", key)
    response = TestClient(service.app).post(
        "/scan", headers={"X-API-Key": key}, json={"repo_id": {"secret": "private-payload"}}
    )
    assert response.status_code == 422
    assert "private-payload" not in response.text


def test_chunked_body_is_bounded(monkeypatch):
    monkeypatch.setattr(service, "_MAX_REQUEST_BYTES", 20)
    response = TestClient(service.app).post("/scan", content=iter([b"x" * 15, b"y" * 15]))
    assert response.status_code == 413


@pytest.mark.parametrize(
    "url",
    [
        "https://attacker.example/x",
        "https://huggingface.co:444/x",
        "https://user:pass@huggingface.co/x",
    ],
)
def test_initial_request_rejects_untrusted_origins(url):
    with pytest.raises(ValueError):
        HFApiClient(token="test-token")._request(url)  # noqa: S106 -- inert fixture


def test_redirect_rejects_nonstandard_origin():
    with pytest.raises(urllib.error.URLError):
        _SafeRedirectHandler({})._check_redirect_target("https://huggingface.co:444/x")


def test_timed_out_worker_keeps_capacity():
    async def scenario():
        slots = asyncio.Semaphore(1)
        release = threading.Event()

        def slow(_):
            release.wait(2)

        try:
            with pytest.raises(asyncio.TimeoutError):
                await service._run_bounded(slow, None, slots, 0.01)
            assert slots.locked()
            with pytest.raises(HTTPException) as exc:
                await service._run_bounded(slow, None, slots, 0.01)
            assert exc.value.status_code == 503
        finally:
            release.set()
            await asyncio.gather(*service._active_jobs)
        assert not slots.locked()

    asyncio.run(scenario())
