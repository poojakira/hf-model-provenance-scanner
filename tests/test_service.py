from __future__ import annotations

from fastapi.testclient import TestClient

from scanner import service

client = TestClient(service.app)


def test_health_is_public():
    response = client.get("/health")
    assert response.status_code == 200


def test_ready_requires_configured_key(monkeypatch):
    monkeypatch.delenv("API_KEY", raising=False)
    assert client.get("/ready").status_code == 503


def test_scan_requires_auth(monkeypatch):
    monkeypatch.setenv("API_KEY", "service-key-at-least-32-characters-long")
    response = client.post("/scan", json={"repo_id": "org/model"})
    assert response.status_code == 401


def test_scan_rejects_invalid_repo_id(monkeypatch):
    key = "service-key-at-least-32-characters-long"
    monkeypatch.setenv("API_KEY", key)
    response = client.post(
        "/scan",
        headers={"X-API-Key": key},
        json={"repo_id": "../etc/passwd"},
    )
    assert response.status_code == 422


def test_complete_clean_scan_allows(monkeypatch):
    key = "service-key-at-least-32-characters-long"
    monkeypatch.setenv("API_KEY", key)
    monkeypatch.setattr(
        service,
        "_scan_sync",
        lambda payload: (
            0,
            {
                "artifact_revision": "a" * 40,
                "completeness": "COMPLETE",
                "risk": {"score": 0, "level": "LOW"},
                "findings": [],
                "error": None,
            },
        ),
    )
    response = client.post(
        "/scan",
        headers={"X-API-Key": key},
        json={"repo_id": "org/model", "revision": "release-v1"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "ALLOW"
    assert body["artifact_revision"] == "a" * 40


def test_partial_scan_never_allows(monkeypatch):
    key = "service-key-at-least-32-characters-long"
    monkeypatch.setenv("API_KEY", key)
    monkeypatch.setattr(
        service,
        "_scan_sync",
        lambda payload: (
            0,
            {
                "artifact_revision": "b" * 40,
                "completeness": "PARTIAL",
                "risk": {"score": 20, "level": "MEDIUM"},
                "findings": [],
                "error": None,
            },
        ),
    )
    response = client.post(
        "/scan",
        headers={"X-API-Key": key},
        json={"repo_id": "org/model"},
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "ERROR"


def test_security_findings_block(monkeypatch):
    key = "service-key-at-least-32-characters-long"
    monkeypatch.setenv("API_KEY", key)
    monkeypatch.setattr(
        service,
        "_scan_sync",
        lambda payload: (
            1,
            {
                "artifact_revision": "c" * 40,
                "completeness": "COMPLETE",
                "risk": {"score": 90, "level": "CRITICAL"},
                "findings": [{"rule_id": "HFS-001"}],
                "error": None,
            },
        ),
    )
    response = client.post(
        "/scan",
        headers={"X-API-Key": key},
        json={"repo_id": "org/model"},
    )
    assert response.json()["decision"] == "BLOCK"
