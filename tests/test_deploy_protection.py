from __future__ import annotations

import json
from pathlib import Path

import deploy_protection


def test_static_scan_requires_complete_result(monkeypatch, tmp_path: Path) -> None:
    model_file = tmp_path / "model.json"
    model_file.write_text("{}", encoding="utf-8")
    server = deploy_protection.ProtectedModelServer(str(tmp_path), {"runtime": {}})

    def fake_cli_main(args):
        print(
            json.dumps(
                {
                    "findings": [],
                    "risk": {"score": 0, "level": "LOW"},
                    "completeness": "INDETERMINATE",
                    "error": None,
                }
            )
        )
        return 1

    monkeypatch.setattr(deploy_protection, "cli_main", fake_cli_main)
    result = server.static_scan()

    assert result["approved"] is False
    assert result["completeness"] == "INDETERMINATE"


def test_static_scan_approves_only_complete_success(monkeypatch, tmp_path: Path) -> None:
    model_file = tmp_path / "model.json"
    model_file.write_text("{}", encoding="utf-8")
    server = deploy_protection.ProtectedModelServer(str(tmp_path), {"runtime": {}})

    def fake_cli_main(args):
        assert "--enforce" in args
        print(
            json.dumps(
                {
                    "findings": [],
                    "risk": {"score": 0, "level": "LOW"},
                    "completeness": "COMPLETE",
                    "error": None,
                }
            )
        )
        return 0

    monkeypatch.setattr(deploy_protection, "cli_main", fake_cli_main)
    result = server.static_scan()

    assert result["approved"] is True
