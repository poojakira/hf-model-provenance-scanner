from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from scanner import config
from scanner.analyzer import dependency_scanner as deps
from scanner.analyzer.keras_scanner import HDF5_MAGIC, analyze_keras_file, is_keras_file
from scanner.analyzer.onnx_scanner import analyze_onnx_file, is_onnx_file
from scanner.provenance import (
    is_sbom_file,
    is_signature_file,
    parse_sbom_hashes,
    sha256_bytes,
    verify_local_signatures,
    verify_sbom_artifacts,
)


def _rule_ids(findings):
    return {finding.rule_id for finding in findings}


def test_config_load_existing_and_missing(tmp_path):
    path = tmp_path / ".hf-scanner.toml"
    path.write_text(
        '[scanner]\nthreshold = 7\nenabled = true\nname = "demo"\n',
        encoding="utf-8",
    )
    loaded = config.load_config(str(path))
    assert loaded["scanner"]["threshold"] == 7
    assert loaded["scanner"]["enabled"] is True
    assert loaded["scanner"]["name"] == "demo"
    assert config.load_config(str(tmp_path / "missing.toml")) == {}


def test_config_python310_fallback_parser(monkeypatch):
    source_path = Path(config.__file__)
    spec = importlib.util.spec_from_file_location("scanner._config_fallback_coverage", source_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "tomllib", None)
    spec.loader.exec_module(module)
    fallback = module.tomllib
    parsed = fallback.loads(
        """
# comment
[scanner]
threshold = 7
enabled = true
disabled = false
publishers = ["openai", "meta-llama"]
empty = []
[nested.policy]
level = "high"
"""
    )
    assert parsed["scanner"]["threshold"] == 7
    assert parsed["scanner"]["enabled"] is True
    assert parsed["scanner"]["disabled"] is False
    assert parsed["scanner"]["publishers"] == ["openai", "meta-llama"]
    assert parsed["scanner"]["empty"] == []
    assert parsed["nested"]["policy"]["level"] == "high"


def test_dependency_requirements_ioc_vulnerable_unpinned(monkeypatch):
    monkeypatch.setattr(
        deps,
        "_IOC_DATA",
        {
            "domains": ["evil.example"],
            "dangerous_packages": ["badpkg"],
            "vulnerable_versions": {"oldpkg": "2.0.0"},
            "suspicious_tlds": [],
        },
    )
    source = "\n".join(
        [
            "# comment",
            "badpkg==1.0",
            "oldpkg==1.0.0",
            "plainpkg",
            "https://evil.example/pkg.whl",
            "-r other.txt",
        ]
    )
    findings = deps.analyze_dependency_source("requirements.txt", source)
    ids = _rule_ids(findings)
    assert {"HFS-040", "HFS-041", "HFS-042", "HFS-043"} <= ids


def test_dependency_pyproject_and_dockerfile(monkeypatch):
    monkeypatch.setattr(
        deps,
        "_IOC_DATA",
        {
            "domains": [],
            "dangerous_packages": ["badpkg"],
            "vulnerable_versions": {"oldpkg": "3.0"},
            "suspicious_tlds": [],
        },
    )
    pyproject = """
[project]
dependencies = [
  "badpkg==1.0",
  "oldpkg==1.2",
  "safe>=4",
]
"""
    ids = _rule_ids(deps.analyze_dependency_source("pyproject.toml", pyproject))
    assert {"HFS-041", "HFS-042"} <= ids

    docker = "\n".join(
        [
            "FROM python:3.12",
            "USER root",
            "RUN curl https://example.com/install.sh | sh",
            "RUN docker run --privileged image",
        ]
    )
    findings = deps.analyze_dependency_source("Dockerfile", docker)
    assert sum(f.rule_id == "HFS-044" for f in findings) >= 4

    pinned = "FROM python@sha256:" + "a" * 64
    assert "HFS-044" not in _rule_ids(deps.analyze_dependency_source("Dockerfile", pinned))
    assert deps.analyze_dependency_source("notes.md", "nothing") == []


def test_dependency_version_helpers_and_ioc_load_failure(monkeypatch):
    assert deps._parse_version("v1.2.3rc1") == (1, 2, 3, 1)
    assert deps._parse_version("latest") == (0,)
    assert deps._version_below("1.9", "2.0")
    monkeypatch.setattr(deps, "_IOC_DATA", None)

    def broken_open(*_args, **_kwargs):
        raise OSError("no file")

    monkeypatch.setattr("builtins.open", broken_open)
    data = deps._load_iocs()
    assert data["domains"] == []


def test_provenance_helpers_and_sbom_verification():
    assert is_sbom_file("/tmp/model.cyclonedx.json")
    assert is_signature_file("weights.bin.sig")
    assert is_signature_file("model.sigstore.bundle")
    assert not is_signature_file("model.bin")
    assert sha256_bytes(b"abc") == hashlib.sha256(b"abc").hexdigest()
    assert parse_sbom_hashes(b"not-json") == {}

    good = b"model bytes"
    digest = hashlib.sha256(good).hexdigest()
    sbom = json.dumps(
        {
            "components": [
                {
                    "name": "weights.bin",
                    "hashes": [
                        {"alg": "SHA-256", "content": digest},
                        {"alg": "SHA-1", "content": "ignored"},
                    ],
                }
            ]
        }
    ).encode()
    parsed = parse_sbom_hashes(sbom)
    assert parsed == {"weights.bin": digest}

    no_findings = verify_sbom_artifacts({"bom.json": sbom}, {"weights.bin": good})
    assert no_findings == []

    findings = verify_sbom_artifacts(
        {"bom.json": sbom},
        {"weights.bin": b"tampered", "extra.bin": b"x"},
    )
    assert {"HFS-036", "HFS-037"} <= _rule_ids(findings)
    assert verify_sbom_artifacts({"bad.json": b"{}"}, {"x.bin": b"x"}) == []


def test_signature_verification_no_verifier_failed_and_timeout(tmp_path, monkeypatch):
    artifact = tmp_path / "weights.bin"
    signature = tmp_path / "weights.bin.sig"
    artifact.write_bytes(b"model")
    signature.write_bytes(b"sig")

    monkeypatch.setattr("scanner.provenance._find_verifier", lambda: None)
    findings = verify_local_signatures(str(tmp_path))
    assert _rule_ids(findings) == {"HFS-039"}

    monkeypatch.setattr("scanner.provenance._find_verifier", lambda: "/usr/bin/cosign")
    monkeypatch.setattr(
        "scanner.provenance.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=1, stderr=b"bad signature"),
    )
    findings = verify_local_signatures(str(tmp_path))
    assert "HFS-038" in _rule_ids(findings)

    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd=["cosign"], timeout=30)

    monkeypatch.setattr("scanner.provenance.subprocess.run", timeout)
    assert "HFS-038" in _rule_ids(verify_local_signatures(str(tmp_path)))

    assert verify_local_signatures(str(tmp_path / "missing")) == []


def test_keras_scanner_dangerous_content():
    assert is_keras_file("model.keras")
    assert is_keras_file("model.H5")
    assert not is_keras_file("model.bin")
    assert analyze_keras_file("model.h5", b"short unrelated") == []

    payload = (
        HDF5_MAGIC
        + b' model_config {"class_name":"Lambda","config":{'
        + b'"function":"os.system(\\\\nwhoami)","custom_objects":{"X":"Y"}}}'
        + b"cos\nsystem\n"
    )
    findings = analyze_keras_file("model.h5", payload)
    assert "HFS-076" in _rule_ids(findings)
    assert len(findings) >= 3


def _protobuf_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    assert 4 < len(raw) < 200
    return bytes([0x0A, len(raw)]) + raw


def test_onnx_scanner_small_custom_op_and_url():
    assert is_onnx_file("m.onnx")
    assert not is_onnx_file("m.bin")
    assert "HFS-075" in _rule_ids(analyze_onnx_file("m.onnx", b"tiny"))

    data = (
        b"\x00\x00"
        + _protobuf_string("EvilCustomOp")
        + _protobuf_string("https://evil.example/payload")
        + _protobuf_string("subprocess")
    )
    ids = _rule_ids(analyze_onnx_file("m.onnx", data))
    assert "HFS-073" in ids
    assert "HFS-074" in ids


def test_navigator_reporter_deduplicates_and_prefers_subtechnique():
    pytest.importorskip("attack_v19_core")
    from scanner.attack_mapping.reporter import NavigatorLayerReporter

    mappings = [
        SimpleNamespace(technique_id="T1000", subtechnique_id=None, confidence=0.8),
        SimpleNamespace(technique_id="T1000", subtechnique_id=None, confidence=0.7),
        SimpleNamespace(technique_id="T2000", subtechnique_id="T2000.001", confidence=0.9),
    ]
    payload = json.loads(NavigatorLayerReporter().generate("scanner", mappings))
    assert payload["name"] == "scanner ATT&CK Coverage"
    assert payload["domain"] == "enterprise-attack"
    assert [x["techniqueID"] for x in payload["techniques"]] == ["T1000", "T2000.001"]
    assert payload["techniques"][0]["score"] == 80
