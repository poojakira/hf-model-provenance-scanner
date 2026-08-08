"""
scanner/sbom/cyclonedx_generator.py
──────────────────────────────────────────────────────────────────────────────
CycloneDX SBOM (Software Bill of Materials) generator for model scan results.

Generates a CycloneDX 1.5 JSON SBOM describing:
  - The scanned model as a component
  - Its detected dependencies / embedded artifacts
  - Security findings as vulnerabilities
  - Scanner provenance metadata

CycloneDX spec: https://cyclonedx.org/specification/overview/
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CYCLONEDX_VERSION = "1.5"
CYCLONEDX_SCHEMA = "http://cyclonedx.org/schema/bom-1.5.schema.json"


def _sha256_file(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def generate_model_sbom(
    model_path: str,
    model_name: str,
    model_version: str = "unknown",
    findings: list[dict[str, Any]] | None = None,
    scanner_version: str = "1.0.0",
) -> dict[str, Any]:
    """Generate a CycloneDX 1.5 SBOM for a scanned model artifact.

    Parameters
    ----------
    model_path:
        Path to the model file on disk.
    model_name:
        Human-readable model name (e.g. 'meta-llama/Llama-3-8B').
    model_version:
        Model version string.
    findings:
        List of scanner findings to include as vulnerabilities.
        Each finding: {'rule_id': str, 'severity': str, 'message': str}
    scanner_version:
        Version of hf-model-provenance-scanner.

    Returns
    -------
    dict
        CycloneDX 1.5 JSON-serialisable SBOM document.
    """
    findings = findings or []
    bom_ref = str(uuid.uuid4())
    timestamp = datetime.now(tz=timezone.utc).isoformat()
    sha256 = _sha256_file(model_path)

    # ── Main model component ───────────────────────────────────────────────────
    component: dict[str, Any] = {
        "type": "machine-learning-model",
        "bom-ref": bom_ref,
        "name": model_name,
        "version": model_version,
        "description": f"ML model artifact scanned by hf-model-provenance-scanner v{scanner_version}",
        "hashes": [],
        "properties": [
            {"name": "scanner:tool", "value": "hf-model-provenance-scanner"},
            {"name": "scanner:version", "value": scanner_version},
            {"name": "scanner:timestamp", "value": timestamp},
            {"name": "artifact:path", "value": str(Path(model_path).name)},
        ],
    }

    if sha256:
        component["hashes"].append({"alg": "SHA-256", "content": sha256})

    # ── Vulnerabilities from findings ─────────────────────────────────────────
    severity_map = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "NOTE": "none",
    }

    vulnerabilities: list[dict[str, Any]] = []
    for finding in findings:
        vuln: dict[str, Any] = {
            "bom-ref": str(uuid.uuid4()),
            "id": finding.get("rule_id", "UNKNOWN"),
            "source": {
                "name": "hf-model-provenance-scanner",
                "url": "https://github.com/poojakira/hf-model-provenance-scanner",
            },
            "ratings": [
                {
                    "severity": severity_map.get(finding.get("severity", "NOTE"), "none"),
                    "method": "other",
                }
            ],
            "description": finding.get("message", ""),
            "affects": [{"ref": bom_ref}],
        }
        vulnerabilities.append(vuln)

    # ── Tool metadata ─────────────────────────────────────────────────────────
    tools: list[dict[str, Any]] = [
        {
            "vendor": "poojakira",
            "name": "hf-model-provenance-scanner",
            "version": scanner_version,
            "externalReferences": [
                {
                    "type": "website",
                    "url": "https://github.com/poojakira/hf-model-provenance-scanner",
                }
            ],
        }
    ]

    # ── Assemble SBOM ─────────────────────────────────────────────────────────
    sbom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_VERSION,
        "$schema": CYCLONEDX_SCHEMA,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": tools,
            "component": {
                "type": "application",
                "name": "hf-model-provenance-scanner",
                "version": scanner_version,
            },
        },
        "components": [component],
        "vulnerabilities": vulnerabilities,
    }

    return sbom


def save_sbom(sbom: dict[str, Any], output_path: str) -> None:
    """Write a CycloneDX SBOM to a JSON file."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sbom, f, indent=2)
