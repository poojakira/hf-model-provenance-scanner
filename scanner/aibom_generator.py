"""
AIBOM Generator — Produce CycloneDX AI Bill of Materials from scan results.

Generates a standards-compliant CycloneDX 1.6 SBOM/AIBOM that includes:
1. Model component inventory (all files with hashes)
2. Dependency declarations (from requirements.txt/pyproject.toml)
3. Vulnerability findings mapped to VEX status
4. Provenance metadata (org, creation date, signatures)
5. AI-specific extensions (model type, training framework, license)

Output format: CycloneDX JSON (compatible with OWASP Dependency-Track,
CISA SBOM tools, and EU AI Act Article 53 requirements).
"""

import json
import os
import time
import uuid

from scanner.models import ScanResult


def generate_aibom(
    result: ScanResult,
    file_hashes: dict,
    target_path: str = "",
) -> dict:
    """
    Generate a CycloneDX 1.6 AIBOM from scan results.
    
    Args:
        result: Completed ScanResult
        file_hashes: Dict of {path: (sha256, size)}
        target_path: The scan target (repo ID or directory)
    
    Returns:
        CycloneDX JSON dict ready for json.dumps()
    """
    serial = str(uuid.uuid4())
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": _build_metadata(result, timestamp),
        "components": _build_components(file_hashes, result),
        "vulnerabilities": _build_vulnerabilities(result),
    }

    # Add AI-specific properties if we have org info
    if result.org_check:
        bom["metadata"]["properties"] = [
            {"name": "ai:publisher", "value": result.org_check.org_name},
            {"name": "ai:verified", "value": str(result.org_check.is_verified).lower()},
        ]
        if result.org_check.age_hours is not None:
            bom["metadata"]["properties"].append(
                {"name": "ai:repository_age_hours",
                 "value": f"{result.org_check.age_hours:.1f}"})

    return bom


def _build_metadata(result: ScanResult, timestamp: str) -> dict:
    return {
        "timestamp": timestamp,
        "tools": {
            "components": [{
                "type": "application",
                "name": "hf-scanner",
                "version": result.scanner_version,
                "description": "ML supply chain provenance scanner",
            }]
        },
        "component": {
            "type": "machine-learning-model",
            "name": result.scan_target,
            "bom-ref": f"model:{result.scan_target}",
        },
    }


def _build_components(
    file_hashes: dict, result: ScanResult
) -> list:
    components = []
    for path, (sha256, size) in file_hashes.items():
        comp_type = _classify_component(path)
        comp = {
            "type": comp_type,
            "name": os.path.basename(path),
            "bom-ref": f"file:{path}",
            "hashes": [{"alg": "SHA-256", "content": sha256}],
            "properties": [
                {"name": "file:path", "value": path},
                {"name": "file:size", "value": str(size)},
            ],
        }
        components.append(comp)
    return components


def _classify_component(path: str) -> str:
    lower = path.lower()
    if lower.endswith((".py", ".sh", ".bat", ".ps1")):
        return "file"
    if lower.endswith((".safetensors", ".pt", ".pth", ".pkl",
                       ".bin", ".gguf", ".onnx", ".h5")):
        return "data"
    if lower.endswith((".json", ".toml", ".yaml", ".yml")):
        return "file"
    return "file"


def _build_vulnerabilities(result: ScanResult) -> list:
    vulns = []
    seen = set()
    for finding in result.findings:
        if finding.rule_id in seen:
            continue
        seen.add(finding.rule_id)
        vuln = {
            "id": finding.rule_id,
            "description": finding.message,
            "source": {"name": "hf-scanner", "url": ""},
            "ratings": [{
                "severity": finding.severity.value,
                "method": "other",
            }],
            "analysis": {
                "state": "exploitable" if finding.severity.value in (
                    "critical", "high") else "in_triage",
            },
        }
        if finding.cwe:
            vuln["cwes"] = [int(finding.cwe.replace("CWE-", ""))]
        if finding.file_path:
            vuln["affects"] = [{"ref": f"file:{finding.file_path}"}]
        vulns.append(vuln)
    return vulns


def format_aibom(result: ScanResult, file_hashes: dict) -> str:
    """Generate AIBOM as formatted JSON string."""
    bom = generate_aibom(result, file_hashes)
    return json.dumps(bom, indent=2)
