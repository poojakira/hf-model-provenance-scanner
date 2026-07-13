"""Provenance verification: signatures, SBOMs, and hash checking."""

import hashlib
import json
import os
import shutil
import subprocess
from typing import Optional

from scanner.models import Finding, Severity
from scanner.rules.definitions import get_rule

SIGNATURE_EXTENSIONS = (".sig", ".asc", ".minisig", ".cosign", ".bundle")
SBOM_MARKERS = ("sbom", "aibom", "bom.json", "cyclonedx", "cdx")


def is_sbom_file(path: str) -> bool:
    """Check if a file path looks like an SBOM/AIBOM artifact."""
    lower = os.path.basename(path).lower()
    return any(marker in lower for marker in SBOM_MARKERS)


def is_signature_file(path: str) -> bool:
    """Check if a file path looks like a detached signature artifact."""
    lower = path.lower()
    return (lower.endswith(SIGNATURE_EXTENSIONS) or "sigstore" in lower)


def sha256_bytes(data: bytes) -> str:
    """Compute hex SHA-256 digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def _find_verifier() -> Optional[str]:
    """Find an available signature verifier tool."""
    for tool in ("cosign", "gpg", "minisign"):
        if shutil.which(tool):
            return tool
    return None


def verify_local_signatures(root: str) -> list:
    """Attempt to verify detached signatures found in a local directory.

    Returns findings for failures or unavailable verifiers.
    """
    findings: list[Finding] = []
    if not os.path.isdir(root):
        return findings

    sig_files: list[str] = []
    for dirpath, _, filenames in os.walk(root):
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            if is_signature_file(fpath):
                sig_files.append(fpath)

    if not sig_files:
        return findings

    verifier = _find_verifier()
    if not verifier:
        for sf in sig_files:
            rule = get_rule("HFS-039")
            findings.append(Finding(
                "HFS-039", rule.severity, sf, 0, 0,
                rule.description,
                f"Signature file found but no verifier ({', '.join(['cosign','gpg','minisign'])}) available",
                rule.remediation, rule.cwe))
        return findings

    for sf in sig_files:
        # Determine the artifact the signature covers
        artifact_path = sf
        for ext in SIGNATURE_EXTENSIONS:
            if sf.lower().endswith(ext):
                artifact_path = sf[: -len(ext)]
                break

        if not os.path.exists(artifact_path):
            continue

        try:
            if verifier == "cosign":
                # A bare `cosign verify-blob --signature ...` (keyless) only
                # proves the signature exists in Rekor — NOT that a trusted
                # party signed it. An attacker can sign their own model and
                # register it. Require a pinned key or certificate identity;
                # otherwise report HFS-041 instead of a meaningless "verified".
                key = os.environ.get("HFS_COSIGN_KEY")
                identity = os.environ.get("HFS_COSIGN_CERT_IDENTITY")
                identity_re = os.environ.get("HFS_COSIGN_CERT_IDENTITY_REGEXP")
                issuer = os.environ.get("HFS_COSIGN_OIDC_ISSUER")
                if key:
                    cmd = ["cosign", "verify-blob", "--key", key,
                           "--signature", sf, artifact_path]
                elif (identity or identity_re) and issuer:
                    id_flag = (
                        ["--certificate-identity-regexp", identity_re]
                        if identity_re
                        else ["--certificate-identity", identity]
                    )
                    cmd = ["cosign", "verify-blob", *id_flag,
                           "--certificate-oidc-issuer", issuer,
                           "--signature", sf, artifact_path]
                else:
                    rule = get_rule("HFS-041")
                    findings.append(Finding(
                        "HFS-041", rule.severity, sf, 0, 0,
                        rule.description,
                        "cosign present but no trusted key/identity configured; "
                        "refusing to treat a bare verify-blob as trust.",
                        rule.remediation, rule.cwe))
                    continue
            elif verifier == "gpg":
                cmd = ["gpg", "--verify", sf, artifact_path]
            else:
                cmd = ["minisign", "-Vm", artifact_path, "-x", sf]

            result = subprocess.run(
                cmd, capture_output=True, timeout=30)
            if result.returncode != 0:
                rule = get_rule("HFS-038")
                findings.append(Finding(
                    "HFS-038", rule.severity, sf, 0, 0,
                    rule.description,
                    f"Verification failed: {result.stderr.decode('utf-8', errors='replace')[:200]}",
                    rule.remediation, rule.cwe))
        except (subprocess.TimeoutExpired, OSError) as exc:
            rule = get_rule("HFS-038")
            findings.append(Finding(
                "HFS-038", rule.severity, sf, 0, 0,
                rule.description, str(exc)[:200],
                rule.remediation, rule.cwe))

    return findings


def parse_sbom_hashes(data: bytes) -> dict:
    """Parse SHA-256 hashes from a CycloneDX SBOM JSON.

    Returns {component_name: sha256_hex, ...}
    """
    hashes: dict[str, str] = {}
    try:
        doc = json.loads(data)
    except (json.JSONDecodeError, ValueError):
        return hashes

    components = doc.get("components", [])
    for comp in components:
        name = comp.get("name", "")
        for h in comp.get("hashes", []):
            if h.get("alg", "").upper() == "SHA-256":
                hashes[name] = h.get("content", "")
                break
    return hashes


def verify_sbom_artifacts(sboms: dict, artifacts: dict) -> list:
    """Cross-check SBOM hashes against scanned artifacts.

    sboms: {file_path: raw_bytes}
    artifacts: {file_path: raw_bytes}

    Returns findings for mismatches and uncovered artifacts.
    """
    findings: list[Finding] = []
    all_sbom_hashes: dict[str, str] = {}

    for sbom_path, sbom_data in sboms.items():
        parsed = parse_sbom_hashes(sbom_data)
        all_sbom_hashes.update(parsed)

    if not all_sbom_hashes:
        return findings

    covered_artifacts = set()
    for artifact_path, artifact_data in artifacts.items():
        basename = os.path.basename(artifact_path)
        if basename in all_sbom_hashes:
            covered_artifacts.add(basename)
            expected = all_sbom_hashes[basename]
            actual = sha256_bytes(artifact_data)
            if expected and actual != expected:
                rule = get_rule("HFS-036")
                findings.append(Finding(
                    "HFS-036", rule.severity, artifact_path, 0, 0,
                    rule.description,
                    f"Expected SHA-256={expected[:16]}... got {actual[:16]}...",
                    rule.remediation, rule.cwe))

    # Report artifacts not covered by any SBOM
    for artifact_path in artifacts:
        basename = os.path.basename(artifact_path)
        if basename not in all_sbom_hashes:
            rule = get_rule("HFS-037")
            findings.append(Finding(
                "HFS-037", rule.severity, artifact_path, 0, 0,
                rule.description,
                f"Artifact '{basename}' not listed in any SBOM",
                rule.remediation, rule.cwe))

    return findings
