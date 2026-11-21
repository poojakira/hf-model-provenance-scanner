"""Provenance verification: signatures, SBOMs, and hash checking."""

import hashlib
import json
import os
import shutil
import subprocess  # nosec B404 - resolved verifier executable with fixed argv only
import tempfile
from pathlib import Path

from scanner.models import Finding
from scanner.rules.definitions import get_rule
from scanner.utils.file_filter import read_regular_file

SIGNATURE_EXTENSIONS = (".sig", ".asc", ".minisig", ".cosign", ".bundle")
SBOM_MARKERS = ("sbom", "aibom", "bom.json", "cyclonedx", "cdx")


def is_sbom_file(path: str) -> bool:
    """Check if a file path looks like an SBOM/AIBOM artifact."""
    lower = os.path.basename(path).lower()
    return any(marker in lower for marker in SBOM_MARKERS)


def is_signature_file(path: str) -> bool:
    """Check if a file path looks like a detached signature artifact."""
    lower = path.lower()
    return lower.endswith(SIGNATURE_EXTENSIONS) or "sigstore" in lower


def sha256_bytes(data: bytes) -> str:
    """Compute hex SHA-256 digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def _find_verifier() -> str | None:
    """Find an available signature verifier executable."""
    for tool in ("cosign", "gpg", "minisign"):
        resolved = shutil.which(tool)
        if resolved:
            return resolved
    return None


def verify_local_signatures(
    root: str,
    *,
    expected_hashes: dict[str, tuple[str, int]] | None = None,
    max_artifact_bytes: int = 100 * 1024 * 1024,
) -> list:
    """Attempt to verify detached signatures found in a local directory.

    Returns findings for failures or unavailable verifiers.
    """
    findings: list[Finding] = []
    if os.path.islink(root) or not os.path.isdir(root):
        return findings

    if expected_hashes is not None:
        sig_files = [path for path in expected_hashes if is_signature_file(path)]
    else:
        sig_files = [
            os.path.join(dirpath, name)
            for dirpath, _, filenames in os.walk(root)
            for name in filenames
            if is_signature_file(os.path.join(dirpath, name))
        ]

    if not sig_files:
        return findings

    verifier = _find_verifier()
    if not verifier:
        for sf in sig_files:
            rule = get_rule("HFS-039")
            findings.append(
                Finding(
                    "HFS-039",
                    rule.severity,
                    sf,
                    0,
                    0,
                    rule.description,
                    f"Signature file found but no verifier ({', '.join(['cosign', 'gpg', 'minisign'])}) available",
                    rule.remediation,
                    rule.cwe,
                )
            )
        return findings

    verifier_name = os.path.splitext(os.path.basename(verifier))[0].lower()

    for sf in sig_files:
        # Determine the artifact the signature covers
        artifact_path = sf
        for ext in SIGNATURE_EXTENSIONS:
            if sf.lower().endswith(ext):
                artifact_path = sf[: -len(ext)]
                break

        if not os.path.lexists(artifact_path):
            continue

        try:
            signature = read_regular_file(root, sf, 1024 * 1024)
            artifact = read_regular_file(root, artifact_path, max_artifact_bytes)
            if expected_hashes is not None and (
                expected_hashes.get(sf) != (sha256_bytes(signature), len(signature))
                or expected_hashes.get(artifact_path) != (sha256_bytes(artifact), len(artifact))
            ):
                raise ValueError("Signature input changed or was not inspected during the scan")
            # The verifier reads the same bounded byte snapshots that were
            # inspected, without resolving any path in the untrusted tree.
            with tempfile.TemporaryDirectory(prefix="hf-static-signature-") as directory:
                signature_file = Path(directory, Path(sf).name)
                artifact_file = Path(directory, Path(artifact_path).name)
                signature_file.write_bytes(signature)
                if artifact_file != signature_file:
                    artifact_file.write_bytes(artifact)
                sig, model = str(signature_file), str(artifact_file)
                if verifier_name == "cosign":
                    cmd = [verifier, "verify-blob", "--signature", sig, model]
                elif verifier_name == "gpg":
                    cmd = [verifier, "--verify", sig, model]
                else:
                    cmd = [verifier, "-Vm", model, "-x", sig]

                result = subprocess.run(  # nosec B603 - resolved verifier and fixed argv shape
                    cmd, capture_output=True, timeout=30
                )
            if result.returncode != 0:
                rule = get_rule("HFS-038")
                findings.append(
                    Finding(
                        "HFS-038",
                        rule.severity,
                        sf,
                        0,
                        0,
                        rule.description,
                        f"Verification failed: {result.stderr.decode('utf-8', errors='replace')[:200]}",
                        rule.remediation,
                        rule.cwe,
                    )
                )
        except (subprocess.TimeoutExpired, OSError, ValueError) as exc:
            rule = get_rule("HFS-038")
            findings.append(
                Finding(
                    "HFS-038",
                    rule.severity,
                    sf,
                    0,
                    0,
                    rule.description,
                    str(exc)[:200],
                    rule.remediation,
                    rule.cwe,
                )
            )

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
                findings.append(
                    Finding(
                        "HFS-036",
                        rule.severity,
                        artifact_path,
                        0,
                        0,
                        rule.description,
                        f"Expected SHA-256={expected[:16]}... got {actual[:16]}...",
                        rule.remediation,
                        rule.cwe,
                    )
                )

    # Report artifacts not covered by any SBOM
    for artifact_path in artifacts:
        basename = os.path.basename(artifact_path)
        if basename not in all_sbom_hashes:
            rule = get_rule("HFS-037")
            findings.append(
                Finding(
                    "HFS-037",
                    rule.severity,
                    artifact_path,
                    0,
                    0,
                    rule.description,
                    f"Artifact '{basename}' not listed in any SBOM",
                    rule.remediation,
                    rule.cwe,
                )
            )

    return findings
