"""
Temporal Analysis / Rug-Pull Detector — Compare scans over time.

Detects:
1. New malicious files added after initial trust establishment
2. Changed file hashes indicating weight poisoning or code injection
3. Removed security artifacts (deleted signatures, SBOMs)
4. Severity escalation between scan baselines
5. Publisher metadata changes (org name change, verification loss)

The baseline is stored as a JSON file that can be committed to version control
or stored in a CI artifact for comparison.
"""

import json
import os
import time
from dataclasses import dataclass, field
from typing import Optional

from scanner.models import Finding, ScanResult, Severity
from scanner.rules.definitions import get_rule

BASELINE_FILENAME = ".hf-scanner-baseline.json"


@dataclass
class FileBaseline:
    """Baseline record for a single file."""
    path: str
    sha256: str
    size: int
    findings_count: int
    highest_severity: Optional[str]


@dataclass
class ScanBaseline:
    """Complete scan baseline for temporal comparison."""
    scan_target: str
    scanned_at: float
    scanner_version: str
    risk_score: int
    risk_level: str
    total_findings: int
    files: list[FileBaseline] = field(default_factory=list)
    finding_rule_ids: list[str] = field(default_factory=list)
    org_verified: Optional[bool] = None
    org_name: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "scan_target": self.scan_target,
            "scanned_at": self.scanned_at,
            "scanner_version": self.scanner_version,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "total_findings": self.total_findings,
            "files": [
                {
                    "path": f.path,
                    "sha256": f.sha256,
                    "size": f.size,
                    "findings_count": f.findings_count,
                    "highest_severity": f.highest_severity,
                }
                for f in self.files
            ],
            "finding_rule_ids": self.finding_rule_ids,
            "org_verified": self.org_verified,
            "org_name": self.org_name,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ScanBaseline":
        files = [
            FileBaseline(
                path=f["path"],
                sha256=f["sha256"],
                size=f["size"],
                findings_count=f["findings_count"],
                highest_severity=f.get("highest_severity"),
            )
            for f in data.get("files", [])
        ]
        return cls(
            scan_target=data["scan_target"],
            scanned_at=data["scanned_at"],
            scanner_version=data["scanner_version"],
            risk_score=data["risk_score"],
            risk_level=data["risk_level"],
            total_findings=data["total_findings"],
            files=files,
            finding_rule_ids=data.get("finding_rule_ids", []),
            org_verified=data.get("org_verified"),
            org_name=data.get("org_name"),
        )


def _make_finding(rule_id: str, file_path: str, evidence: str) -> Finding:
    rule = get_rule(rule_id)
    return Finding(
        rule_id=rule_id,
        severity=rule.severity,
        file_path=file_path,
        line_number=0,
        column=0,
        message=rule.description,
        evidence=evidence[:300],
        remediation=rule.remediation,
        cwe=rule.cwe,
    )


def _normalize_path(path: str) -> str:
    """Normalize path separators for cross-platform baseline comparison."""
    return path.replace("\\", "/")


def create_baseline(
    result: ScanResult,
    file_hashes: dict[str, tuple[str, int]],
) -> ScanBaseline:
    """
    Create a baseline from a completed scan result.
    
    Args:
        result: The completed ScanResult
        file_hashes: Dict of {file_path: (sha256_hex, file_size)}
    """
    files = []
    for path, (hash_val, size) in file_hashes.items():
        norm_path = _normalize_path(path)
        path_findings = [f for f in result.findings if _normalize_path(f.file_path) == norm_path]
        highest = None
        if path_findings:
            for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
                if any(f.severity == sev for f in path_findings):
                    highest = sev.value
                    break
        files.append(FileBaseline(
            path=norm_path,
            sha256=hash_val,
            size=size,
            findings_count=len(path_findings),
            highest_severity=highest,
        ))

    return ScanBaseline(
        scan_target=result.scan_target,
        scanned_at=time.time(),
        scanner_version=result.scanner_version,
        risk_score=result.risk.score,
        risk_level=result.risk.level,
        total_findings=len(result.findings),
        files=files,
        finding_rule_ids=sorted(set(f.rule_id for f in result.findings)),
        org_verified=result.org_check.is_verified if result.org_check else None,
        org_name=result.org_check.org_name if result.org_check else None,
    )


def save_baseline(baseline: ScanBaseline, output_path: Optional[str] = None) -> str:
    """Save baseline to JSON file."""
    path = output_path or BASELINE_FILENAME
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(baseline.to_dict(), f, indent=2)
    return path


def load_baseline(path: Optional[str] = None) -> Optional[ScanBaseline]:
    """Load a previously saved baseline."""
    path = path or BASELINE_FILENAME
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return ScanBaseline.from_dict(data)
    except (json.JSONDecodeError, KeyError, OSError):
        return None


def compare_with_baseline(
    baseline: ScanBaseline,
    current_result: ScanResult,
    current_hashes: dict[str, tuple[str, int]],
) -> list[Finding]:
    """
    Compare current scan against a stored baseline to detect rug-pulls.
    
    Detects:
    - New critical/high findings that weren't in the baseline
    - Files whose hashes changed (possible code injection)
    - New files with suspicious characteristics
    - Risk score escalation
    - Removed security artifacts
    - Org verification changes
    """
    findings: list[Finding] = []
    target = baseline.scan_target

    # 1. Risk escalation
    if current_result.risk.score > baseline.risk_score + 20:
        findings.append(_make_finding(
            "HFS-062", target,
            f"Risk score escalated: {baseline.risk_score} -> {current_result.risk.score} "
            f"(+{current_result.risk.score - baseline.risk_score})"
        ))

    # 2. New critical rules
    current_rules = set(f.rule_id for f in current_result.findings)
    baseline_rules = set(baseline.finding_rule_ids)
    new_rules = current_rules - baseline_rules
    critical_new = [r for r in new_rules if r.startswith("HFS-00")]  # Critical rules
    if critical_new:
        findings.append(_make_finding(
            "HFS-061", target,
            f"New critical findings since baseline: {critical_new}"
        ))

    # 3. File hash changes
    baseline_files = {f.path: f for f in baseline.files}
    for path, (current_hash, current_size) in current_hashes.items():
        norm_path = _normalize_path(path)
        baseline_file = baseline_files.get(norm_path)
        if baseline_file is None:
            # New file — check if it has findings
            path_findings = [f for f in current_result.findings if f.file_path == path]
            if any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in path_findings):
                findings.append(_make_finding(
                    "HFS-061", path,
                    "New file with critical/high findings added after baseline"
                ))
        elif baseline_file.sha256 != current_hash:
            # File changed — possible rug pull
            path_findings = [f for f in current_result.findings if f.file_path == path]
            if path_findings:
                findings.append(_make_finding(
                    "HFS-061", path,
                    f"File hash changed AND has findings. "
                    f"Old: {baseline_file.sha256[:16]}... "
                    f"New: {current_hash[:16]}..."
                ))
            else:
                findings.append(_make_finding(
                    "HFS-063", path,
                    f"File hash changed since baseline scan. "
                    f"Old: {baseline_file.sha256[:16]}... "
                    f"New: {current_hash[:16]}..."
                ))

    # 4. Removed files (potentially deleted signatures/SBOMs)
    current_paths = set(current_hashes.keys())
    for baseline_file in baseline.files:
        if baseline_file.path not in current_paths:
            lower = baseline_file.path.lower()
            if any(kw in lower for kw in ("sig", "sbom", "aibom", "cosign", "attestation")):
                findings.append(_make_finding(
                    "HFS-062", baseline_file.path,
                    f"Security artifact removed since baseline: {baseline_file.path}"
                ))

    # 5. Org verification loss
    if current_result.org_check and baseline.org_verified:
        if not current_result.org_check.is_verified:
            findings.append(_make_finding(
                "HFS-062", target,
                "Organization lost verified status since baseline"
            ))

    return findings
