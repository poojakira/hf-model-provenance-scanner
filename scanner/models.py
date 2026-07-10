"""Core data models for the HF Model Provenance Scanner."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    file_path: str
    line_number: int
    column: int
    message: str
    evidence: str
    remediation: str
    cwe: Optional[str]
    decoded_layer: int = 0


@dataclass
class OrgCheckResult:
    repo_id: str
    org_name: str
    is_verified: bool
    levenshtein_matches: list
    model_card_similarity_score: float
    age_hours: float
    download_velocity: int


@dataclass
class RiskSummary:
    score: int = 0
    level: str = "LOW"
    reasons: list = field(default_factory=list)


@dataclass
class ScanResult:
    scan_target: str
    scan_mode: str
    scanner_version: str
    findings: list = field(default_factory=list)
    org_check: Optional[OrgCheckResult] = None
    risk: RiskSummary = field(default_factory=RiskSummary)
    files_scanned: int = 0
    files_skipped: int = 0
    scan_duration_seconds: float = 0.0
    error: Optional[str] = None

    @property
    def highest_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        for sev in order:
            if any(f.severity == sev for f in self.findings):
                return sev
        return None
