"""Risk score computation for scan results."""

from scanner.models import RiskSummary, ScanResult, Severity

SEVERITY_POINTS = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 15,
    Severity.MEDIUM: 7,
    Severity.LOW: 2,
    Severity.INFO: 0,
}

# Rules that indicate high-signal active threats get bonus points
HIGH_SIGNAL_RULES = {
    "HFS-001", "HFS-003", "HFS-004", "HFS-005", "HFS-006",
    "HFS-036", "HFS-038",
}
HIGH_SIGNAL_BONUS = 10


def compute_risk(result: ScanResult) -> RiskSummary:
    """Compute a 0-100 risk score from scan findings.

    Scoring:
    - CRITICAL: 40 points each
    - HIGH: 15 points each
    - MEDIUM: 7 points each
    - LOW: 2 points each
    - INFO: 0 points
    - High-signal rules add a bonus of 10 per occurrence
    - Score is capped at 100
    """
    score = 0
    reasons: list[str] = []
    severity_counts = {s: 0 for s in Severity}

    for finding in result.findings:
        points = SEVERITY_POINTS.get(finding.severity, 0)
        score += points
        severity_counts[finding.severity] += 1

        if finding.rule_id in HIGH_SIGNAL_RULES:
            score += HIGH_SIGNAL_BONUS

    # Cap at 100
    score = min(score, 100)

    # Determine level
    if score >= 70:
        level = "CRITICAL"
    elif score >= 40:
        level = "HIGH"
    elif score >= 20:
        level = "MEDIUM"
    elif score > 0:
        level = "LOW"
    else:
        level = "LOW"

    # Build reason strings
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        count = severity_counts[sev]
        if count > 0:
            reasons.append(f"{count} {sev.value} finding{'s' if count != 1 else ''}")

    if any(f.rule_id in HIGH_SIGNAL_RULES for f in result.findings):
        reasons.append("High-signal active threat indicators detected")

    return RiskSummary(score=score, level=level, reasons=reasons)
