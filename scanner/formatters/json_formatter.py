"""JSON output formatter for scan results."""

import json

from scanner.models import ScanResult


def format_json(result: ScanResult) -> str:
    """Serialize scan results to a JSON string."""
    findings_list = []
    for f in result.findings:
        findings_list.append({
            "rule_id": f.rule_id,
            "severity": f.severity.value,
            "file_path": f.file_path,
            "line_number": f.line_number,
            "column": f.column,
            "message": f.message,
            "evidence": f.evidence,
            "remediation": f.remediation,
            "cwe": f.cwe,
            "decoded_layer": f.decoded_layer,
        })

    org_check = None
    if result.org_check:
        org_check = {
            "repo_id": result.org_check.repo_id,
            "org_name": result.org_check.org_name,
            "is_verified": result.org_check.is_verified,
            "levenshtein_matches": result.org_check.levenshtein_matches,
            "model_card_similarity_score": result.org_check.model_card_similarity_score,
            "age_hours": result.org_check.age_hours,
            "download_velocity": result.org_check.download_velocity,
        }

    output = {
        "scan_target": result.scan_target,
        "scan_mode": result.scan_mode,
        "scanner_version": result.scanner_version,
        "findings": findings_list,
        "org_check": org_check,
        "risk": {
            "score": result.risk.score,
            "level": result.risk.level,
            "reasons": result.risk.reasons,
        },
        "files_scanned": result.files_scanned,
        "files_skipped": result.files_skipped,
        "scan_duration_seconds": result.scan_duration_seconds,
        "error": result.error,
    }
    return json.dumps(output, indent=2)
