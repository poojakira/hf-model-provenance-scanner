"""SARIF 2.1.0 output formatter for scan results."""

from scanner.models import ScanResult, Severity
from scanner.rules.definitions import RULES


_SARIF_SEVERITY_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def json_to_sarif(result: ScanResult) -> dict:
    """Convert scan results to SARIF 2.1.0 format."""
    rules = []
    rule_index_map = {}
    for idx, (rule_id, rule) in enumerate(RULES.items()):
        rule_index_map[rule_id] = idx
        rule_entry = {
            "id": rule.id,
            "name": rule.name,
            "shortDescription": {"text": rule.description},
            "helpUri": f"https://github.com/poojakira/hf-model-provenance-scanner#{rule.id}",
            "properties": {
                "tags": rule.tags,
            },
        }
        if rule.cwe:
            rule_entry["properties"]["cwe"] = rule.cwe
        rules.append(rule_entry)

    results = []
    for finding in result.findings:
        sarif_result = {
            "ruleId": finding.rule_id,
            "ruleIndex": rule_index_map.get(finding.rule_id, 0),
            "level": _SARIF_SEVERITY_MAP.get(finding.severity, "note"),
            "message": {
                "text": finding.message,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file_path,
                        },
                        "region": {
                            "startLine": max(finding.line_number, 1),
                            "startColumn": max(finding.column, 1),
                        },
                    }
                }
            ],
        }
        if finding.evidence:
            sarif_result["properties"] = {"evidence": finding.evidence}
        results.append(sarif_result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "hf-scanner",
                        "version": result.scanner_version,
                        "informationUri": "https://github.com/poojakira/hf-model-provenance-scanner",
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": result.error is None,
                        "properties": {
                            "scanTarget": result.scan_target,
                            "scanMode": result.scan_mode,
                            "filesScanned": result.files_scanned,
                            "filesSkipped": result.files_skipped,
                            "scanDurationSeconds": result.scan_duration_seconds,
                            "riskScore": result.risk.score,
                            "riskLevel": result.risk.level,
                        },
                    }
                ],
            }
        ],
    }
    return sarif
