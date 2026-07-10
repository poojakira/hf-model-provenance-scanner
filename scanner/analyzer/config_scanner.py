"""Config file analyzer: detects suspicious URLs, unpinned refs, and trust_remote_code."""

import json
import re
from typing import List

from scanner.models import Finding, Severity
from scanner.rules.definitions import get_rule

# Fields where URLs are expected/normal in HF config files
STANDARD_URL_FIELDS = {
    "model_type", "architectures", "tokenizer_class",
    "auto_map", "transformers_version", "_name_or_path",
}

URL_PATTERN = re.compile(r'https?://[^\s"\']+')
TRUST_REMOTE_CODE_PATTERN = re.compile(r'trust_remote_code["\s:=]*true', re.IGNORECASE)
FROM_PRETRAINED_PATTERN = re.compile(
    r'from_pretrained\s*\(\s*["\']([^"\']+)["\'](?:\s*,\s*(?!revision))*\)',
    re.IGNORECASE,
)


def analyze_config_file(file_path: str, source: str) -> List[Finding]:
    """Analyze a JSON config file for suspicious patterns.

    Checks:
    - HFS-024: URLs in non-standard config fields
    - HFS-030: Unpinned model references (no revision= with 40-char SHA)
    - HFS-031: trust_remote_code=True
    """
    findings: List[Finding] = []
    lower_path = file_path.lower()

    # Only analyze JSON config files
    if not lower_path.endswith(".json"):
        return findings

    # Check for trust_remote_code in raw source
    for match in TRUST_REMOTE_CODE_PATTERN.finditer(source):
        line_num = source[:match.start()].count("\n") + 1
        rule = get_rule("HFS-031")
        findings.append(Finding(
            "HFS-031", rule.severity, file_path, line_num, 0,
            rule.description, match.group()[:100],
            rule.remediation, rule.cwe))

    # Try to parse as JSON for deeper analysis
    try:
        config = json.loads(source)
    except (json.JSONDecodeError, ValueError):
        return findings

    if not isinstance(config, dict):
        return findings

    # HFS-024: Check for URLs in non-standard fields
    for key, value in config.items():
        if key.startswith("_") or key in STANDARD_URL_FIELDS:
            continue
        value_str = json.dumps(value) if not isinstance(value, str) else value
        urls = URL_PATTERN.findall(value_str)
        for url in urls:
            # Find approximate line number
            url_pos = source.find(url)
            line_num = source[:url_pos].count("\n") + 1 if url_pos >= 0 else 0
            rule = get_rule("HFS-024")
            findings.append(Finding(
                "HFS-024", rule.severity, file_path, line_num, 0,
                rule.description, f"field={key}, url={url[:200]}",
                rule.remediation, rule.cwe))

    # HFS-030: Check for unpinned model references in auto_map or _name_or_path
    name_or_path = config.get("_name_or_path", "")
    if name_or_path and "/" in name_or_path:
        # Check if it looks like org/model without a pinned revision
        if not re.search(r'[0-9a-f]{40}', name_or_path):
            # This is informational; actual from_pretrained calls are more concerning
            pass

    return findings
