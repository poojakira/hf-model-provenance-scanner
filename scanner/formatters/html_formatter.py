"""HTML report formatter for scan results."""

from scanner.models import ScanResult, Severity


def _severity_color(sev: Severity) -> str:
    return {
        Severity.CRITICAL: "#dc3545",
        Severity.HIGH: "#fd7e14",
        Severity.MEDIUM: "#ffc107",
        Severity.LOW: "#28a745",
        Severity.INFO: "#6c757d",
    }.get(sev, "#6c757d")


def format_html(result: ScanResult) -> str:
    """Generate an HTML report from scan results."""
    counts = {s: sum(1 for f in result.findings if f.severity == s) for s in Severity}

    findings_rows = []
    for f in result.findings:
        color = _severity_color(f.severity)
        evidence_escaped = (f.evidence or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        message_escaped = (f.message or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        file_escaped = (f.file_path or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        findings_rows.append(
            f'<tr>'
            f'<td><span style="color:{color};font-weight:bold">{f.severity.value.upper()}</span></td>'
            f'<td><code>{f.rule_id}</code></td>'
            f'<td>{file_escaped}:{f.line_number}</td>'
            f'<td>{message_escaped}</td>'
            f'<td><small>{evidence_escaped}</small></td>'
            f'</tr>'
        )

    risk_color = _severity_color(
        Severity.CRITICAL if result.risk.score >= 70
        else Severity.HIGH if result.risk.score >= 40
        else Severity.MEDIUM if result.risk.score >= 20
        else Severity.LOW
    )

    reasons_html = "".join(f"<li>{r}</li>" for r in result.risk.reasons)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>HF Scanner Report - {result.scan_target}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 2em; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 1em; }}
th, td {{ border: 1px solid #dee2e6; padding: 0.5em; text-align: left; }}
th {{ background: #f8f9fa; }}
.summary {{ display: flex; gap: 2em; margin: 1em 0; }}
.summary-card {{ padding: 1em; border-radius: 8px; background: #f8f9fa; }}
code {{ background: #e9ecef; padding: 0.1em 0.3em; border-radius: 3px; }}
</style>
</head>
<body>
<h1>HF Model Provenance Scanner Report</h1>
<p><strong>Target:</strong> {result.scan_target} | <strong>Mode:</strong> {result.scan_mode} | <strong>Version:</strong> {result.scanner_version}</p>
<p><strong>Duration:</strong> {result.scan_duration_seconds:.2f}s | <strong>Files scanned:</strong> {result.files_scanned} | <strong>Skipped:</strong> {result.files_skipped}</p>

<h2>Risk Assessment</h2>
<div class="summary">
<div class="summary-card">
<strong style="color:{risk_color};font-size:1.5em">{result.risk.level}</strong>
<p>Score: {result.risk.score}/100</p>
<ul>{reasons_html}</ul>
</div>
<div class="summary-card">
<p><strong>Critical:</strong> {counts[Severity.CRITICAL]}</p>
<p><strong>High:</strong> {counts[Severity.HIGH]}</p>
<p><strong>Medium:</strong> {counts[Severity.MEDIUM]}</p>
<p><strong>Low:</strong> {counts[Severity.LOW]}</p>
<p><strong>Info:</strong> {counts[Severity.INFO]}</p>
</div>
</div>

<h2>Findings ({len(result.findings)})</h2>
<table>
<thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Message</th><th>Evidence</th></tr></thead>
<tbody>
{"".join(findings_rows)}
</tbody>
</table>

{f'<p class="error"><strong>Error:</strong> {result.error}</p>' if result.error else ''}
</body>
</html>"""
    return html
