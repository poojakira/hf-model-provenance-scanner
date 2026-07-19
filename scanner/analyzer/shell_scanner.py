"""Shell script analyzer: detects dangerous patterns in .sh/.bat/.ps1/.cmd files."""

import re
from typing import List

from scanner.models import Finding
from scanner.rules.definitions import get_rule

# Pattern definitions: (compiled_regex, rule_id, evidence_description)
_PATTERNS = [
    # HFS-005: PowerShell encoded commands
    (re.compile(r'powershell.*-(?:enc|encodedcommand)\b', re.IGNORECASE),
     "HFS-005", "PowerShell -EncodedCommand"),
    (re.compile(r'pwsh.*-(?:enc|encodedcommand)\b', re.IGNORECASE),
     "HFS-005", "pwsh -EncodedCommand"),

    # HFS-015: Defender exclusion manipulation
    (re.compile(r'Set-MpPreference\s+-ExclusionPath', re.IGNORECASE),
     "HFS-015", "Defender exclusion path modification"),
    (re.compile(r'Add-MpPreference\s+-Exclusion', re.IGNORECASE),
     "HFS-015", "Defender exclusion addition"),
    (re.compile(r'Set-MpPreference\s+-Disable', re.IGNORECASE),
     "HFS-015", "Defender preference disable"),

    # HFS-013: Zone.Identifier removal (Windows ADS bypass)
    (re.compile(r'Zone\.Identifier', re.IGNORECASE),
     "HFS-013", "Zone.Identifier ADS manipulation"),
    (re.compile(r'Unblock-File', re.IGNORECASE),
     "HFS-013", "Unblock-File (Zone.Identifier removal)"),

    # HFS-006: AMSI/ETW bypass
    (re.compile(r'amsi(?:InitFailed|Utils|Context|ScanBuffer)', re.IGNORECASE),
     "HFS-006", "AMSI bypass indicator"),
    (re.compile(r'AmsiScanBuffer', re.IGNORECASE),
     "HFS-006", "AMSI ScanBuffer manipulation"),
    (re.compile(r'\[Ref\]\.Assembly.*GetType.*SetValue.*true', re.IGNORECASE),
     "HFS-006", "Reflection-based AMSI bypass"),
    (re.compile(r'EtwEventWrite', re.IGNORECASE),
     "HFS-006", "ETW event disable"),

    # HFS-023: Network downloads in scripts
    (re.compile(r'Invoke-WebRequest|wget\s|curl\s.*-[oO]|urllib', re.IGNORECASE),
     "HFS-023", "Network download in script"),
    (re.compile(r'Net\.WebClient|DownloadFile|DownloadString', re.IGNORECASE),
     "HFS-023", "WebClient download"),
    (re.compile(r'Start-BitsTransfer', re.IGNORECASE),
     "HFS-023", "BITS transfer download"),

    # HFS-003: IEX/certutil code execution
    (re.compile(r'\bIEX\b|\bInvoke-Expression\b', re.IGNORECASE),
     "HFS-003", "Invoke-Expression (IEX)"),
    (re.compile(r'certutil.*-decode|certutil.*-urlcache', re.IGNORECASE),
     "HFS-003", "certutil decode/download"),

    # HFS-016: Scheduled tasks / persistence
    (re.compile(r'schtasks\s+/create', re.IGNORECASE),
     "HFS-016", "Scheduled task creation"),
    (re.compile(r'Register-ScheduledTask', re.IGNORECASE),
     "HFS-016", "Register-ScheduledTask"),
    (re.compile(r'New-ScheduledTask', re.IGNORECASE),
     "HFS-016", "New-ScheduledTask"),
    (re.compile(r'HKCU.*\\Run|HKLM.*\\Run', re.IGNORECASE),
     "HFS-016", "Registry Run key persistence"),
    (re.compile(r'crontab\s+-|@reboot', re.IGNORECASE),
     "HFS-016", "cron persistence"),

    # HFS-014: Hidden window execution
    (re.compile(r'WindowStyle\s+Hidden', re.IGNORECASE),
     "HFS-014", "Hidden WindowStyle"),
    (re.compile(r'CREATE_NO_WINDOW|0x08000000', re.IGNORECASE),
     "HFS-014", "CREATE_NO_WINDOW flag"),
    (re.compile(r'SW_HIDE', re.IGNORECASE),
     "HFS-014", "SW_HIDE window flag"),
    (re.compile(r'creationflags.*0x08000000', re.IGNORECASE),
     "HFS-014", "creationflags hidden window"),

    # HFS-004: Paste services / C2 endpoints
    (re.compile(r'pastebin\.com|hastebin\.com|paste\.ee', re.IGNORECASE),
     "HFS-004", "Paste service C2 endpoint"),
    (re.compile(r'ngrok\.io|ngrok-free\.app', re.IGNORECASE),
     "HFS-004", "ngrok tunnel endpoint"),
    (re.compile(r'trycloudflare\.com', re.IGNORECASE),
     "HFS-004", "Cloudflare tunnel endpoint"),
    (re.compile(r'webhook\.site|requestbin\.net', re.IGNORECASE),
     "HFS-004", "Webhook/requestbin endpoint"),
    (re.compile(r'transfer\.sh|anonfiles\.com', re.IGNORECASE),
     "HFS-004", "Anonymous file sharing endpoint"),
]


def analyze_shell_script(file_path: str, source: str) -> List[Finding]:
    """Analyze a shell/batch/PowerShell script for dangerous patterns.

    Scans for:
    - HFS-005: PowerShell encoded commands
    - HFS-015: Defender exclusions
    - HFS-013: Zone.Identifier removal
    - HFS-006: AMSI/ETW bypass
    - HFS-023: Network downloads
    - HFS-003: IEX/certutil execution
    - HFS-016: Scheduled task persistence
    - HFS-014: Hidden windows
    - HFS-004: Paste service C2
    """
    findings: List[Finding] = []
    seen: set = set()  # Deduplicate rule+line combos

    for pattern, rule_id, description in _PATTERNS:
        for match in pattern.finditer(source):
            line_num = source[:match.start()].count("\n") + 1
            dedup_key = (rule_id, line_num)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            rule = get_rule(rule_id)
            evidence = match.group()[:200]
            findings.append(Finding(
                rule_id, rule.severity, file_path, line_num, 0,
                rule.description, f"{description}: {evidence}",
                rule.remediation, rule.cwe))

    return findings
