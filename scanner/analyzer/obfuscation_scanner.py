"""
Advanced Obfuscation Detection — Unicode homoglyphs, zero-width chars, polyglots.

Detects techniques used to bypass visual code review and static analysis:
1. Unicode confusable characters (Cyrillic а vs Latin a in identifiers)
2. Zero-width characters hidden in strings (ZWJ, ZWSP, ZWNJ, etc.)
3. Bidi override characters (RLO/LRO) that reverse displayed text
4. Polyglot file headers (files valid as multiple formats simultaneously)
5. Unicode escape sequences hiding dangerous strings
6. Invisible/control characters in source code
7. Homoglyph domain names in URLs
"""

import re
from typing import Optional

from scanner.models import Finding
from scanner.rules.definitions import get_rule

# Zero-width and invisible characters
ZERO_WIDTH_CHARS = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\u2060": "WORD JOINER",
    "\ufeff": "BYTE ORDER MARK (mid-file)",
    "\u00ad": "SOFT HYPHEN",
    "\u034f": "COMBINING GRAPHEME JOINER",
    "\u061c": "ARABIC LETTER MARK",
    "\u115f": "HANGUL CHOSEONG FILLER",
    "\u1160": "HANGUL JUNGSEONG FILLER",
    "\u17b4": "KHMER VOWEL INHERENT AQ",
    "\u17b5": "KHMER VOWEL INHERENT AA",
    "\u180e": "MONGOLIAN VOWEL SEPARATOR",
    "\u2000": "EN QUAD",
    "\u2001": "EM QUAD",
    "\u2002": "EN SPACE",
    "\u2003": "EM SPACE",
    "\u2004": "THREE-PER-EM SPACE",
    "\u2005": "FOUR-PER-EM SPACE",
    "\u2006": "SIX-PER-EM SPACE",
    "\u2007": "FIGURE SPACE",
    "\u2008": "PUNCTUATION SPACE",
    "\u2009": "THIN SPACE",
    "\u200a": "HAIR SPACE",
}

# Bidirectional override characters (can reverse displayed text)
BIDI_CHARS = {
    "\u202a": "LEFT-TO-RIGHT EMBEDDING",
    "\u202b": "RIGHT-TO-LEFT EMBEDDING",
    "\u202c": "POP DIRECTIONAL FORMATTING",
    "\u202d": "LEFT-TO-RIGHT OVERRIDE",
    "\u202e": "RIGHT-TO-LEFT OVERRIDE",
    "\u2066": "LEFT-TO-RIGHT ISOLATE",
    "\u2067": "RIGHT-TO-LEFT ISOLATE",
    "\u2068": "FIRST STRONG ISOLATE",
    "\u2069": "POP DIRECTIONAL ISOLATE",
}

# Common confusable character pairs (Cyrillic/Greek vs Latin)
# Format: {confusable_char: (latin_equivalent, script_name)}
CONFUSABLES = {
    "\u0430": ("a", "Cyrillic"),  # а
    "\u0435": ("e", "Cyrillic"),  # е
    "\u043e": ("o", "Cyrillic"),  # о
    "\u0440": ("p", "Cyrillic"),  # р
    "\u0441": ("c", "Cyrillic"),  # с
    "\u0443": ("y", "Cyrillic"),  # у
    "\u0445": ("x", "Cyrillic"),  # х
    "\u0456": ("i", "Cyrillic"),  # і
    "\u0458": ("j", "Cyrillic"),  # ј
    "\u0455": ("s", "Cyrillic"),  # ѕ
    "\u04bb": ("h", "Cyrillic"),  # һ
    "\u0501": ("d", "Cyrillic"),  # ԁ
    "\u051b": ("q", "Cyrillic"),  # ԛ
    "\u051d": ("w", "Cyrillic"),  # ԝ
    # Greek
    "\u03b1": ("a", "Greek"),  # α
    "\u03b5": ("e", "Greek"),  # ε
    "\u03bf": ("o", "Greek"),  # ο
    "\u03c1": ("p", "Greek"),  # ρ
    "\u0391": ("A", "Greek"),  # Α
    "\u0392": ("B", "Greek"),  # Β
    "\u0395": ("E", "Greek"),  # Ε
    "\u0397": ("H", "Greek"),  # Η
    "\u0399": ("I", "Greek"),  # Ι
    "\u039a": ("K", "Greek"),  # Κ
    "\u039c": ("M", "Greek"),  # Μ
    "\u039d": ("N", "Greek"),  # Ν
    "\u039f": ("O", "Greek"),  # Ο
    "\u03a1": ("P", "Greek"),  # Ρ
    "\u03a4": ("T", "Greek"),  # Τ
    "\u03a7": ("X", "Greek"),  # Χ
    "\u03a5": ("Y", "Greek"),  # Υ
    "\u0396": ("Z", "Greek"),  # Ζ
}

# Polyglot file signatures
POLYGLOT_SIGNATURES = [
    (b"%PDF", b"<script", "PDF+HTML polyglot"),
    (b"%PDF", b"<?php", "PDF+PHP polyglot"),
    (b"PK\x03\x04", b"<script", "ZIP+HTML polyglot"),
    (b"\x89PNG", b"<script", "PNG+HTML polyglot"),
    (b"GIF89a", b"<script", "GIF+HTML polyglot"),
    (b"\xff\xd8\xff", b"<script", "JPEG+HTML polyglot"),
]

# Regex for Unicode escape sequences that might hide dangerous content
UNICODE_ESCAPE_RE = re.compile(r"\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){3,}")


def _make_finding(rule_id: str, file_path: str, evidence: str, line: int = 0) -> Finding:
    rule = get_rule(rule_id)
    return Finding(
        rule_id=rule_id,
        severity=rule.severity,
        file_path=file_path,
        line_number=line,
        column=0,
        message=rule.description,
        evidence=evidence[:300],
        remediation=rule.remediation,
        cwe=rule.cwe,
    )


def scan_unicode_obfuscation(file_path: str, source: str) -> list[Finding]:
    """
    Scan source code for Unicode-based obfuscation techniques.
    """
    findings: list[Finding] = []
    lines = source.splitlines()

    zero_width_lines: list[int] = []
    bidi_lines: list[int] = []
    confusable_lines: list[tuple[int, str, str]] = []

    for line_num, line in enumerate(lines, 1):
        # Check for zero-width characters
        for char, name in ZERO_WIDTH_CHARS.items():
            if char in line:
                zero_width_lines.append(line_num)
                break

        # Check for bidi override characters
        for char, name in BIDI_CHARS.items():
            if char in line:
                bidi_lines.append(line_num)
                break

        # Check for confusable characters in identifiers
        # Only flag if mixed with ASCII in the same token
        tokens = re.findall(r"[a-zA-Z_\u0080-\uffff][a-zA-Z0-9_\u0080-\uffff]*", line)
        for token in tokens:
            has_ascii = any(c.isascii() and c.isalpha() for c in token)
            confusable_found = []
            for char in token:
                if char in CONFUSABLES:
                    confusable_found.append((char, CONFUSABLES[char]))
            if has_ascii and confusable_found:
                char, (latin, script) = confusable_found[0]
                confusable_lines.append((
                    line_num, token,
                    f"{script} '{char}' looks like Latin '{latin}'"
                ))

        # Check for long Unicode escape sequences (potential payload hiding)
        if UNICODE_ESCAPE_RE.search(line):
            findings.append(_make_finding(
                "HFS-066", file_path,
                f"Long Unicode escape sequence at line {line_num}: may hide payload",
                line_num,
            ))

    # Emit consolidated findings
    if zero_width_lines:
        findings.append(_make_finding(
            "HFS-065", file_path,
            f"Zero-width/invisible characters on {len(zero_width_lines)} lines: "
            f"{zero_width_lines[:10]}",
            zero_width_lines[0],
        ))

    if bidi_lines:
        findings.append(_make_finding(
            "HFS-064", file_path,
            f"Bidirectional override characters on {len(bidi_lines)} lines: "
            f"{bidi_lines[:10]}. Text display may be reversed to hide malicious code.",
            bidi_lines[0],
        ))

    if confusable_lines:
        examples = confusable_lines[:3]
        evidence_parts = [f"L{ln}: '{tok}' ({desc})" for ln, tok, desc in examples]
        findings.append(_make_finding(
            "HFS-064", file_path,
            f"Unicode confusable characters in identifiers: "
            f"{'; '.join(evidence_parts)}",
            confusable_lines[0][0],
        ))

    return findings


def scan_polyglot_header(file_path: str, data: bytes) -> list[Finding]:
    """
    Check if file has polyglot signatures (valid as multiple formats).
    """
    findings: list[Finding] = []

    # Only scan first 8KB for efficiency
    header = data[:8192]

    for sig1, sig2, description in POLYGLOT_SIGNATURES:
        if header.startswith(sig1) and sig2 in header:
            findings.append(_make_finding(
                "HFS-067", file_path,
                f"Polyglot file detected: {description}. "
                f"File is valid as multiple formats simultaneously."
            ))

    # Check for null bytes followed by script-like content
    # (indicates binary/text polyglot)
    if b"\x00" in header[:16] and (b"<script" in data[:4096] or b"eval(" in data[:4096]):
        findings.append(_make_finding(
            "HFS-067", file_path,
            "Binary header with embedded script content — possible polyglot attack"
        ))

    return findings


def analyze_obfuscation(file_path: str, source: str, raw_data: Optional[bytes] = None) -> list[Finding]:
    """
    Main entry point: run all obfuscation detection checks.
    """
    findings: list[Finding] = []

    # Unicode obfuscation in source
    findings.extend(scan_unicode_obfuscation(file_path, source))

    # Polyglot detection (needs raw bytes)
    if raw_data:
        findings.extend(scan_polyglot_header(file_path, raw_data))

    return findings
