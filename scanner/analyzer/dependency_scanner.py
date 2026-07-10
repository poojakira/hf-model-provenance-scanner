"""Dependency file analyzer: requirements.txt, pyproject.toml, Dockerfiles."""

import json
import os
import re
from typing import List

from scanner.models import Finding, Severity
from scanner.rules.definitions import get_rule

# Load IOC data at module level
_IOC_DATA = None


def _load_iocs() -> dict:
    global _IOC_DATA
    if _IOC_DATA is None:
        ioc_path = os.path.join(os.path.dirname(__file__), "..", "data", "iocs.json")
        try:
            with open(ioc_path, "r", encoding="utf-8") as f:
                _IOC_DATA = json.load(f)
        except (OSError, json.JSONDecodeError):
            _IOC_DATA = {
                "domains": [],
                "dangerous_packages": [],
                "vulnerable_versions": {},
                "suspicious_tlds": [],
            }
    return _IOC_DATA


# Dockerfile patterns
DOCKERFILE_ROOT_PATTERN = re.compile(r'^\s*USER\s+root', re.MULTILINE | re.IGNORECASE)
DOCKERFILE_PRIVILEGED = re.compile(r'--privileged', re.IGNORECASE)
DOCKERFILE_CURL_PIPE = re.compile(r'curl\s+.*\|\s*(sh|bash|python)', re.IGNORECASE)
DOCKERFILE_UNPINNED_FROM = re.compile(r'^\s*FROM\s+\S+(?!@sha256:)', re.MULTILINE | re.IGNORECASE)

# Requirements patterns
VERSION_PIN_PATTERN = re.compile(r'^([a-zA-Z0-9_-]+)\s*(==|>=|<=|~=|!=|>|<)\s*([^\s;#]+)', re.MULTILINE)
UNPINNED_PATTERN = re.compile(r'^([a-zA-Z0-9_-]+)\s*$', re.MULTILINE)
URL_PATTERN = re.compile(r'https?://[^\s"\']+')


def _parse_version(version_str: str) -> tuple:
    """Parse version string into comparable tuple."""
    parts = re.findall(r'\d+', version_str)
    return tuple(int(p) for p in parts) if parts else (0,)


def _version_below(actual: str, minimum: str) -> bool:
    """Check if actual version is below minimum."""
    return _parse_version(actual) < _parse_version(minimum)


def analyze_dependency_source(file_path: str, source: str) -> List[Finding]:
    """Analyze dependency files for security issues.

    Checks:
    - HFS-040: IOC domains referenced
    - HFS-041: Dangerous packages
    - HFS-042: Vulnerable dependency versions
    - HFS-043: Unpinned dependencies
    - HFS-044: Unsafe container directives (Dockerfiles)
    """
    findings: List[Finding] = []
    basename = os.path.basename(file_path).lower()
    iocs = _load_iocs()

    # Check all text files for IOC domains
    for domain in iocs.get("domains", []):
        if domain in source:
            pos = source.find(domain)
            line_num = source[:pos].count("\n") + 1
            rule = get_rule("HFS-040")
            findings.append(Finding(
                "HFS-040", rule.severity, file_path, line_num, 0,
                rule.description, f"domain={domain}",
                rule.remediation, rule.cwe))

    # Dockerfile analysis
    if basename in ("dockerfile", "containerfile") or basename.startswith("dockerfile"):
        findings.extend(_analyze_dockerfile(file_path, source))
        return findings

    # Only continue for dependency-specific files
    if basename not in ("requirements.txt", "requirements-dev.txt", "constraints.txt",
                        "pyproject.toml", "environment.yml", "environment.yaml"):
        return findings

    dangerous_packages = set(p.lower() for p in iocs.get("dangerous_packages", []))
    vulnerable_versions = iocs.get("vulnerable_versions", {})

    # Parse requirements-style files
    if basename.endswith(".txt"):
        findings.extend(_analyze_requirements(file_path, source, dangerous_packages, vulnerable_versions))
    elif basename == "pyproject.toml":
        findings.extend(_analyze_pyproject(file_path, source, dangerous_packages, vulnerable_versions))

    return findings


def _analyze_requirements(file_path: str, source: str,
                          dangerous_packages: set, vulnerable_versions: dict) -> List[Finding]:
    """Analyze requirements.txt format files."""
    findings: List[Finding] = []

    for line_num, line in enumerate(source.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        # Check for URLs in requirements (potential supply chain attack)
        if "://" in line:
            continue

        # Extract package name and version
        match = VERSION_PIN_PATTERN.match(line)
        if match:
            pkg_name = match.group(1).lower()
            operator = match.group(2)
            version = match.group(3)

            # HFS-041: Dangerous packages
            if pkg_name in dangerous_packages:
                rule = get_rule("HFS-041")
                findings.append(Finding(
                    "HFS-041", rule.severity, file_path, line_num, 0,
                    rule.description, f"package={pkg_name}",
                    rule.remediation, rule.cwe))

            # HFS-042: Vulnerable versions
            if pkg_name in vulnerable_versions and operator == "==":
                min_version = vulnerable_versions[pkg_name]
                if _version_below(version, min_version):
                    rule = get_rule("HFS-042")
                    findings.append(Finding(
                        "HFS-042", rule.severity, file_path, line_num, 0,
                        rule.description,
                        f"{pkg_name}=={version} < minimum safe {min_version}",
                        rule.remediation, rule.cwe))
        else:
            # Check for unpinned
            unpinned = UNPINNED_PATTERN.match(line)
            if unpinned:
                pkg_name = unpinned.group(1).lower()
                # HFS-041 check
                if pkg_name in dangerous_packages:
                    rule = get_rule("HFS-041")
                    findings.append(Finding(
                        "HFS-041", rule.severity, file_path, line_num, 0,
                        rule.description, f"package={pkg_name}",
                        rule.remediation, rule.cwe))
                else:
                    # HFS-043: Unpinned
                    rule = get_rule("HFS-043")
                    findings.append(Finding(
                        "HFS-043", rule.severity, file_path, line_num, 0,
                        rule.description, f"package={pkg_name}",
                        rule.remediation, rule.cwe))

    return findings


def _analyze_pyproject(file_path: str, source: str,
                       dangerous_packages: set, vulnerable_versions: dict) -> List[Finding]:
    """Analyze pyproject.toml for dependency issues."""
    findings: List[Finding] = []

    # Simple regex-based extraction of dependencies from pyproject.toml
    # Look for dependencies = [...] sections
    dep_section = re.search(r'dependencies\s*=\s*\[(.*?)\]', source, re.DOTALL)
    if not dep_section:
        return findings

    deps_text = dep_section.group(1)
    section_start = source[:dep_section.start()].count("\n")

    for rel_line, line in enumerate(deps_text.splitlines(), 1):
        line = line.strip().strip('",\'')
        if not line:
            continue
        line_num = section_start + rel_line

        # Extract package name
        pkg_match = re.match(r'([a-zA-Z0-9_-]+)', line)
        if not pkg_match:
            continue
        pkg_name = pkg_match.group(1).lower()

        if pkg_name in dangerous_packages:
            rule = get_rule("HFS-041")
            findings.append(Finding(
                "HFS-041", rule.severity, file_path, line_num, 0,
                rule.description, f"package={pkg_name}",
                rule.remediation, rule.cwe))

        # Check for pinned version
        version_match = re.search(r'==\s*([^\s,;"\']+)', line)
        if version_match and pkg_name in vulnerable_versions:
            version = version_match.group(1)
            min_version = vulnerable_versions[pkg_name]
            if _version_below(version, min_version):
                rule = get_rule("HFS-042")
                findings.append(Finding(
                    "HFS-042", rule.severity, file_path, line_num, 0,
                    rule.description,
                    f"{pkg_name}=={version} < minimum safe {min_version}",
                    rule.remediation, rule.cwe))

    return findings


def _analyze_dockerfile(file_path: str, source: str) -> List[Finding]:
    """Analyze Dockerfile for unsafe patterns."""
    findings: List[Finding] = []

    patterns = [
        (DOCKERFILE_ROOT_PATTERN, "USER root directive"),
        (DOCKERFILE_PRIVILEGED, "--privileged flag"),
        (DOCKERFILE_CURL_PIPE, "curl piped to shell"),
    ]

    for pattern, description in patterns:
        for match in pattern.finditer(source):
            line_num = source[:match.start()].count("\n") + 1
            rule = get_rule("HFS-044")
            findings.append(Finding(
                "HFS-044", rule.severity, file_path, line_num, 0,
                rule.description, description,
                rule.remediation, rule.cwe))

    # Check for unpinned FROM (no @sha256:)
    for match in DOCKERFILE_UNPINNED_FROM.finditer(source):
        line = match.group().strip()
        if "@sha256:" not in line and "scratch" not in line.lower():
            line_num = source[:match.start()].count("\n") + 1
            rule = get_rule("HFS-044")
            findings.append(Finding(
                "HFS-044", rule.severity, file_path, line_num, 0,
                rule.description, f"Unpinned base image: {line[:100]}",
                rule.remediation, rule.cwe))

    return findings
