# API Versioning Policy

## Overview

The HuggingFace Model Provenance Scanner maintains strict versioning guarantees for its public interfaces. This document defines what is considered stable, how breaking changes are managed, and what consumers can depend on.

We follow [Semantic Versioning 2.0.0](https://semver.org/):
- **MAJOR** (X.0.0): Breaking changes to stable APIs
- **MINOR** (0.X.0): New features, new rules, backward-compatible changes
- **PATCH** (0.0.X): Bug fixes, rule accuracy improvements, documentation

---

## 1. CLI Interface Stability

### Stable (Will Not Break Without Major Version Bump)

The following CLI behaviors are guaranteed stable:

| Feature | Guarantee |
|---------|-----------|
| `hf-scanner <path>` | Always accepts a positional path/target argument |
| `--format json` | JSON output schema is versioned (see §3) |
| `--format sarif` | SARIF 2.1.0 compliant output |
| `--format text` | Human-readable output (format may change cosmetically) |
| `--no-network` | Fully offline operation |
| `--rules-dir <path>` | Custom rules directory |
| `--severity <level>` | Filter by minimum severity |
| `--version` | Print version and exit |
| `--help` | Print usage and exit |
| Exit code 0 | No findings at or above severity threshold |
| Exit code 1 | Findings detected at or above severity threshold |
| Exit code 2 | Scanner error (invalid input, configuration error) |

### Unstable / Experimental

Features prefixed with `--experimental-` or documented as "unstable" may change in any release. Current experimental features:

- `--experimental-deep-scan` — Recursive archive inspection
- `--experimental-heuristic` — ML-based anomaly detection

### Deprecation Process

1. Feature marked deprecated in release notes and `--help` output
2. Deprecation warning printed to stderr for at least 2 minor versions
3. Feature removed in next major version

---

## 2. Rule ID Stability

### Rule ID Format

All rules follow the format `HFS-XXX` where XXX is a zero-padded integer:

```
HFS-001  Pickle GLOBAL opcode with os module
HFS-002  Pickle GLOBAL opcode with subprocess module
...
HFS-189  (current latest)
```

### Guarantees

| Guarantee | Description |
|-----------|-------------|
| **IDs are never reused** | Once `HFS-042` is assigned, that ID permanently refers to that specific detection, even if the rule is deprecated or removed. |
| **IDs are never reassigned** | A retired rule's ID becomes permanently reserved. |
| **Monotonically increasing** | New rules always get the next available integer. |
| **Stable severity** | A rule's severity level does not change without a MINOR version bump and CHANGELOG entry. |
| **Stable description** | The `id` + `name` fields are immutable once published. The `description` may be clarified. |

### Rule Lifecycle

```
DRAFT ──▶ ACTIVE ──▶ DEPRECATED ──▶ RETIRED
                         │
                         ▼
                    (still fires, warning emitted)
```

- **DRAFT**: In development, not in any release
- **ACTIVE**: Included in scanner, fully supported
- **DEPRECATED**: Still fires but marked for future removal; downstream should stop depending on it
- **RETIRED**: No longer fires; ID permanently reserved

### Suppression Stability

If a user suppresses `HFS-042` in their configuration:
- That suppression continues to work across all versions
- If the rule is retired, the suppression becomes a no-op (no error)

---

## 3. SARIF Output Schema Versioning

### Schema Version

The scanner outputs SARIF 2.1.0 compliant JSON. The output includes a version field:

```json
{
  "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [...]
}
```

### Custom Properties

Scanner-specific extensions use the `properties` bag as per SARIF spec:

```json
{
  "results": [{
    "ruleId": "HFS-042",
    "level": "error",
    "message": { "text": "..." },
    "properties": {
      "hf-scanner-version": "1.5.0",
      "confidence": 0.95,
      "opcode": "GLOBAL",
      "dangerous_import": "os.system"
    }
  }]
}
```

### Compatibility Guarantees

| Field | Stability |
|-------|-----------|
| `$schema` | Changes only with SARIF spec updates |
| `version` | Always `"2.1.0"` until SARIF 2.2 adoption |
| `runs[].tool.driver.name` | Always `"hf-model-provenance-scanner"` |
| `runs[].tool.driver.version` | Scanner version string |
| `runs[].results[].ruleId` | Matches `HFS-XXX` rule ID |
| `runs[].results[].level` | One of: `error`, `warning`, `note` |
| `properties.*` | May add new properties in MINOR versions; never removes existing ones |

### JSON Output Schema (`--format json`)

The native JSON format is versioned independently:

```json
{
  "schema_version": "1.0",
  "scanner_version": "1.5.0",
  "scan_timestamp": "2026-08-27T12:00:00Z",
  "target": "/path/to/model",
  "findings": [
    {
      "rule_id": "HFS-042",
      "severity": "CRITICAL",
      "file": "model.pkl",
      "offset": 128,
      "description": "...",
      "details": {}
    }
  ],
  "summary": {
    "total_files": 5,
    "files_scanned": 5,
    "findings_count": 1,
    "max_severity": "CRITICAL"
  }
}
```

**Schema version history:**

| Version | Changes |
|---------|---------|
| `1.0` | Initial stable schema |
| `1.1` | Added `summary.scan_duration_ms` field (backward compatible) |

**Guarantees:**
- `schema_version` bumps MINOR for additive changes (new fields)
- `schema_version` bumps MAJOR for breaking changes (removed/renamed fields)
- Breaking JSON schema changes require a scanner MAJOR version bump
- Consumers should ignore unknown fields for forward compatibility

---

## 4. Python API Compatibility

### Public API Surface

The following Python imports are considered public and stable:

```python
from hf_scanner import scan_file, scan_directory, Scanner
from hf_scanner.rules import load_rules, RuleSet
from hf_scanner.findings import Finding, Severity
from hf_scanner.formats import to_sarif, to_json
```

### Stability Tiers

| Tier | Import Path | Guarantee |
|------|-------------|-----------|
| **Stable** | `hf_scanner.*` (top-level) | SemVer: breaking changes only in MAJOR |
| **Public** | `hf_scanner.rules.*`, `hf_scanner.findings.*`, `hf_scanner.formats.*` | SemVer: breaking changes only in MAJOR |
| **Internal** | `hf_scanner._internal.*`, `hf_scanner.core._*` | May change in any release |
| **Plugins** | `hf_scanner.plugins.*` | Stable interface, plugin implementations may vary |

### Type Annotations

Public API functions include complete type annotations. Type changes follow these rules:

- **Widening** a parameter type (accepting more) = MINOR
- **Narrowing** a parameter type (accepting less) = MAJOR
- **Widening** a return type = MAJOR (caller may not handle new variants)
- **Narrowing** a return type (returning less) = MINOR

### Deprecation in Python API

```python
import warnings

def old_function():
    warnings.warn(
        "old_function() is deprecated since v1.4.0, use new_function() instead. "
        "It will be removed in v2.0.0.",
        DeprecationWarning,
        stacklevel=2,
    )
    return new_function()
```

- Deprecated functions remain for at least 2 minor versions
- Removed only in major versions
- Always include migration guidance in the warning message

### Minimum Python Version

- Current minimum: Python 3.10
- Python version support follows [NEP 29](https://numpy.org/neps/nep-0029-deprecation_policy.html) (support versions released in the last 42 months)
- Dropping a Python version is a MINOR version change (documented in CHANGELOG)

---

## 5. Versioning Summary Matrix

| Interface | Breaking Change = | Additive Change = | Bug Fix = |
|-----------|-------------------|-------------------|-----------|
| CLI flags & exit codes | MAJOR | MINOR | PATCH |
| Rule IDs (HFS-xxx) | Never broken (IDs permanent) | MINOR (new rules) | PATCH (accuracy fix) |
| SARIF output | MAJOR | MINOR | PATCH |
| JSON output schema | MAJOR | MINOR (schema_version bump) | PATCH |
| Python public API | MAJOR | MINOR | PATCH |
| Python internal API | Any | Any | Any |
| Rule severity levels | MINOR | MINOR | — |

---

## 6. Version Support Policy

| Version | Status | Support Until |
|---------|--------|--------------|
| 1.x (current) | Active | Until 2.0 + 6 months |
| 0.x | Legacy | Unsupported |

- Only the latest MINOR release receives PATCH updates
- Security fixes may be backported to previous MINOR on request
- LTS versions may be designated for enterprise consumers (TBD)

---

*Last updated: 2026-08-27*
*Owner: Core maintainers*
