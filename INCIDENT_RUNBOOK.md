# Incident Response Runbook — HF Model Provenance Scanner

## Overview

This runbook covers incident response procedures for the HuggingFace Model Provenance Scanner project. As a supply-chain security tool, incidents may include scanner bypasses, false positives affecting production systems, or newly discovered attack vectors in model serialization formats.

**Severity Levels:**

| Level | Description | Response Time |
|-------|-------------|---------------|
| SEV-1 | Active exploitation / scanner bypass in the wild | < 1 hour |
| SEV-2 | Confirmed bypass with no known exploitation | < 4 hours |
| SEV-3 | False positive blocking legitimate models | < 24 hours |
| SEV-4 | Minor rule improvement / non-urgent enhancement | Next sprint |

---

## 1. New Bypass Discovered

### Immediate Actions (First 30 Minutes)

1. **Confirm the bypass**
   - Reproduce the bypass with a minimal proof-of-concept
   - Determine which pickle opcodes / serialization tricks are used
   - Verify against the current rule set (`Rule()` objects in `scanner/rules/definitions.py`)
   - Document: What is the attack vector? Which rule(s) should have caught it?

2. **Assess blast radius**
   - Check HuggingFace Hub for models using this technique
   - Determine if any known-malicious models exploit this bypass
   - Estimate number of affected downstream users

3. **Notify stakeholders**
   - Post to `#security-incidents` internal channel
   - Notify HuggingFace security team via `security@huggingface.co`
   - If SEV-1: Page on-call engineer via PagerDuty

### Containment (Hours 1–4)

4. **Draft emergency rule**
   - Create new rule targeting the bypass opcode pattern
   - Assign rule ID following `HFS-XXX` convention (see Rule ID Registry)
   - Write at least 3 test cases: exact match, variant, edge case

5. **Test emergency rule**
   ```bash
   # Run against the PoC
   python -m scanner.cli poc_bypass.pkl -m local

   # Run full test suite to check for regressions
   pytest tests/ -x --timeout=60

   # Run against known-good models for a false positive check
   python -m scanner.cli ./known-good-models -m local --fail-on never --verbose
   ```

6. **Peer review**
   - Emergency rules require at least ONE reviewer
   - Reviewer checks: detection accuracy, false positive risk, performance impact

### Resolution

7. **Deploy fix** (see Section 3: Emergency Rule Deployment)
8. **Post-incident review** within 48 hours
9. **Update rule documentation** and CHANGELOG

---

## 2. Rule Update Procedure

### Standard Rule Addition

```
┌─────────────────┐     ┌──────────────┐     ┌─────────────┐     ┌──────────┐
│ Identify Pattern │────▶│ Write Rule   │────▶│ Write Tests │────▶│ PR Review│
└─────────────────┘     └──────────────┘     └─────────────┘     └──────────┘
                                                                        │
                              ┌──────────┐     ┌─────────────┐          │
                              │ Release  │◀────│ Merge to    │◀─────────┘
                              └──────────┘     │ main        │
                                               └─────────────┘
```

### Steps

1. **Add a `Rule()` object** in `scanner/rules/definitions.py`:
   ```python
   Rule(
       id="HFS-190",
       name="Detect pickle INST opcode with dangerous module",
       severity="CRITICAL",
       description=(
           "The INST opcode instantiates a class, which can be abused to "
           "execute arbitrary code during deserialization."
       ),
       dangerous_modules=["os", "subprocess", "sys", "builtins", "nt", "posix"],
       references=["https://blog.example.com/pickle-exploit"],
   )
   ```

2. **Write test cases** in `tests/rules/`:
   - `test_HFS190_positive.py` — Files that MUST trigger the rule
   - `test_HFS190_negative.py` — Files that MUST NOT trigger the rule
   - `test_HFS190_edge.py` — Boundary conditions

3. **Validate performance impact**:
   ```bash
   python benchmarks/scan_perf.py --output before.json
   # Apply rule
   python benchmarks/scan_perf.py --output after.json
   # Compare before.json and after.json manually or with your own diff tooling
   ```

4. **Submit PR** with:
   - Updated `scanner/rules/definitions.py`
   - Test files (minimum 5 test cases)
   - Performance comparison
   - CHANGELOG entry

5. **Rule ID Registry**: Rule IDs are tracked in `scanner/rules/definitions.py` — IDs are never reused.

---

## 3. Emergency Rule Deployment

### When to Use

- SEV-1 or SEV-2 incidents where waiting for standard release is unacceptable
- Active exploitation detected in the wild

### Procedure

1. **Create hotfix branch** from latest release tag:
   ```bash
   git checkout -b hotfix/HFS-XXX vX.Y.Z
   ```

2. **Add rule + minimal tests**:
   ```bash
   # Add the new Rule() to scanner/rules/definitions.py

   # Run smoke tests
   pytest tests/ -k "test_HFS" --timeout=30
   ```

3. **Fast-track review**:
   - Requires ONE approving review (normally two)
   - Reviewer must be from CODEOWNERS security team
   - Mark PR with `emergency` and `security` labels

4. **Release**:
   ```bash
   # Bump the version in pyproject.toml (edit the version field directly)

   # Tag and push
   git tag vX.Y.(Z+1)
   git push origin hotfix/HFS-XXX --tags
   ```

5. **PyPI deployment** (automatic via CI):
   - CI workflow triggers on tag push
   - Generates SBOM attestation
   - Publishes to PyPI with Trusted Publisher

6. **Notify downstream**:
   - Post GitHub Security Advisory (if applicable)
   - Notify HuggingFace to update their integrated scanner version
   - Post to project mailing list / Discord

### Rollback Procedure

If the emergency rule causes widespread false positives:

```bash
# Revert the rule
git revert <commit-hash>

# Immediate patch release: bump the version field in pyproject.toml
git tag vX.Y.(Z+2)
git push origin main --tags
```

---

## 4. False Positive Handling

### Triage

1. **Receive report** via GitHub issue or security contact
2. **Reproduce locally**:
   ```bash
   python -m scanner.cli <reported_model_path> -m local --verbose --format json > report.json
   ```
3. **Classify**:
   - **True false positive**: Rule is overly broad → fix rule
   - **Suspicious but benign**: Unusual pattern that looks dangerous but isn't → add to allowlist with justification
   - **Intentional detection**: Model genuinely contains dangerous code → close as "working as intended"

### Resolution Process

For true false positives:

1. **Add to false-positive regression test suite**:
   ```python
   # tests/false_positives/test_fp_ISSUE_NUMBER.py
   def test_reported_false_positive_issue_123():
       """Model X reported as FP in issue #123."""
       result = scan_file("fixtures/fp_issue_123.pkl")
       assert result.findings == []
   ```

2. **Narrow the rule** to exclude the benign pattern:
   - Add specific allowlist entry, OR
   - Tighten the opcode pattern match, OR
   - Add contextual analysis to distinguish benign from malicious use

3. **Validate no security regression**:
   ```bash
   # Ensure all malicious fixtures still detected
   pytest tests/ -k "malicious" --strict-markers
   ```

4. **Release patch** within 24 hours for SEV-3

### Allowlist Management

- Allowlisted patterns live in `rules/allowlists/`
- Each entry requires: justification, author, date, issue link
- Allowlists are reviewed quarterly for continued relevance

---

## 5. Coordination with HuggingFace Security Team

### Communication Channels

| Channel | Purpose | SLA |
|---------|---------|-----|
| `security@huggingface.co` | Report new attack vectors | Response within 24h |
| Private GitHub Security Advisory | Coordinated disclosure | Per advisory timeline |
| Shared Slack channel `#hf-scanner-security` | Real-time coordination | During incidents |

### Coordinated Disclosure Process

1. **Discovery**: New bypass or attack vector identified
2. **Private notification**: Report to HuggingFace security team with:
   - Technical description of the vulnerability
   - Proof-of-concept (minimal, non-weaponized)
   - Proposed detection rule
   - Estimated timeline for fix
3. **Coordination window**: 90 days standard (14 days if actively exploited)
4. **Parallel work**:
   - We develop and test the detection rule
   - HuggingFace implements server-side mitigations
5. **Joint disclosure**: Publish advisory, release scanner update, HF deploys server-side fix
6. **Post-disclosure**: Monitor for variants and follow-up attacks

### Information Sharing

**We share with HuggingFace:**
- New opcode abuse techniques discovered
- Models flagged as malicious (hashes, repo IDs)
- Scanner bypass techniques
- Performance data on Hub-scale scanning

**HuggingFace shares with us:**
- New model formats requiring scanner support
- Telemetry on scanner effectiveness (detection rates)
- Reports from their internal security scanning
- Upcoming format changes that may affect rules

### Joint Incident Response

For SEV-1 incidents affecting both parties:

1. Open shared incident bridge (video call)
2. Designate incident commander (rotates)
3. Parallel workstreams: scanner rule (us) + server-side block (HF)
4. Coordinated deployment: both parties deploy within same maintenance window
5. Joint post-incident review within 72 hours

---

## 6. Post-Incident Review Template

```markdown
## Incident Review: [TITLE]

**Date:** YYYY-MM-DD
**Severity:** SEV-X
**Duration:** X hours
**Rule(s) affected:** HFS-XXX

### Timeline
- HH:MM — Incident reported/detected
- HH:MM — Incident confirmed
- HH:MM — Emergency rule drafted
- HH:MM — Rule deployed
- HH:MM — All-clear confirmed

### Root Cause
[What allowed the bypass/false positive to occur?]

### Detection Gap
[Why didn't existing rules catch this?]

### Resolution
[What rule/code change fixed it?]

### Action Items
- [ ] Add regression test
- [ ] Update rule documentation
- [ ] Review similar rules for same gap
- [ ] Update this runbook if process gaps found

### Lessons Learned
[What should we do differently next time?]
```

---

## 7. Escalation Matrix

| Condition | Action |
|-----------|--------|
| Bypass confirmed, no exploitation | SEV-2: Fix within 4 hours |
| Bypass with active exploitation | SEV-1: Page on-call, fix within 1 hour |
| False positive on top-100 model | SEV-3: Fix within 24 hours |
| False positive on obscure model | SEV-4: Fix in next release |
| Scanner crash / DoS vector | SEV-2: Fix within 4 hours |
| Performance regression > 2x | SEV-3: Investigate within 24 hours |

---

## 8. Contact Information

| Role | Contact | Backup |
|------|---------|--------|
| Security Lead | @security-lead | @backup-security |
| On-Call Engineer | PagerDuty rotation | — |
| HuggingFace Security | security@huggingface.co | — |
| Release Manager | @release-manager | @backup-release |

---

*Last updated: 2026-08-27*
*Next review date: 2026-11-27*
*Owner: Security Team*
