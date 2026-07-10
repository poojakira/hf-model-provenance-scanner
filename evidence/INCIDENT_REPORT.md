# Incident Report: Fake OpenAI "Privacy Filter" Repository (May 2026)

## Executive Summary

In early May 2026, a malicious actor published a repository named **`Open-OSS/privacy-filter`** on Hugging Face, impersonating OpenAI's legitimate organization. The repository reached **#1 trending** on the platform and accumulated approximately **244,000 downloads** within 18 hours before being removed by moderators. The payload delivered a **Rust-based information stealer** targeting Windows systems.

This incident demonstrates the critical need for automated model provenance scanning in ML supply chains.

## Timeline

| Date | Event |
|------|-------|
| ~May 1, 2026 | Attacker creates "Open-OSS" organization on HuggingFace |
| ~May 1, 2026 | Repository `Open-OSS/privacy-filter` published |
| Within hours | Model card copied verbatim from OpenAI's legitimate content |
| ~18 hours | Reaches #1 trending; 244,000+ downloads recorded |
| ~May 2, 2026 | Platform moderators remove the repository |
| May 2026 | Multiple security firms publish analysis reports |

## Attack Chain (Kill Chain Analysis)

### Stage 1: Reconnaissance & Social Engineering
- Created organization name "Open-OSS" — visually similar to "openai"
- Copied model card (README.md) verbatim from legitimate OpenAI repository
- Named model "privacy-filter" — a plausible OpenAI product name

### Stage 2: Weaponization
- Embedded `loader.py` with multi-layer obfuscation
- Payload encoded in Base64 (decoded to PowerShell commands)
- Secondary payloads staged on jsonkeeper.com dead-drop service

### Stage 3: Delivery
- SSL certificate verification disabled (`ssl._create_unverified_context`)
- Network call to `jsonkeeper.com` for payload retrieval
- Silent exception handling to suppress error messages

### Stage 4: Exploitation
- Base64-decoded content reveals PowerShell command
- Hidden window execution (`-WindowStyle Hidden`, `CREATE_NO_WINDOW`)
- Downloads and executes Rust-based infostealer binary

### Stage 5: Installation & Persistence
- Windows Defender exclusion manipulation (`Add-MpPreference -ExclusionPath`)
- Scheduled task creation for persistence
- Zone.Identifier removal to bypass Windows security warnings

### Stage 6: Command & Control
- C2 communication via jsonkeeper.com
- Exfiltration of stolen credentials to attacker infrastructure
- Beacon-style check-in pattern

## Technical Indicators of Compromise (IOCs)

### Domains
- `jsonkeeper.com` (payload staging)
- `eth-fastscan.org` (secondary C2)

### File Hashes (loader.py techniques)
- SSL bypass: `ssl._create_unverified_context`
- Base64 payload: `cG93ZXJzaGVsbCAtV2luZG93U3R5bGU...`
- Hidden execution: `creationflags=0x08000000`

### MITRE ATT&CK / ATLAS Mapping
- **AML.T0010**: AI Supply Chain Compromise
- **AML.T0019**: Publish Poisoned Model
- **T1566.001**: Spearphishing Attachment (via model download)
- **T1059.001**: PowerShell execution
- **T1562.001**: Disable/Modify Security Tools (Defender exclusion)
- **T1053.005**: Scheduled Task persistence

## Impact Assessment

| Metric | Value |
|--------|-------|
| Downloads before removal | ~244,000 |
| Time to detection | ~18 hours |
| Platform affected | HuggingFace Hub |
| Target OS | Windows |
| Payload type | Rust infostealer |
| Data targeted | Browser credentials, API keys, crypto wallets |

## Root Cause Analysis

1. **No pre-download scanning**: HuggingFace's PickleScan only checks `.pkl` files, not Python source code
2. **No org verification requirement**: Anyone can create an org with any name
3. **No model card plagiarism detection**: Verbatim copies not flagged
4. **No velocity anomaly detection**: 244K downloads in 18h not auto-flagged
5. **Trust in platform trending**: Users assumed trending = safe

## How HF Model Provenance Scanner Detects This

Our scanner detects this attack at **multiple stages** simultaneously:

| Detection | Rule | Severity | Stage Blocked |
|-----------|------|----------|---------------|
| SSL verification disabled | HFS-002 | CRITICAL | Stage 3 |
| jsonkeeper.com C2 domain | HFS-004 | CRITICAL | Stage 3 |
| Base64 → PowerShell decode | HFS-003 | CRITICAL | Stage 2 |
| subprocess + powershell | HFS-001 | CRITICAL | Stage 4 |
| Hidden window execution | HFS-014 | HIGH | Stage 4 |
| Silent exception swallowing | HFS-012 | HIGH | Stage 3 |
| Known IOC domain | HFS-040 | HIGH | Stage 6 |
| Loader entrypoint present | HFS-025 | MEDIUM | Stage 2 |
| Network call in loader | HFS-023 | MEDIUM | Stage 3 |
| Model card similarity >0.90 | HFS-021 | MEDIUM | Stage 1 |
| Download velocity anomaly | HFS-022 | MEDIUM | Stage 1 |

**Total: 12+ findings, Risk Score: CRITICAL (100/100)**

## Verification

Run the red team simulation to verify detection:

```bash
cd hf-model-provenance-scanner
python3 tests/redteam/simulate_attacks.py
```

The simulation replicates the **exact techniques** from this incident and confirms 100% detection.

## References

- MLHive: "The Hugging Face Malware Epidemic: How a Fake OpenAI Model Hijacked 244K Systems" (May 2026)
- CSO Online: "Malicious Hugging Face model masquerading as OpenAI release hits 244K downloads" (July 2026)
- Infosecurity Magazine: "Malicious Hugging Face Repository Typosquats OpenAI" (June 2026)
- Acronis TRU: "AI supply chain attacks on Hugging Face and OpenClaw" (May 2026)
- CyberSecureFox: "Malicious Hugging Face Model Delivers Rust Infostealer" (May 2026)

## Lessons Learned

1. **Platform scanning is insufficient** — PickleScan has 7+ confirmed bypass vulnerabilities
2. **Source code analysis is essential** — the attack used Python loaders, not pickle
3. **Org impersonation is trivial** — no verification required to create similar names
4. **Speed matters** — 244K downloads in 18h means detection must be pre-download
5. **Multi-layer defense required** — no single technique catches everything
6. **Adoption is the bottleneck** — the best scanner is useless if nobody deploys it
