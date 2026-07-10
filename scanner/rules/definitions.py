from dataclasses import dataclass
from typing import Optional
from scanner.models import Severity

@dataclass
class Rule:
    id: str
    name: str
    severity: Severity
    description: str
    remediation: str
    cwe: Optional[str]
    tags: list[str]

RULES: dict[str, Rule] = {
    "HFS-001": Rule("HFS-001", "powershell-subprocess", Severity.CRITICAL, "subprocess or shell execution whose args contain powershell, cmd.exe, or pwsh", "Remove the subprocess call. Models should not invoke shell commands.", "CWE-78", ["loader", "execution"]),
    "HFS-002": Rule("HFS-002", "ssl-verification-disabled", Severity.CRITICAL, "verify=False, ssl._create_unverified_context, check_hostname=False, or CERT_NONE TLS policy", "Remove SSL bypass. Use a proper CA bundle if connecting to internal endpoints.", "CWE-295", ["network", "ssl"]),
    "HFS-003": Rule("HFS-003", "base64-decoded-payload-executes", Severity.CRITICAL, "base64 string decoded and result passed to exec, eval, subprocess, or os.system", "Remove this code block entirely. A legitimate model loader has no reason to execute decoded payloads.", "CWE-94", ["obfuscation", "execution"]),
    "HFS-004": Rule("HFS-004", "paste-service-c2", Severity.CRITICAL, "network call to known paste/dead-drop or attacker infrastructure domains", "Remove the network call. Models should not fetch code or commands from public paste services.", "CWE-506", ["network", "c2"]),
    "HFS-005": Rule("HFS-005", "dynamic-powershell-in-shell", Severity.CRITICAL, ".bat or .ps1 file containing powershell + -EncodedCommand or -enc", "Remove the encoded PowerShell execution.", "CWE-78", ["loader", "shell"]),
    "HFS-006": Rule("HFS-006", "amsi-etw-disable", Severity.CRITICAL, "AMSI, ETW, or process-mitigation bypass strings present in model code", "Remove security software evasion techniques.", "CWE-693", ["evasion"]),
    "HFS-010": Rule("HFS-010", "high-entropy-string", Severity.HIGH, "String literal with Shannon entropy >= 5.7 AND length >= 40 chars, not in allowlist", "Remove highly obfuscated strings or add to allowlist if legitimate.", "CWE-506", ["obfuscation"]),
    "HFS-011": Rule("HFS-011", "dynamic-import-construction", Severity.HIGH, "Attribute or module name built via string concatenation", "Use standard, static import statements.", "CWE-94", ["obfuscation"]),
    "HFS-012": Rule("HFS-012", "silent-exception-swallow", Severity.HIGH, "except: or except Exception: pass wrapping suspicious loader behavior", "Handle exceptions explicitly and do not swallow network/execution errors silently.", "CWE-390", ["evasion"]),
    "HFS-013": Rule("HFS-013", "zone-identifier-removal", Severity.HIGH, "Zone.Identifier string in any file (Windows ADS removal)", "Remove Zone.Identifier manipulation.", "CWE-693", ["evasion"]),
    "HFS-014": Rule("HFS-014", "hidden-window-execution", Severity.HIGH, "CREATE_NO_WINDOW, WindowStyle Hidden, creationflags=0x08000000, or SW_HIDE in Python or shell", "Remove hidden window flags.", "CWE-693", ["evasion"]),
    "HFS-015": Rule("HFS-015", "defender-exclusion-add", Severity.HIGH, "Windows Defender exclusion or preference manipulation in model code", "Remove commands that modify Defender exclusions.", "CWE-693", ["evasion"]),
    "HFS-016": Rule("HFS-016", "scheduled-task-persistence", Severity.HIGH, "Scheduled task or startup persistence command in model code", "Remove persistence logic. Model loading code must not register startup tasks.", "CWE-693", ["persistence", "evasion"]),
    "HFS-020": Rule("HFS-020", "typosquat-levenshtein", Severity.MEDIUM, "Org name has Levenshtein distance <= 2 from a protected org", "Verify if the organization is legitimate or attempting to typosquat.", "CWE-451", ["typosquat"]),
    "HFS-021": Rule("HFS-021", "model-card-verbatim-copy", Severity.MEDIUM, "Cosine similarity of model card tokens >= 0.90 vs protected org card", "Verify model authenticity. Model card appears plagiarized.", "CWE-451", ["typosquat"]),
    "HFS-022": Rule("HFS-022", "new-org-high-velocity", Severity.MEDIUM, "Org age < 72 hours AND download count > 10,000", "Manual review recommended. This download velocity is highly unusual for a new organization.", "CWE-693", ["anomaly"]),
    "HFS-023": Rule("HFS-023", "suspicious-network-in-loader", Severity.MEDIUM, "Network call inside loader, setup, install, or startup model code", "Review network calls in loader scripts for potential C2 communication.", "CWE-506", ["network"]),
    "HFS-024": Rule("HFS-024", "outbound-call-in-config", Severity.MEDIUM, "config.json or tokenizer_config.json contains a URL in a non-standard field", "Remove suspicious URLs from configuration files.", "CWE-506", ["network"]),
    "HFS-025": Rule("HFS-025", "suspicious-loader-entrypoint", Severity.MEDIUM, "Repository contains executable loader/startup files that require manual review", "Review the entrypoint and remove it unless it is strictly required and audited.", "CWE-506", ["loader", "review"]),
    "HFS-030": Rule("HFS-030", "unpinned-model-reference", Severity.LOW, "from_pretrained('org/model') without revision= pointing to a full 40-char SHA", "Pin the model revision to a full commit SHA to prevent upstream changes.", None, ["best-practice"]),
    "HFS-031": Rule("HFS-031", "trust-remote-code-enabled", Severity.LOW, "trust_remote_code=True present in calling code or config", "Avoid trust_remote_code unless the publisher, revision, and code have been reviewed.", None, ["best-practice"]),
    "HFS-032": Rule("HFS-032", "unsigned-model", Severity.INFO, "Remote scan: model has no obvious Sigstore/GPG signature artifact", "Publishers should sign models to guarantee provenance.", None, ["best-practice", "signature"]),
    "HFS-033": Rule("HFS-033", "missing-ai-bom", Severity.INFO, "Remote scan: repository has no obvious CycloneDX SBOM/AIBOM inventory artifact", "Publish a CycloneDX SBOM/AIBOM with hashes for model code, configs, and weights.", None, ["provenance", "sbom"]),
    "HFS-034": Rule("HFS-034", "unapproved-publisher", Severity.MEDIUM, "Publisher is not in the configured approved publisher allowlist", "Route this model through manual vendor approval or add the publisher to policy.", "CWE-345", ["vendor", "policy"]),
    "HFS-035": Rule("HFS-035", "missing-provenance-attestation", Severity.INFO, "Remote scan: repository has no obvious SLSA/in-toto provenance attestation", "Publish cryptographically bound provenance metadata for the model release.", None, ["provenance", "attestation"]),
    "HFS-036": Rule("HFS-036", "sbom-hash-mismatch", Severity.HIGH, "SBOM/AIBOM hash does not match the scanned artifact", "Regenerate the SBOM from trusted build output and block this model until the mismatch is explained.", "CWE-345", ["provenance", "sbom", "integrity"]),
    "HFS-037": Rule("HFS-037", "sbom-unverified-artifact", Severity.INFO, "SBOM/AIBOM is present but does not cover a scanned artifact", "Add every executable/config artifact to the SBOM with SHA-256 hashes.", None, ["provenance", "sbom"]),
    "HFS-038": Rule("HFS-038", "signature-verification-failed", Severity.HIGH, "Detached signature artifact could not be verified", "Verify the publisher key identity and reject the model until signature verification passes.", "CWE-347", ["provenance", "signature"]),
    "HFS-039": Rule("HFS-039", "signature-verifier-unavailable", Severity.INFO, "Signature artifact exists but no supported verifier tool is available locally", "Install cosign, gpg, or minisign in CI and rerun verification.", None, ["provenance", "signature"]),
    "HFS-040": Rule("HFS-040", "known-ioc-domain", Severity.HIGH, "Known suspicious IOC domain or dead-drop service referenced", "Remove the endpoint and investigate whether it was used for payload staging or exfiltration.", "CWE-506", ["ioc", "network"]),
    "HFS-041": Rule("HFS-041", "dangerous-dependency", Severity.HIGH, "Dependency is commonly abused in malware, credential theft, or unsafe packaging", "Remove the dependency unless a reviewed and documented security exception exists.", "CWE-506", ["dependency"]),
    "HFS-042": Rule("HFS-042", "vulnerable-dependency-version", Severity.MEDIUM, "Dependency version is below the scanner's conservative minimum safe baseline", "Upgrade the dependency and verify compatibility in CI.", "CWE-1104", ["dependency", "cve"]),
    "HFS-043": Rule("HFS-043", "unpinned-dependency", Severity.LOW, "Dependency is not pinned to an exact version", "Pin dependencies with exact versions or hashes for reproducible builds.", None, ["dependency", "reproducibility"]),
    "HFS-044": Rule("HFS-044", "unsafe-container-directive", Severity.MEDIUM, "Dockerfile contains unsafe root, privileged, curl-pipe-shell, or unpinned base-image behavior", "Harden the container build: pin base image digests, avoid root, and do not pipe remote scripts to shell.", "CWE-250", ["container", "supply-chain"]),
    # --- Pickle Binary Scanning (HFS-050 to HFS-052) ---
    "HFS-050": Rule("HFS-050", "pickle-dangerous-callable", Severity.CRITICAL, "Pickle file contains opcode invoking dangerous callable (os.system, subprocess, exec, eval, etc.)", "Do NOT load this model. The pickle file contains executable code that will run on deserialization. Convert to SafeTensors format from a trusted source.", "CWE-502", ["pickle", "deserialization", "execution"]),
    "HFS-051": Rule("HFS-051", "pickle-suspicious-callable", Severity.HIGH, "Pickle file contains suspicious callable or obfuscated opcode pattern", "Investigate the pickle file contents. Consider converting to SafeTensors. Do not load without sandboxing.", "CWE-502", ["pickle", "deserialization"]),
    "HFS-052": Rule("HFS-052", "pickle-bypass-technique", Severity.CRITICAL, "Pickle file uses known PickleScan bypass technique (corrupted pickle, __reduce_ex__, etc.)", "This file is deliberately crafted to evade security scanners. Block immediately and report to platform.", "CWE-502", ["pickle", "evasion", "bypass"]),
    # --- SafeTensors Validation (HFS-053 to HFS-055) ---
    "HFS-053": Rule("HFS-053", "safetensors-metadata-injection", Severity.HIGH, "SafeTensors metadata contains suspicious content (URLs, scripts, encoded payloads)", "Remove injected content from SafeTensors metadata. Metadata should contain only model documentation.", "CWE-94", ["safetensors", "injection"]),
    "HFS-054": Rule("HFS-054", "safetensors-oversized-header", Severity.MEDIUM, "SafeTensors header or metadata is abnormally large, potentially hiding payloads", "Regenerate the SafeTensors file with minimal metadata. Investigate the oversized content.", "CWE-400", ["safetensors", "anomaly"]),
    "HFS-055": Rule("HFS-055", "safetensors-malformed", Severity.MEDIUM, "SafeTensors file has invalid structure (bad header size, corrupt JSON, truncated data)", "The file is not a valid SafeTensors file. Do not load it. Obtain the model from a verified source.", "CWE-20", ["safetensors", "integrity"]),
    # --- GGUF Inspection (HFS-056 to HFS-058) ---
    "HFS-056": Rule("HFS-056", "gguf-metadata-suspicious", Severity.HIGH, "GGUF metadata key-value contains suspicious content (URLs, scripts, shell commands)", "Remove suspicious metadata entries. GGUF metadata should contain only model configuration.", "CWE-94", ["gguf", "injection"]),
    "HFS-057": Rule("HFS-057", "gguf-metadata-oversized", Severity.MEDIUM, "GGUF metadata entry or count is abnormally large, indicating possible abuse", "Regenerate the GGUF file with standard metadata. Investigate oversized entries.", "CWE-400", ["gguf", "anomaly"]),
    "HFS-058": Rule("HFS-058", "gguf-malformed", Severity.MEDIUM, "GGUF file has invalid magic, unsupported version, or corrupted header", "The file is not a valid GGUF file. Do not load. Obtain from a verified source.", "CWE-20", ["gguf", "integrity"]),
    # --- Weight Fingerprinting (HFS-060) ---
    "HFS-060": Rule("HFS-060", "weight-fingerprint-mismatch", Severity.HIGH, "Model weight tensor hash does not match expected fingerprint (possible weight poisoning)", "Do not deploy this model. Weight tensors have been modified since the trusted baseline was established. Obtain fresh weights from the verified publisher.", "CWE-345", ["integrity", "weights", "poisoning"]),
    # --- Temporal / Rug-Pull Detection (HFS-061 to HFS-063) ---
    "HFS-061": Rule("HFS-061", "temporal-new-critical-finding", Severity.CRITICAL, "New critical/high security finding appeared since the last trusted baseline scan", "Block deployment. The repository has been modified to introduce malicious content after initial trust was established (possible rug-pull attack).", "CWE-506", ["temporal", "rug-pull"]),
    "HFS-062": Rule("HFS-062", "temporal-risk-escalation", Severity.HIGH, "Risk score escalated significantly or security artifacts removed since baseline", "Investigate changes. Security posture degraded since last scan — possible supply chain compromise.", "CWE-345", ["temporal", "regression"]),
    "HFS-063": Rule("HFS-063", "temporal-file-hash-changed", Severity.MEDIUM, "File content changed since baseline (hash mismatch) without corresponding security review", "Review the changed files. Consider re-running a full security audit before deployment.", "CWE-345", ["temporal", "drift"]),
    # --- Advanced Obfuscation (HFS-064 to HFS-067) ---
    "HFS-064": Rule("HFS-064", "unicode-confusable-or-bidi", Severity.HIGH, "Source contains Unicode confusable characters (homoglyphs) or bidirectional override characters", "Remove non-ASCII lookalike characters from identifiers and strings. These are used to disguise malicious code as benign.", "CWE-1007", ["obfuscation", "unicode"]),
    "HFS-065": Rule("HFS-065", "zero-width-characters", Severity.MEDIUM, "Source contains zero-width or invisible Unicode characters that may hide content", "Remove all zero-width characters. They serve no legitimate purpose in source code and can hide malicious strings.", "CWE-1007", ["obfuscation", "unicode"]),
    "HFS-066": Rule("HFS-066", "unicode-escape-payload", Severity.MEDIUM, "Long Unicode escape sequence detected that may encode hidden commands or URLs", "Decode and review the Unicode escape sequences. Replace with readable literals if legitimate.", "CWE-116", ["obfuscation", "encoding"]),
    "HFS-067": Rule("HFS-067", "polyglot-file", Severity.HIGH, "File is valid as multiple formats simultaneously (polyglot), enabling parser confusion attacks", "Replace with a single-format file. Polyglots are used to bypass security tools that only parse one format.", "CWE-436", ["obfuscation", "polyglot"]),
    # --- Internal / Meta ---
    "HFS-070": Rule("HFS-070", "taint-flow-to-sink", Severity.CRITICAL, "Taint analysis: data from untrusted source flows to execution sink (exec, eval, system)", "This code dynamically constructs and executes content. Block deployment.", "CWE-94", ["taint", "dataflow"]),
    "HFS-071": Rule("HFS-071", "symbolic-resolve-dangerous", Severity.CRITICAL, "Symbolically resolved obfuscated string contains dangerous content", "Remove obfuscated string construction. Use explicit readable code.", "CWE-506", ["obfuscation", "symbolic"]),
    "HFS-072": Rule("HFS-072", "sandbox-dangerous-operation", Severity.CRITICAL, "Sandbox execution detected dangerous operation (exec/eval/import of blocked module)", "Code performs dangerous operations at runtime. Block immediately.", "CWE-94", ["sandbox", "dynamic"]),
    "HFS-073": Rule("HFS-073", "onnx-custom-operator", Severity.HIGH, "ONNX model uses custom/non-standard operator that may load native code", "Review custom operator. Custom ops can execute arbitrary native code.", "CWE-94", ["onnx", "custom-op"]),
    "HFS-074": Rule("HFS-074", "onnx-suspicious-content", Severity.HIGH, "ONNX model contains suspicious strings (URLs, shell commands)", "Investigate embedded content. ONNX should not contain executable code.", "CWE-506", ["onnx", "injection"]),
    "HFS-075": Rule("HFS-075", "onnx-malformed-or-oversized", Severity.MEDIUM, "ONNX model has structural anomalies", "Verify model source and regenerate from trusted training.", "CWE-400", ["onnx", "integrity"]),
    "HFS-076": Rule("HFS-076", "keras-unsafe-layer", Severity.CRITICAL, "Keras model contains Lambda layer or embedded executable code", "Remove Lambda layers. They execute arbitrary Python on model load.", "CWE-94", ["keras", "lambda"]),
    "HFS-097": Rule("HFS-097", "card-comparison-unavailable", Severity.INFO, "Model card similarity requires the protected org's card to be downloadable.", "", None, ["internal"]),
    "HFS-098": Rule("HFS-098", "oversized-file-skipped", Severity.INFO, "File exceeded size limits and was skipped.", "", None, ["internal"]),
    "HFS-099": Rule("HFS-099", "unparseable-python", Severity.INFO, "File could not be parsed as valid Python.", "", None, ["internal"]),
}

def get_rule(rule_id: str) -> Rule:
    return RULES[rule_id]



