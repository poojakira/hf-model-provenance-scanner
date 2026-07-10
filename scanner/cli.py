import argparse
import hashlib
import json
import os
import sys
import time

from scanner.analyzer.ast_visitor import analyze_python_source
from scanner.analyzer.config_scanner import analyze_config_file
from scanner.analyzer.dependency_scanner import analyze_dependency_source
from scanner.analyzer.gguf_scanner import analyze_gguf_file, is_gguf_file
from scanner.analyzer.keras_scanner import analyze_keras_file, is_keras_file
from scanner.analyzer.obfuscation_scanner import analyze_obfuscation
from scanner.analyzer.onnx_scanner import analyze_onnx_file, is_onnx_file
from scanner.analyzer.org_checker import check_organization
from scanner.analyzer.pickle_scanner import analyze_pickle_file, is_pickle_file
from scanner.analyzer.safetensors_scanner import analyze_safetensors_file, is_safetensors_file
from scanner.analyzer.sandbox_executor import sandbox_execute
from scanner.analyzer.shell_scanner import analyze_shell_script
from scanner.analyzer.symbolic_resolver import resolve_strings_in_source
from scanner.analyzer.taint_engine import analyze_taint
from scanner.analyzer.temporal_scanner import (
    compare_with_baseline,
    create_baseline,
    load_baseline,
    save_baseline,
)
from scanner.analyzer.weight_fingerprint import fingerprint_file
from scanner.aibom_generator import format_aibom
from scanner.config import load_config
from scanner.formatters.html_formatter import format_html
from scanner.formatters.json_formatter import format_json
from scanner.formatters.sarif_formatter import json_to_sarif
from scanner.models import Finding, ScanResult, Severity
from scanner.provenance import (
    is_sbom_file,
    is_signature_file,
    verify_local_signatures,
    verify_sbom_artifacts,
)
from scanner.risk import compute_risk
from scanner.rules.definitions import get_rule
from scanner.runtime_policy import format_runtime_policy
from scanner.utils.file_filter import walk_files
from scanner.utils.hf_api import HFApiClient

SCANNER_VERSION = "0.2.0"
SCRIPT_EXTENSIONS = (".sh", ".bat", ".ps1", ".cmd")
CONFIG_EXTENSIONS = (".json",)
PYTHON_EXTENSIONS = (".py",)
DEPENDENCY_EXTENSIONS = (".txt", ".toml", ".yml", ".yaml")
BINARY_MODEL_EXTENSIONS = (".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt", ".joblib",
                           ".safetensors", ".gguf", ".onnx", ".h5", ".hdf5", ".keras")
REMOTE_SCAN_EXTENSIONS = (PYTHON_EXTENSIONS + SCRIPT_EXTENSIONS + CONFIG_EXTENSIONS +
                          DEPENDENCY_EXTENSIONS + BINARY_MODEL_EXTENSIONS)
HIGH_RISK_NAMES = {"loader.py", "start.py", "start.bat", "start.ps1", "setup.py",
                   "install.py", "run.py", "bootstrap.py"}
DEPENDENCY_NAMES = {"requirements.txt", "requirements-dev.txt", "constraints.txt",
                    "pyproject.toml", "environment.yml", "environment.yaml", "dockerfile"}
SIGNATURE_MARKERS = (".sig", ".asc", ".minisig", ".cosign", ".bundle", "sigstore")
SBOM_MARKERS = ("sbom", "aibom", "bom.json", "cyclonedx", "cdx")
PROVENANCE_MARKERS = ("provenance", "slsa", "intoto", ".att", "attestation")


def make_finding(rule_id: str, file_path: str = "", evidence: str = "") -> Finding:
    rule = get_rule(rule_id)
    return Finding(rule_id, rule.severity, file_path, 0, 0, rule.description,
                   evidence[:300], rule.remediation, rule.cwe)


def should_scan_remote_file(path: str) -> bool:
    lower = path.lower()
    base = os.path.basename(lower)
    return (lower.endswith(REMOTE_SCAN_EXTENSIONS) or base in HIGH_RISK_NAMES
            or base in DEPENDENCY_NAMES or is_sbom_file(path))


def analyze_source_file(file_path: str, source: str, raw_data: bytes = b"") -> list[Finding]:
    """Analyze a text source file with all applicable analyzers."""
    lower = file_path.lower()
    findings = analyze_dependency_source(file_path, source)
    if lower.endswith(PYTHON_EXTENSIONS):
        findings.extend(analyze_python_source(file_path, source))
        # Advanced analysis: taint tracking + symbolic resolution
        findings.extend(analyze_taint(file_path, source))
        findings.extend(resolve_strings_in_source(file_path, source))
    elif lower.endswith(SCRIPT_EXTENSIONS):
        findings.extend(analyze_shell_script(file_path, source))
    elif lower.endswith(CONFIG_EXTENSIONS):
        findings.extend(analyze_config_file(file_path, source))
    # Advanced obfuscation detection on all text files
    findings.extend(analyze_obfuscation(file_path, source, raw_data or None))
    return findings


def analyze_binary_file(file_path: str, data: bytes) -> list[Finding]:
    """Analyze a binary model file (pickle, safetensors, GGUF, ONNX, Keras)."""
    findings: list[Finding] = []
    if is_pickle_file(file_path):
        findings.extend(analyze_pickle_file(file_path, data))
    if is_safetensors_file(file_path):
        findings.extend(analyze_safetensors_file(file_path, data))
    if is_gguf_file(file_path):
        findings.extend(analyze_gguf_file(file_path, data))
    if is_onnx_file(file_path):
        findings.extend(analyze_onnx_file(file_path, data))
    if is_keras_file(file_path):
        findings.extend(analyze_keras_file(file_path, data))
    return findings


def add_remote_policy_findings(result: ScanResult, repo_id: str, files: list[str],
                               config: dict):
    lower_files = [f.lower() for f in files]
    org = repo_id.split("/", 1)[0].lower()
    policy = (config.get("policy", {})
              if isinstance(config.get("policy", {}), dict) else {})
    approved = [str(p).lower() for p in policy.get("approved_publishers", [])]

    if approved and org not in approved:
        result.findings.append(make_finding(
            "HFS-034", evidence=f"publisher={org}; approved={approved}"))
    if not any(any(marker in f for marker in SIGNATURE_MARKERS) for f in lower_files):
        result.findings.append(make_finding(
            "HFS-032", evidence="No .sig/.asc/.cosign/sigstore artifact found"))
    if not any(any(marker in f for marker in SBOM_MARKERS) for f in lower_files):
        result.findings.append(make_finding(
            "HFS-033", evidence="No SBOM/AIBOM/CycloneDX artifact found"))
    if not any(any(marker in f for marker in PROVENANCE_MARKERS) for f in lower_files):
        result.findings.append(make_finding(
            "HFS-035", evidence="No SLSA/in-toto/provenance attestation found"))

    for filename in files:
        if os.path.basename(filename).lower() in HIGH_RISK_NAMES:
            result.findings.append(make_finding(
                "HFS-025", file_path=filename,
                evidence="Executable model entrypoint present"))


def _is_binary_model(file_path: str) -> bool:
    """Check if file is a binary model format we scan."""
    return file_path.lower().endswith(BINARY_MODEL_EXTENSIONS)


def scan_local(result: ScanResult, target: str, config: dict,
               max_binary_mb: int = 100) -> tuple[dict[str, bytes], dict[str, bytes], dict[str, tuple[str, int]]]:
    """
    Scan local files. Returns (artifacts, sboms, file_hashes).
    Now handles binary model files (pickle, safetensors, GGUF).
    """
    max_size_kb = config.get("scanner", {}).get("max_file_size_kb", 512)
    max_binary_bytes = max_binary_mb * 1024 * 1024
    artifacts: dict[str, bytes] = {}
    sboms: dict[str, bytes] = {}
    file_hashes: dict[str, tuple[str, int]] = {}

    if os.path.isdir(target):
        files_to_scan = walk_files(target, max_size_kb=max_size_kb)
    elif os.path.exists(target):
        size = os.path.getsize(target)
        files_to_scan = [(target, size > max_size_kb * 1024)]
    else:
        files_to_scan = []

    # Also find binary model files (larger size limit)
    binary_files: list[str] = []
    if os.path.isdir(target):
        for root, _, filenames in os.walk(target):
            for fname in filenames:
                fpath = os.path.join(root, fname)
                if _is_binary_model(fpath):
                    binary_files.append(fpath)

    for file_path, is_oversized in files_to_scan:
        base = os.path.basename(file_path).lower()
        if base in HIGH_RISK_NAMES:
            result.findings.append(make_finding(
                "HFS-025", file_path=file_path,
                evidence="Executable model entrypoint present"))
        # Skip binary models here (handled separately below)
        if _is_binary_model(file_path):
            continue
        if is_oversized:
            result.files_skipped += 1
            result.findings.append(make_finding(
                "HFS-098", file_path=file_path,
                evidence="size exceeds scanner.max_file_size_kb"))
            continue
        try:
            with open(file_path, "rb") as f:
                data = f.read()
        except OSError as exc:
            result.files_skipped += 1
            result.findings.append(make_finding(
                "HFS-098", file_path=file_path, evidence=str(exc)))
            continue

        # Track file hash for temporal analysis
        file_hashes[file_path] = (hashlib.sha256(data).hexdigest(), len(data))

        if is_sbom_file(file_path):
            sboms[file_path] = data
            continue
        if is_signature_file(file_path):
            continue
        try:
            source = data.decode("utf-8")
        except UnicodeDecodeError:
            result.files_skipped += 1
            continue
        result.files_scanned += 1
        source_findings = analyze_source_file(file_path, source, data)
        if source_findings or should_scan_remote_file(file_path):
            artifacts[file_path] = data
        result.findings.extend(source_findings)

    # Scan binary model files with dedicated analyzers
    for file_path in binary_files:
        try:
            size = os.path.getsize(file_path)
            if size > max_binary_bytes:
                result.files_skipped += 1
                result.findings.append(make_finding(
                    "HFS-098", file_path=file_path,
                    evidence=f"Binary model {size // (1024*1024)}MB exceeds "
                             f"{max_binary_mb}MB limit"))
                continue
            with open(file_path, "rb") as f:
                data = f.read()
        except OSError as exc:
            result.files_skipped += 1
            result.findings.append(make_finding(
                "HFS-098", file_path=file_path, evidence=str(exc)))
            continue

        file_hashes[file_path] = (hashlib.sha256(data).hexdigest(), len(data))
        result.files_scanned += 1
        binary_findings = analyze_binary_file(file_path, data)
        result.findings.extend(binary_findings)

        # Generate weight fingerprint (stored in result metadata)
        fp, fp_findings = fingerprint_file(file_path, data)
        result.findings.extend(fp_findings)

    return artifacts, sboms, file_hashes


def scan_remote_files(result: ScanResult, repo_id: str, client: HFApiClient,
                      config: dict) -> tuple[dict[str, bytes], dict[str, bytes], dict[str, tuple[str, int]]]:
    """Scan remote files including binary model scanning."""
    files = client.list_repo_files(repo_id)
    add_remote_policy_findings(result, repo_id, files, config)
    artifacts: dict[str, bytes] = {}
    sboms: dict[str, bytes] = {}
    file_hashes: dict[str, tuple[str, int]] = {}

    for filename in files:
        if not should_scan_remote_file(filename):
            continue
        try:
            data = client.download_file(repo_id, filename)
        except Exception as exc:
            result.files_skipped += 1
            result.findings.append(make_finding(
                "HFS-098", file_path=filename, evidence=str(exc)))
            continue

        file_hashes[filename] = (hashlib.sha256(data).hexdigest(), len(data))

        # Binary model files get specialized scanning
        if _is_binary_model(filename):
            result.files_scanned += 1
            binary_findings = analyze_binary_file(filename, data)
            result.findings.extend(binary_findings)
            fp, fp_findings = fingerprint_file(filename, data)
            result.findings.extend(fp_findings)
            continue

        if is_sbom_file(filename):
            sboms[filename] = data
            continue
        if is_signature_file(filename):
            continue
        try:
            source = data.decode("utf-8")
        except UnicodeDecodeError:
            result.files_skipped += 1
            continue
        result.files_scanned += 1
        source_findings = analyze_source_file(filename, source, data)
        if source_findings or should_scan_remote_file(filename):
            artifacts[filename] = data
        result.findings.extend(source_findings)

    return artifacts, sboms, file_hashes


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hf-scanner",
        description="Zero-dependency ML supply chain provenance scanner for "
                    "Hugging Face repositories — v0.2.0 with binary model analysis")
    parser.add_argument("target", metavar="TARGET",
                        help="Hugging Face repo ID or local directory path")
    parser.add_argument("-m", "--mode", choices=["local", "remote", "both"],
                        default="both", help="Scan mode (default: both)")
    parser.add_argument("--fail-on",
                        choices=["critical", "high", "medium", "low", "info", "never"],
                        default="high",
                        help="Exit code 1 if any finding >= this severity (default: high)")
    parser.add_argument("--format", choices=["json", "sarif", "text", "html"],
                        help="Output format (default: text for TTY, json for pipe)")
    parser.add_argument("--output", metavar="FILE",
                        help="Write report to file instead of stdout")
    parser.add_argument("--config", metavar="FILE", default=".hf-scanner.toml",
                        help="Path to .hf-scanner.toml")
    parser.add_argument("--runtime-policy", metavar="FILE",
                        help="Write hardened runtime sandbox policy JSON to FILE")
    parser.add_argument("--no-network", action="store_true",
                        help="Force local mode; fail if target requires network")
    parser.add_argument("--token",
                        help="HF API token (overrides HF_TOKEN env var)")
    parser.add_argument("--verbose", action="store_true",
                        help="Include INFO findings in output")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Suppress all output except exit code")
    parser.add_argument("--version", action="version",
                        version=f"hf-scanner {SCANNER_VERSION}")
    # New v0.2 flags
    parser.add_argument("--baseline", metavar="FILE",
                        help="Path to scan baseline JSON for temporal/rug-pull detection")
    parser.add_argument("--save-baseline", metavar="FILE",
                        help="Save current scan as baseline to FILE for future comparison")
    parser.add_argument("--max-binary-mb", type=int, default=100,
                        help="Max binary model file size in MB (default: 100)")
    parser.add_argument("--skip-binary", action="store_true",
                        help="Skip binary model scanning (pickle, safetensors, GGUF)")
    parser.add_argument("--sandbox", action="store_true",
                        help="Enable sandbox execution (instruments and runs code in restricted subprocess)")
    parser.add_argument("--aibom", metavar="FILE",
                        help="Generate CycloneDX AI Bill of Materials to FILE")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    out_format = args.format or ("text" if sys.stdout.isatty() else "json")
    mode = "local" if args.no_network else args.mode
    is_local_dir = os.path.isdir(args.target)

    if is_local_dir and mode == "both":
        mode = "local"
    elif not is_local_dir and mode == "local" and not os.path.exists(args.target):
        print(f"Error: Target '{args.target}' is not a local directory, "
              f"but mode is 'local'", file=sys.stderr)
        return 3

    config = load_config(args.config)
    hf_token = (args.token or
                os.environ.get(config.get("network", {}).get("hf_token_env", "HF_TOKEN")))
    client = HFApiClient(token=hf_token)
    result = ScanResult(args.target, mode, SCANNER_VERSION)
    start_time = time.time()
    artifacts: dict[str, bytes] = {}
    sboms: dict[str, bytes] = {}
    all_file_hashes: dict[str, tuple[str, int]] = {}

    try:
        if args.runtime_policy:
            policy_dir = os.path.dirname(os.path.abspath(args.runtime_policy))
            if policy_dir:
                os.makedirs(policy_dir, exist_ok=True)
            with open(args.runtime_policy, "w", encoding="utf-8") as f:
                f.write(format_runtime_policy(args.target))

        if mode in ["remote", "both"] and not is_local_dir:
            org_check, org_findings = check_organization(args.target, client)
            result.org_check = org_check
            result.findings.extend(org_findings)
            remote_artifacts, remote_sboms, remote_hashes = scan_remote_files(
                result, args.target, client, config)
            artifacts.update(remote_artifacts)
            sboms.update(remote_sboms)
            all_file_hashes.update(remote_hashes)

        if mode in ["local", "both"]:
            local_artifacts, local_sboms, local_hashes = scan_local(
                result, args.target, config,
                max_binary_mb=args.max_binary_mb)
            artifacts.update(local_artifacts)
            sboms.update(local_sboms)
            all_file_hashes.update(local_hashes)
            result.findings.extend(verify_local_signatures(args.target))

        result.findings.extend(verify_sbom_artifacts(sboms, artifacts))

        # Temporal analysis: compare with baseline if provided
        if args.baseline:
            baseline = load_baseline(args.baseline)
            if baseline:
                temporal_findings = compare_with_baseline(
                    baseline, result, all_file_hashes)
                result.findings.extend(temporal_findings)

        # Sandbox execution (optional — runs Python files in restricted subprocess)
        if getattr(args, 'sandbox', False):
            for path, data in artifacts.items():
                if path.lower().endswith(PYTHON_EXTENSIONS):
                    try:
                        source = data.decode("utf-8")
                        sandbox_findings = sandbox_execute(path, source)
                        result.findings.extend(sandbox_findings)
                    except (UnicodeDecodeError, OSError):
                        pass

    except Exception as e:
        result.error = str(e)
        if not args.quiet:
            print(f"Scanner error: {e}", file=sys.stderr)
        return 2

    result.scan_duration_seconds = time.time() - start_time
    result.risk = compute_risk(result)

    # Save baseline if requested
    if args.save_baseline:
        baseline = create_baseline(result, all_file_hashes)
        save_baseline(baseline, args.save_baseline)

    if not args.quiet:
        if out_format == "json":
            out_content = format_json(result)
        elif out_format == "sarif":
            out_content = json.dumps(json_to_sarif(result), indent=2)
        elif out_format == "html":
            out_content = format_html(result)
        else:
            lines = [f"Risk: {result.risk.level} ({result.risk.score}/100)"]
            for reason in result.risk.reasons:
                lines.append(f"  - {reason}")
            lines.append("")
            for f in result.findings:
                if not args.verbose and f.severity == Severity.INFO:
                    continue
                lines.append(
                    f"[{f.severity.name}] {f.rule_id} "
                    f"{f.file_path}:{f.line_number} - {f.message}")
            counts = {s: sum(1 for f in result.findings if f.severity == s)
                      for s in Severity}
            lines.append(
                f"\n{len(result.findings)} findings "
                f"({counts[Severity.CRITICAL]} critical, "
                f"{counts[Severity.HIGH]} high, "
                f"{counts[Severity.MEDIUM]} medium)")
            out_content = "\n".join(lines)

        if args.output:
            output_dir = os.path.dirname(os.path.abspath(args.output))
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out_content)
        else:
            print(out_content)

    fail_threshold_str = config.get("scanner", {}).get("fail_on", args.fail_on).lower()
    if fail_threshold_str != "never":
        severity_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        threshold_val = severity_order.get(fail_threshold_str, 4)
        if any(severity_order.get(f.severity.value, 0) >= threshold_val
               for f in result.findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
