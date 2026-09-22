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
        "Hugging Face repositories — v0.2.0 with binary model analysis",
    )
    parser.add_argument(
        "target", metavar="TARGET", help="Hugging Face repo ID or local directory path"
    )
    parser.add_argument(
        "-m",
        "--mode",
        choices=["local", "remote", "both"],
        default="both",
        help="Scan mode (default: both)",
    )
    parser.add_argument(
        "--revision",
        default="main",
        help="Remote branch, tag, or commit to resolve to an immutable SHA before scanning.",
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "info", "never"],
        default="high",
        help="Exit code 1 if any finding >= this severity (default: high)",
    )
    parser.add_argument(
        "--format",
        choices=["json", "sarif", "text", "html"],
        help="Output format (default: text for TTY, json for pipe)",
    )
    parser.add_argument("--output", metavar="FILE", help="Write report to file instead of stdout")
    parser.add_argument(
        "--config", metavar="FILE", default=".hf-scanner.toml", help="Path to .hf-scanner.toml"
    )
    parser.add_argument(
        "--runtime-policy",
        metavar="FILE",
        help="Write hardened runtime sandbox policy JSON to FILE",
    )
    parser.add_argument(
        "--no-network",
        action="store_true",
        help="Force local mode; fail if target requires network",
    )
    parser.add_argument("--token", help="HF API token (overrides HF_TOKEN env var)")
    parser.add_argument("--verbose", action="store_true", help="Include INFO findings in output")
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Suppress all output except exit code"
    )
    parser.add_argument("--version", action="version", version=f"hf-scanner {SCANNER_VERSION}")
    # New v0.2 flags
    parser.add_argument(
        "--baseline",
        metavar="FILE",
        help="Path to scan baseline JSON for temporal/rug-pull detection",
    )
    parser.add_argument(
        "--save-baseline",
        metavar="FILE",
        help="Save current scan as baseline to FILE for future comparison",
    )
    parser.add_argument(
        "--max-binary-mb",
        type=int,
        default=100,
        help="Max binary model file size in MB (default: 100)",
    )
    parser.add_argument(
        "--skip-binary",
        action="store_true",
        help="Skip binary model scanning (pickle, safetensors, GGUF)",
    )
    parser.add_argument(
        "--sandbox",
        action="store_true",
        help="Enable sandbox execution (instruments and runs code in restricted subprocess)",
    )
    parser.add_argument(
        "--aibom", metavar="FILE", help="Generate CycloneDX AI Bill of Materials to FILE"
    )
    # Runtime protection (v0.3)
    parser.add_argument(
        "--protect",
        action="store_true",
        help="Enable runtime protection checks during monitored execution (blocks on critical findings)",
    )
    parser.add_argument(
        "--protect-config",
        metavar="FILE",
        help="Runtime protection config JSON (egress allowlist, thresholds)",
    )
    parser.add_argument(
        "--protect-daemon",
        action="store_true",
        help="Run as daemon protecting all model processes (requires root)",
    )
    parser.add_argument(
        "--enforce",
        action="store_true",
        help=(
            "Enforce mode: fail on incomplete/indeterminate scans in addition to "
            "severity threshold. Use in CI/CD gates to prevent partial scans from passing."
        ),
    )
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
        print(
            f"Error: Target '{args.target}' is not a local directory, but mode is 'local'",
            file=sys.stderr,
        )
        return 3

    config = load_config(args.config)
    hf_token = args.token or os.environ.get(
        config.get("network", {}).get("hf_token_env", "HF_TOKEN")
    )
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
                result, args.target, client, config, revision=args.revision
            )
            artifacts.update(remote_artifacts)
            sboms.update(remote_sboms)
            all_file_hashes.update(remote_hashes)

        if mode in ["local", "both"]:
            local_artifacts, local_sboms, local_hashes = scan_local(
                result, args.target, config, max_binary_mb=args.max_binary_mb
            )
            artifacts.update(local_artifacts)
            sboms.update(local_sboms)
            all_file_hashes.update(local_hashes)
            result.findings.extend(verify_local_signatures(args.target))

        result.findings.extend(verify_sbom_artifacts(sboms, artifacts))

        # Temporal analysis: compare with baseline if provided
        if args.baseline:
            baseline = load_baseline(args.baseline)
            if baseline:
                temporal_findings = compare_with_baseline(baseline, result, all_file_hashes)
                result.findings.extend(temporal_findings)

        # Sandbox execution (optional — runs Python files in restricted subprocess)
        if getattr(args, "sandbox", False):
            for path, data in artifacts.items():
                if path.lower().endswith(PYTHON_EXTENSIONS):
                    try:
                        source = data.decode("utf-8")
                        sandbox_findings = sandbox_execute(path, source)
                        result.findings.extend(sandbox_findings)
                    except (UnicodeDecodeError, OSError):
                        pass

        # Runtime Protection Mode (v0.3) — Real-time behavioral monitoring
        if getattr(args, "protect", False):
            protect_config = {}
            if args.protect_config: