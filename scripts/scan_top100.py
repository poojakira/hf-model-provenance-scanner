#!/usr/bin/env python3
"""
scan_top100.py - Production-grade scanner for Top 100 Hugging Face models.

Fetches the top 100 most-downloaded models from the HuggingFace API, scans each
using the scanner's url_scanner.scan_hf_url() API, and produces:
  - evidence/top100_scan_results.json  (structured JSON report)
  - evidence/TOP100_SCAN_REPORT.md     (human-readable markdown summary)

Usage:
    python scripts/scan_top100.py [--workers N] [--limit N] [--token HF_TOKEN]
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

# Ensure the project root is on sys.path for scanner imports
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scanner.url_scanner import scan_hf_url  # noqa: E402
from scanner.risk import compute_risk, SEVERITY_POINTS  # noqa: E402
from scanner.models import Severity, ScanResult  # noqa: E402

# ─── Configuration ────────────────────────────────────────────────────────────

HF_API_URL = "https://huggingface.co/api/models?sort=downloads&direction=-1&limit={limit}"
EVIDENCE_DIR = PROJECT_ROOT / "evidence"
JSON_REPORT_PATH = EVIDENCE_DIR / "top100_scan_results.json"
MD_REPORT_PATH = EVIDENCE_DIR / "TOP100_SCAN_REPORT.md"

DEFAULT_WORKERS = 1
DEFAULT_LIMIT = 100
INTER_SCAN_DELAY = 1.5  # seconds between scans to avoid rate-limits

# ─── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("scan_top100")


# ─── Helpers ──────────────────────────────────────────────────────────────────


def fetch_top_models(limit: int = 100) -> list[dict]:
    """Fetch top models list from HuggingFace API."""
    url = HF_API_URL.format(limit=limit)
    log.info(f"Fetching top {limit} models from HuggingFace API...")
    req = urllib.request.Request(
        url, headers={"User-Agent": "hf-scanner/1.0.0 scan_top100"}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310
            data = json.loads(resp.read())
        log.info(f"Successfully fetched {len(data)} models from API")
        return data
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
        log.error(f"Failed to fetch models list: {e}")
        raise


def scan_single_model(
    model_id: str, token: str | None, index: int, total: int
) -> dict:
    """Scan a single model and return a result dict."""
    log.info(f"[{index + 1}/{total}] Scanning: {model_id}")
    start_ms = time.time()

    try:
        result = scan_hf_url(model_id, token=token)
        duration_ms = int((time.time() - start_ms) * 1000)

        # Count findings by severity
        findings_by_severity = {s.value: 0 for s in Severity}
        for f in result.findings:
            findings_by_severity[f.severity.value] += 1

        # Compute a risk score using the scanner's risk module
        # We need a ScanResult to compute risk; build a minimal one
        scan_result = ScanResult(
            scan_target=model_id,
            scan_mode="remote",
            scanner_version="1.0.0",
        )
        scan_result.findings = result.findings
        scan_result.files_scanned = result.files_scanned
        risk = compute_risk(scan_result)

        entry = {
            "model_id": model_id,
            "status": "scanned",
            "risk_score": risk.score,
            "risk_level": risk.level,
            "findings_count": len(result.findings),
            "findings_by_severity": findings_by_severity,
            "scan_duration_ms": duration_ms,
            "bytes_fetched": result.bytes_fetched,
            "files_listed": result.files_listed,
            "files_scanned": result.files_scanned,
            "is_malicious": result.is_malicious,
            "errors": result.errors,
        }

        status_icon = "🔴" if result.is_malicious else "🟢"
        log.info(
            f"  {status_icon} {model_id}: risk={risk.score}/100 ({risk.level}), "
            f"{len(result.findings)} findings, {duration_ms}ms, "
            f"{result.bytes_fetched / 1024:.1f} KB fetched"
        )
        return entry

    except urllib.error.HTTPError as e:
        duration_ms = int((time.time() - start_ms) * 1000)
        log.warning(f"  ⚠️  {model_id}: HTTP {e.code} - skipping")
        return {
            "model_id": model_id,
            "status": f"error_http_{e.code}",
            "risk_score": -1,
            "risk_level": "UNKNOWN",
            "findings_count": 0,
            "findings_by_severity": {s.value: 0 for s in Severity},
            "scan_duration_ms": duration_ms,
            "bytes_fetched": 0,
            "files_listed": 0,
            "files_scanned": 0,
            "is_malicious": False,
            "errors": [f"HTTP {e.code}: {e.reason}"],
        }
    except Exception as e:
        duration_ms = int((time.time() - start_ms) * 1000)
        log.warning(f"  ⚠️  {model_id}: {type(e).__name__}: {e} - skipping")
        return {
            "model_id": model_id,
            "status": "error",
            "risk_score": -1,
            "risk_level": "UNKNOWN",
            "findings_count": 0,
            "findings_by_severity": {s.value: 0 for s in Severity},
            "scan_duration_ms": duration_ms,
            "bytes_fetched": 0,
            "files_listed": 0,
            "files_scanned": 0,
            "is_malicious": False,
            "errors": [str(e)],
        }


def generate_json_report(results: list[dict], scan_start: datetime, scan_end: datetime) -> dict:
    """Build the structured JSON report."""
    successful = [r for r in results if r["status"] == "scanned"]
    failed = [r for r in results if r["status"] != "scanned"]

    # Aggregate severity counts
    total_findings_by_severity = {s.value: 0 for s in Severity}
    for r in successful:
        for sev, count in r["findings_by_severity"].items():
            total_findings_by_severity[sev] += count

    total_findings = sum(total_findings_by_severity.values())

    report = {
        "scan_timestamp": scan_start.isoformat(),
        "scan_completed": scan_end.isoformat(),
        "scan_duration_seconds": round((scan_end - scan_start).total_seconds(), 1),
        "total_models_scanned": len(successful),
        "total_models_failed": len(failed),
        "total_models_attempted": len(results),
        "total_findings": total_findings,
        "total_findings_by_severity": total_findings_by_severity,
        "total_bytes_fetched": sum(r["bytes_fetched"] for r in results),
        "models_flagged_malicious": sum(1 for r in successful if r["is_malicious"]),
        "risk_distribution": {
            "CRITICAL": sum(1 for r in successful if r["risk_level"] == "CRITICAL"),
            "HIGH": sum(1 for r in successful if r["risk_level"] == "HIGH"),
            "MEDIUM": sum(1 for r in successful if r["risk_level"] == "MEDIUM"),
            "LOW": sum(1 for r in successful if r["risk_level"] == "LOW"),
        },
        "per_model_results": results,
    }
    return report


def generate_markdown_report(report: dict) -> str:
    """Generate a human-readable markdown summary."""
    lines = []
    lines.append("# Top 100 HuggingFace Models - Security Scan Report")
    lines.append("")
    lines.append(f"**Scan Date:** {report['scan_timestamp']}")
    lines.append(f"**Duration:** {report['scan_duration_seconds']}s")
    lines.append(f"**Models Scanned:** {report['total_models_scanned']}/{report['total_models_attempted']}")
    lines.append(f"**Total Findings:** {report['total_findings']}")
    lines.append(f"**Total Data Fetched:** {report['total_bytes_fetched'] / (1024 * 1024):.2f} MB")
    lines.append("")

    # Severity summary
    lines.append("## Findings by Severity")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = report["total_findings_by_severity"].get(sev, 0)
        emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(sev, "")
        lines.append(f"| {emoji} {sev.upper()} | {count} |")
    lines.append("")

    # Risk distribution
    lines.append("## Risk Distribution")
    lines.append("")
    lines.append("| Risk Level | Models |")
    lines.append("|------------|--------|")
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = report["risk_distribution"].get(level, 0)
        lines.append(f"| {level} | {count} |")
    lines.append("")

    # Malicious models
    malicious_count = report["models_flagged_malicious"]
    if malicious_count > 0:
        lines.append(f"## ⚠️ Models Flagged as Potentially Malicious: {malicious_count}")
        lines.append("")
        for r in report["per_model_results"]:
            if r.get("is_malicious"):
                lines.append(f"- **{r['model_id']}** (risk: {r['risk_score']}/100)")
        lines.append("")

    # Top findings table (sorted by risk score descending)
    lines.append("## Per-Model Results (sorted by risk)")
    lines.append("")
    lines.append("| # | Model | Risk | Findings | Duration | Data |")
    lines.append("|---|-------|------|----------|----------|------|")

    scanned = [r for r in report["per_model_results"] if r["status"] == "scanned"]
    scanned_sorted = sorted(scanned, key=lambda x: x["risk_score"], reverse=True)

    for i, r in enumerate(scanned_sorted, 1):
        risk_badge = f"{r['risk_score']}/100 ({r['risk_level']})"
        findings = r["findings_count"]
        duration = f"{r['scan_duration_ms']}ms"
        data = f"{r['bytes_fetched'] / 1024:.1f} KB"
        lines.append(f"| {i} | `{r['model_id']}` | {risk_badge} | {findings} | {duration} | {data} |")
    lines.append("")

    # Failed models
    failed = [r for r in report["per_model_results"] if r["status"] != "scanned"]
    if failed:
        lines.append(f"## Skipped/Failed Models ({len(failed)})")
        lines.append("")
        for r in failed:
            errors = "; ".join(r.get("errors", ["unknown"]))
            lines.append(f"- `{r['model_id']}`: {r['status']} — {errors}")
        lines.append("")

    lines.append("---")
    lines.append(f"*Generated by hf-model-provenance-scanner v1.0.0 at {report['scan_timestamp']}*")
    lines.append("")

    return "\n".join(lines)


# ─── Main ─────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description="Scan top 100 HuggingFace models")
    parser.add_argument(
        "--workers", type=int, default=DEFAULT_WORKERS,
        help=f"Number of concurrent workers (default: {DEFAULT_WORKERS})"
    )
    parser.add_argument(
        "--limit", type=int, default=DEFAULT_LIMIT,
        help=f"Number of models to fetch (default: {DEFAULT_LIMIT})"
    )
    parser.add_argument(
        "--token", default=os.environ.get("HF_TOKEN"),
        help="HuggingFace API token (default: $HF_TOKEN)"
    )
    parser.add_argument(
        "--delay", type=float, default=INTER_SCAN_DELAY,
        help=f"Delay between scans in seconds (default: {INTER_SCAN_DELAY})"
    )
    args = parser.parse_args()

    print("=" * 70)
    print("  HF Model Provenance Scanner - Top 100 Batch Scan")
    print("=" * 70)
    print()

    # Ensure evidence directory exists
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

    # Step 1: Fetch top models
    try:
        models = fetch_top_models(args.limit)
    except Exception as e:
        log.critical(f"Cannot proceed without model list: {e}")
        sys.exit(1)

    # Extract model IDs (prefer modelId field, fallback to id)
    model_ids = []
    for m in models:
        mid = m.get("modelId") or m.get("id", "")
        if mid and "/" in mid:  # Must be org/model format
            model_ids.append(mid)
        elif mid:
            # Some models may not have org prefix
            model_ids.append(mid)

    if not model_ids:
        log.critical("No valid model IDs found in API response")
        sys.exit(1)

    total = len(model_ids)
    log.info(f"Starting scan of {total} models with {args.workers} worker(s)")
    log.info(f"Inter-scan delay: {args.delay}s")
    print()

    # Step 2: Scan all models
    scan_start = datetime.now(timezone.utc)
    results: list[dict] = []

    if args.workers <= 1:
        # Sequential scanning (safest for rate limits)
        for i, model_id in enumerate(model_ids):
            result = scan_single_model(model_id, args.token, i, total)
            results.append(result)
            # Delay between scans to avoid rate-limiting
            if i < total - 1:
                time.sleep(args.delay)
    else:
        # Concurrent scanning with controlled parallelism
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {}
            for i, model_id in enumerate(model_ids):
                future = executor.submit(
                    scan_single_model, model_id, args.token, i, total
                )
                futures[future] = model_id
                # Stagger submissions slightly
                time.sleep(args.delay / args.workers)

            for future in as_completed(futures):
                result = future.result()
                results.append(result)

    scan_end = datetime.now(timezone.utc)

    # Step 3: Generate reports
    log.info("Generating reports...")
    report = generate_json_report(results, scan_start, scan_end)

    # Write JSON report
    with open(JSON_REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    log.info(f"JSON report written to: {JSON_REPORT_PATH}")

    # Write Markdown report
    md_content = generate_markdown_report(report)
    with open(MD_REPORT_PATH, "w", encoding="utf-8") as f:
        f.write(md_content)
    log.info(f"Markdown report written to: {MD_REPORT_PATH}")

    # Step 4: Print summary
    print()
    print("=" * 70)
    print("  SCAN COMPLETE - SUMMARY")
    print("=" * 70)
    print(f"  Models scanned:     {report['total_models_scanned']}/{report['total_models_attempted']}")
    print(f"  Models failed:      {report['total_models_failed']}")
    print(f"  Total findings:     {report['total_findings']}")
    print(f"  Flagged malicious:  {report['models_flagged_malicious']}")
    print(f"  Duration:           {report['scan_duration_seconds']}s")
    print(f"  Data fetched:       {report['total_bytes_fetched'] / (1024 * 1024):.2f} MB")
    print()
    print("  Findings by severity:")
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = report["total_findings_by_severity"].get(sev, 0)
        if count > 0:
            print(f"    {sev.upper():>10}: {count}")
    print()
    print("  Risk distribution:")
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = report["risk_distribution"].get(level, 0)
        if count > 0:
            print(f"    {level:>10}: {count} models")
    print()
    print(f"  Reports saved to:")
    print(f"    {JSON_REPORT_PATH}")
    print(f"    {MD_REPORT_PATH}")
    print("=" * 70)


if __name__ == "__main__":
    main()
