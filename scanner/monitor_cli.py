"""
CLI for the real-time Hub watchtower.

Separate entry point from the main scanner because watching is a long-running
daemon, not a one-shot scan. Run it under systemd/supervisor in production.

Usage:
    hf-scan-monitor                      # watch the whole Hub, default settings
    hf-scan-monitor --interval 30        # poll every 30s
    hf-scan-monitor --fail-on critical   # only page on critical hits
    hf-scan-monitor --show-all           # print CLEAN/SKIP too, not just hits
    hf-scan-monitor --sandbox            # run the heavy sandbox engine per repo
    hf-scan-monitor --once               # single poll cycle then exit (for cron)
"""

import argparse
import json
import sys

from scanner.monitor import MonitorConfig, watch


def _slack_escalation(webhook_url: str):
    """Return an on_hit callback that posts detections to a Slack/Discord webhook.

    Kept as a closure so the URL is captured once. Failures here must never
    take down the watchtower — a dead Slack webhook is not a reason to stop
    watching the Hub."""
    import urllib.request

    def _notify(report: dict) -> None:
        risk = report.get("risk", {})
        text = (
            f":rotating_light: HF Scanner HIT: `{report.get('repo_id')}` "
            f"risk={risk.get('level')}({risk.get('score')}/100) "
            f"https://huggingface.co/{report.get('repo_id')}"
        )
        body = json.dumps({"text": text}).encode()
        req = urllib.request.Request(
            webhook_url, data=body,
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            urllib.request.urlopen(req, timeout=10)
        except Exception as err:  # noqa: BLE001 - never crash the daemon on notify
            print(f"[monitor] slack notify failed: {err}", file=sys.stderr)

    return _notify


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hf-scan-monitor",
        description="Real-time watchtower: scan newly-published Hugging Face "
                    "models as they appear.")
    p.add_argument("--interval", type=int, default=60,
                   help="seconds between polls of the Hub (default: 60)")
    p.add_argument("--page-size", type=int, default=50,
                   help="how many newest models to pull per poll (default: 50)")
    p.add_argument("--fail-on", default="critical",
                   choices=["critical", "high", "medium", "low"],
                   help="severity that counts as a hit (default: critical — "
                        "Hub-wide watching is noisy at 'high')")
    p.add_argument("--show-all", action="store_true",
                   help="print CLEAN and SKIPPED repos too, not just hits")
    p.add_argument("--sandbox", action="store_true",
                   help="run the sandbox engine on each repo (slower, deeper)")
    p.add_argument("--once", action="store_true",
                   help="run a single poll cycle then exit (for cron jobs)")
    p.add_argument("--token", default=None,
                   help="HF token for higher rate limits / gated repos")
    p.add_argument("--slack-webhook", default=None,
                   help="post hits to this Slack/Discord-compatible webhook URL")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    cfg = MonitorConfig(
        poll_interval_sec=args.interval,
        page_size=args.page_size,
        fail_on=args.fail_on,
        only_flagged=not args.show_all,
        token=args.token,
        sandbox=args.sandbox,
    )
    on_hit = _slack_escalation(args.slack_webhook) if args.slack_webhook else None
    # --once means one cycle (cron-friendly); otherwise run forever.
    watch(cfg, on_hit=on_hit, max_iterations=1 if args.once else None)
    return 0


if __name__ == "__main__":
    sys.exit(main())
