"""
Real-time Hub monitor — a watchtower over newly-published Hugging Face models.

This is the "real-time on real data" piece. Instead of waiting for someone to
point the scanner at a repo, this polls the live Hugging Face API for models
that were JUST created, and scans each one the moment it appears.

Two ways to run it:
  1. Poll mode (default) — no HF cooperation needed. We hit the public
     /api/models endpoint sorted by creation time, diff against what we've
     already seen, and scan the new arrivals. This is how an independent
     researcher would watch the whole Hub.
  2. Webhook mode — see integrations/huggingface_webhook.py. That's push-based
     and lower latency, but the org has to configure the webhook to point at us.

Why polling and not just webhooks: webhooks only fire for repos WE own or are
subscribed to. To watch the entire Hub for typosquats of openai/meta/etc, we
have to pull the firehose ourselves. HF rate-limits but the createdAt sort is
cheap.

Zero dependencies — urllib only, same as the rest of the tool.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Optional

# We reuse the real scanner rather than reimplementing detection here.
from scanner.cli import main as run_scan

HF_API = "https://huggingface.co/api/models"
# Where we remember which repos we've already looked at, so a restart doesn't
# rescan the whole page. Kept tiny and local on purpose.
STATE_FILE = os.environ.get(
    "HF_SCANNER_MONITOR_STATE",
    os.path.join(os.path.expanduser("~"), ".cache", "hf-scanner", "seen_repos.json"),
)


@dataclass
class MonitorConfig:
    """Knobs for the watchtower. Defaults are deliberately conservative so we
    don't hammer the HF API and get throttled."""
    poll_interval_sec: int = 60          # how often we ask HF "what's new?"
    page_size: int = 50                  # models per API page
    # Hub-wide watching defaults to 'critical' on purpose. At 'high' a single
    # `except: pass` on some stranger's legit training repo pages the operator,
    # and the Hub produces thousands of those an hour. A CI gate on YOUR OWN
    # repo should use 'high' (you want clean code); a firehose watchtower over
    # everyone else's repos should only fire on actual malware. Learned this the
    # noisy way — see LinuxAdi143/Yt_shorts, a legit repo that tripped 'high'.
    fail_on: str = "critical"            # severity that counts as a real hit
    only_flagged: bool = True            # print clean repos too, or just hits?
    max_seen_memory: int = 5000          # cap the dedupe set so it can't grow forever
    token: Optional[str] = None          # HF token for higher rate limits
    sandbox: bool = False                # run the heavier sandbox engine per repo


def _load_seen() -> set:
    """Pull the set of repo ids we've already scanned off disk.

    We keep this so restarting the monitor at 3am doesn't re-flag every model
    that was already cleared yesterday. Corrupt/missing file just means we
    start fresh — not worth crashing over."""
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as fh:
            return set(json.load(fh))
    except (OSError, json.JSONDecodeError, ValueError):
        return set()


def _save_seen(seen: set, cap: int) -> None:
    """Persist the dedupe set, trimmed to the last `cap` ids.

    The trim matters: on a busy day the Hub gets thousands of new repos and we
    don't want this file growing without bound. We keep the most-recently-added
    ids (dicts preserve insertion order, sets don't, so we just slice a list)."""
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    trimmed = list(seen)[-cap:]
    tmp = STATE_FILE + ".tmp"
    # Write-then-rename so a crash mid-write can't corrupt the real file.
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(trimmed, fh)
    os.replace(tmp, STATE_FILE)


def fetch_newest(cfg: MonitorConfig) -> list[str]:
    """Ask HF for the most recently created models. Returns repo ids, newest first.

    We sort by createdAt descending because that's the firehose of brand-new
    repos — exactly where a typosquat attack shows up first. A transient network
    blip returns an empty list rather than throwing; the caller just tries again
    next tick."""
    url = f"{HF_API}?sort=createdAt&direction=-1&limit={cfg.page_size}"
    headers = {"User-Agent": "hf-scanner-monitor/0.2.0"}
    if cfg.token:
        headers["Authorization"] = f"Bearer {cfg.token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            payload = json.loads(resp.read())
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as err:
        # Don't die on a hiccup — a monitor that crashes on the first 503 is
        # useless. Log to stderr and let the loop retry.
        print(f"[monitor] fetch failed: {err}", file=sys.stderr)
        return []
    return [m["id"] for m in payload if isinstance(m, dict) and "id" in m]


def scan_one(repo_id: str, cfg: MonitorConfig) -> dict:
    """Run the real scanner against a single live repo and return its JSON verdict.

    We shell into the same CLI everything else uses instead of importing internals,
    so the monitor can never drift out of sync with what a manual scan would report.
    stdout is captured because the CLI prints the JSON report there."""
    import io
    from contextlib import redirect_stdout, redirect_stderr

    argv = [repo_id, "--mode", "remote", "--format", "json", "--fail-on", cfg.fail_on]
    if cfg.token:
        argv += ["--token", cfg.token]
    if cfg.sandbox:
        argv.append("--sandbox")

    buf = io.StringIO()
    err_buf = io.StringIO()  # swallow the CLI's expected 404/401 noise on empty repos
    exit_code = 0
    try:
        # redirect_stderr too: a half-created repo makes the CLI print
        # "Scanner error: HTTP 404" which is normal Hub churn, not something
        # the operator needs to see for every empty training-run repo.
        with redirect_stdout(buf), redirect_stderr(err_buf):
            exit_code = run_scan(argv)
    except SystemExit as e:
        # argparse or the CLI may call sys.exit; treat its code as the verdict.
        exit_code = int(e.code) if e.code is not None else 0
    except Exception as err:
        # A single malformed repo must not take down the whole watchtower.
        return {"repo_id": repo_id, "error": str(err), "exit_code": 2}

    try:
        report = json.loads(buf.getvalue())
    except json.JSONDecodeError:
        report = {"repo_id": repo_id, "error": "unparseable scan output"}
    report["exit_code"] = exit_code
    report["repo_id"] = repo_id
    return report


def classify(report: dict) -> str:
    """Bucket a scan report into HIT / CLEAN / SKIPPED.

    Real Hub traffic is mostly noise: half-created repos with no README (404),
    gated/private repos we can't read (401), training-run junk. A production
    monitor has to tell those apart from an actual clean pass and an actual hit,
    otherwise the operator drowns. SKIPPED means 'we genuinely couldn't assess
    this', which is different from 'we assessed it and it's fine'."""
    if report.get("exit_code") == 1:
        return "HIT"
    if report.get("error") or "risk" not in report:
        return "SKIPPED"
    return "CLEAN"


def _format_line(report: dict) -> str:
    """Turn a scan report into a one-line, glance-able status for the operator."""
    status = classify(report)
    repo_id = report.get("repo_id", "?")
    ts = time.strftime("%H:%M:%S")

    if status == "SKIPPED":
        # Say WHY we skipped so the operator knows it wasn't a silent failure.
        reason = report.get("error", "no readable content (empty/gated repo)")
        return f"[{ts}] SKIP  {repo_id} — {reason[:60]}"

    risk = report.get("risk", {})
    findings = report.get("findings", [])
    crit = sum(1 for f in findings if f.get("severity") == "critical")
    high = sum(1 for f in findings if f.get("severity") == "high")
    return (
        f"[{ts}] {status:<5} {repo_id} — "
        f"risk={risk.get('level','?')}({risk.get('score',0)}/100) "
        f"crit={crit} high={high} "
        f"https://huggingface.co/{repo_id}"
    )


def watch(cfg: MonitorConfig, on_hit: Optional[Callable[[dict], None]] = None,
          max_iterations: Optional[int] = None) -> None:
    """Main loop: poll the Hub, scan new arrivals, alert on hits, repeat.

    `max_iterations` exists so tests (and demos) can run a bounded number of
    cycles instead of blocking forever. In production you leave it None and
    run it under systemd/supervisor.

    `on_hit` is the escalation hook — wire it to Slack, PagerDuty, an abuse
    report, whatever. If it's None we just print."""
    seen = _load_seen()
    print(f"[monitor] watchtower up. {len(seen)} repos already known. "
          f"polling every {cfg.poll_interval_sec}s, fail-on={cfg.fail_on}",
          file=sys.stderr)

    loops = 0
    while max_iterations is None or loops < max_iterations:
        loops += 1
        newest = fetch_newest(cfg)
        # Only look at repos we haven't cleared before. This is the whole point
        # of the seen-set: on a quiet minute there may be zero new repos and we
        # do no scanning work at all.
        fresh = [r for r in newest if r not in seen]

        for repo_id in fresh:
            seen.add(repo_id)
            report = scan_one(repo_id, cfg)
            status = classify(report)
            if status == "HIT":
                # A real detection — always surface it and fire the escalation hook.
                print(_format_line(report))
                if on_hit:
                    on_hit(report)
            elif not cfg.only_flagged:
                # Verbose mode: show CLEAN and SKIPPED too so the operator can
                # confirm the watchtower is actually working, not just silent.
                print(_format_line(report))

        if fresh:
            _save_seen(seen, cfg.max_seen_memory)

        if max_iterations is None or loops < max_iterations:
            time.sleep(cfg.poll_interval_sec)


def _build_config_from_env() -> MonitorConfig:
    """Read config from env vars so the daemon can be configured without code."""
    return MonitorConfig(
        poll_interval_sec=int(os.environ.get("HF_SCANNER_POLL_SEC", "60")),
        page_size=int(os.environ.get("HF_SCANNER_PAGE_SIZE", "50")),
        fail_on=os.environ.get("HF_SCANNER_FAIL_ON", "critical"),
        only_flagged=os.environ.get("HF_SCANNER_ONLY_FLAGGED", "1") != "0",
        token=os.environ.get("HF_TOKEN"),
        sandbox=os.environ.get("HF_SCANNER_SANDBOX", "0") == "1",
    )


if __name__ == "__main__":
    watch(_build_config_from_env())
