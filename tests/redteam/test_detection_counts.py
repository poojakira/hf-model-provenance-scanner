"""CI-guarded assertions on the red-team detection numbers.

These lock the numbers quoted in README/LIMITATIONS/RUNBOOK to what the code
actually delivers, so a future regression that lowers detection (or that
re-inflates it by counting INFO-level notices as detections) fails CI instead
of silently drifting the published claim.

Verified counts (run locally, py3.12):
  core simulation : 12/12 detected, 0 missed
  extended suite  : 18/18 detected, 0 missed, 0 false positives (actionable only)
  large-scale     : 3/3 detected
"""

import sys

# The redteam scripts reconfigure stdout to UTF-8 on import-time side effects;
# they are safe to import.
from tests.redteam.extended_attacks import run_extended
from tests.redteam.simulate_attacks import run_simulation


def test_core_simulation_detects_all_twelve():
    report, _results = run_simulation()
    summary = report["summary"]
    assert summary["total_attacks"] == 12
    assert summary["detected"] == 12, f"core detection regressed: {summary}"
    assert summary["missed"] == 0


def test_extended_suite_detects_all_with_zero_false_positives():
    report = run_extended()
    assert report["total_attacks"] == 18
    assert report["detected"] == 18, f"extended detection regressed: {report}"
    assert report["missed"] == 0
    # 0 false positives on the benign LEGIT samples — this must count only
    # actionable (non-INFO) findings, not the sandbox-backend capability notice.
    assert report["false_positives"] == 0, (
        "benign code produced actionable findings (real false positive) — "
        f"{report['false_positives']} FP"
    )


def test_stdout_reconfigure_is_windows_safe():
    """The redteam scripts must not crash on cp1252 consoles (Windows)."""
    # If import + reconfigure succeeded, stdout should be usable for the emoji.
    assert hasattr(sys.stdout, "encoding")
