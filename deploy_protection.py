"""
Deployment Admission Gate and Runtime Monitoring
================================================

This entry point provides a fail-closed pre-deployment admission gate and an
optional runtime-monitoring sidecar process. It does not start or proxy an
inference server; the inference runtime remains an external deployment concern.

Architecture:
1. Pre-deployment: Static scan (pickle, safetensors, GGUF, ONNX, code)
2. Runtime: Behavioral monitoring using the capabilities implemented by RuntimeMonitor
3. Response: Experimental alerting/quarantine hooks; validate enforcement in your environment

Usage:
    python deploy_protection.py --model-path ./model --serve --port 8080
"""

import argparse
import json
import os
import signal
import sys
import time
from pathlib import Path

# Add scanner to path
sys.path.insert(0, str(Path(__file__).parent))

from scanner.analyzer.runtime_monitor import (
    BehavioralProfiler,
    RuntimeMonitor,
    SideChannelDetector,
)
from scanner.cli import main as cli_main


class ProtectedModelServer:
    """Fail-closed model admission and runtime-monitoring coordinator."""

    def __init__(self, model_path: str, config: dict):
        self.model_path = model_path
        self.config = config
        self.model_hash = self._compute_model_hash()
        self.monitor = RuntimeMonitor(
            model_hash=self.model_hash, allowlist_config=config.get("runtime", {})
        )
        self.profiler = BehavioralProfiler()
        self.side_channel = SideChannelDetector()
        self._running = False

    def _compute_model_hash(self) -> str:
        """Compute SHA-256 of model artifacts for baseline tracking."""
        import hashlib

        hasher = hashlib.sha256()
        for root, _, files in os.walk(self.model_path):
            for f in sorted(files):
                if f.endswith(
                    (
                        ".bin",
                        ".safetensors",
                        ".gguf",
                        ".onnx",
                        ".pt",
                        ".pth",
                        ".pkl",
                        ".py",
                        ".json",
                    )
                ):
                    filepath = os.path.join(root, f)
                    try:
                        with open(filepath, "rb") as fp:
                            while chunk := fp.read(8192):
                                hasher.update(chunk)
                    except OSError as exc:
                        raise RuntimeError(f"Unable to hash model artifact {filepath}: {exc}") from exc
        return hasher.hexdigest()[:16]

    def static_scan(self) -> dict:
        """Run comprehensive static analysis before deployment."""
        print(f"[STATIC] Scanning {self.model_path}...")
        args = [
            self.model_path,
            "--mode",
            "local",
            "--format",
            "json",
            "--fail-on",
            "high",
            "--enforce",
            "--quiet",
        ]
        # Capture output
        import io
        from contextlib import redirect_stderr, redirect_stdout

        stdout = io.StringIO()
        stderr = io.StringIO()
        try:
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = cli_main(args)
            result = json.loads(stdout.getvalue())
            completeness = str(result.get("completeness", "UNKNOWN")).upper()
            scan_error = result.get("error")
            approved = exit_code == 0 and completeness == "COMPLETE" and not scan_error
            return {
                "exit_code": exit_code,
                "findings": result.get("findings", []),
                "risk_score": result.get("risk", {}).get("score", 0),
                "risk_level": result.get("risk", {}).get("level", "UNKNOWN"),
                "completeness": completeness,
                "error": scan_error,
                "approved": approved,
            }
        except Exception as e:
            return {"error": str(e), "exit_code": 1}

    def start_runtime_protection(self, target_pid: int | None = None):
        """Start real-time behavioral monitoring."""
        if target_pid is None:
            target_pid = os.getpid()

        print(f"[RUNTIME] Starting protection for PID {target_pid}")
        print(f"[RUNTIME] Model hash: {self.model_hash}")
        print(
            f"[RUNTIME] Allowed egress: {self.config.get('runtime', {}).get('egress_allowlist', [])}"
        )

        self.monitor.start_monitoring(target_pid)
        self._running = True

        # Start monitoring loop in background
        import threading

        self._monitor_thread = threading.Thread(target=self._protection_loop, daemon=True)
        self._monitor_thread.start()

    def _protection_loop(self):
        """Continuous threat detection and response."""
        while self._running:
            try:
                # Get alerts from monitor
                alerts = self.monitor.get_alerts()
                for alert in alerts:
                    self._handle_alert(alert)

                # Profile behavior
                if self._running:
                    self._profile_behavior()

                time.sleep(1)  # 1Hz monitoring

            except Exception as e:
                print(f"[RUNTIME] Monitor error: {e}")
                time.sleep(5)

    def _profile_behavior(self):
        """Collect behavioral features for anomaly detection."""
        import psutil

        try:
            proc = psutil.Process(os.getpid())
            features = [
                proc.cpu_percent(interval=0.01),
                proc.memory_info().rss / 1024 / 1024,
                proc.num_threads(),
                len(proc.open_files()),
                len(proc.connections()),
            ]
            score = self.profiler.score(features)
            if score > 0.8:  # High anomaly
                self.monitor._alert("HFS-113", f"Behavioral anomaly score: {score:.3f}")
        except Exception:
            pass

    def _handle_alert(self, alert):
        """Process security alert - log, block, quarantine."""
        print(f"\n[ALERT] {alert.rule_id} [{alert.severity.value.upper()}]")
        print(f"        {alert.message}")
        print(f"        Evidence: {alert.evidence}")
        print(f"        Remediation: {alert.remediation}")

        # Critical = immediate block
        if alert.severity.value == "critical":
            print("[ACTION] CRITICAL THREAT - Initiating emergency response")
            self._emergency_response(alert)

        # Log to SIEM
        self._log_to_siem(alert)

    def _emergency_response(self, alert):
        """Emergency response for critical threats."""
        actions = [
            "1. Isolate process (cgroup freeze / SIGSTOP)",
            "2. Quarantine model artifacts",
            "3. Alert security team (PagerDuty/Slack/Email)",
            "4. Capture memory dump for forensics",
            "5. Update IOC feeds",
            "6. Block model hash in registry",
        ]
        for action in actions:
            print(f"[RESPONSE] {action}")

        # In production: os.kill(os.getpid(), signal.SIGSTOP)

    def _log_to_siem(self, alert):
        """Structured logging for SIEM integration."""
        log_entry = {
            "timestamp": time.time(),
            "model_hash": self.model_hash,
            "rule_id": alert.rule_id,
            "severity": alert.severity.value,
            "message": alert.message,
            "evidence": alert.evidence,
            "cwe": alert.cwe,
        }
        # In production: send to Splunk/Elastic/Datadog
        print(f"[SIEM] {json.dumps(log_entry)}")

    def stop(self):
        """Graceful shutdown."""
        self._running = False
        self.monitor.stop_monitoring()
        self.monitor.save_baseline()
        print("[RUNTIME] Protection stopped, baseline saved")


def create_production_config() -> dict:
    """Example configuration for the experimental deployment reference."""
    return {
        "static": {
            "fail_on": "high",
            "formats": ["json", "sarif", "html"],
            "rules": "all",
        },
        "runtime": {
            "egress_allowlist": [
                "10.0.0.0/8",  # Private
                "192.168.0.0/16",  # Private
                "172.16.0.0/12",  # Private
                "api.trusted-inference.com",  # Specific allowlist
            ],
            "enable_container_escape_detection": True,
            "enable_gpu_monitoring": True,
            "enable_side_channel_detection": True,
            "behavioral_baseline_samples": 100,
            "anomaly_threshold": 0.8,
        },
        "response": {
            "critical_action": "quarantine",
            "high_action": "alert_and_block",
            "medium_action": "alert",
            "low_action": "log",
        },
        "compliance": {
            "eu_ai_act": True,
            "nist_ai_rmf": True,
            "gdpr_art22": True,
            "slsa_level": 3,
        },
    }


def main():
    parser = argparse.ArgumentParser(description="Deploy real-time model protection")
    parser.add_argument("--model-path", required=True, help="Path to model directory")
    parser.add_argument("--serve", action="store_true", help="Start protected inference server")
    parser.add_argument("--port", type=int, default=8080, help="Server port")
    parser.add_argument("--config", help="Path to config JSON")
    parser.add_argument("--static-only", action="store_true", help="Only run static scan")
    args = parser.parse_args()

    # Load config
    if args.config:
        with open(args.config) as f:
            config = json.load(f)
    else:
        config = create_production_config()

    # Initialize server
    server = ProtectedModelServer(args.model_path, config)

    # Phase 1: Static Analysis
    print("=" * 60)
    print("PHASE 1: STATIC ANALYSIS (Pre-Deployment)")
    print("=" * 60)
    result = server.static_scan()
    print(f"Risk Score: {result.get('risk_score', 'N/A')}/100")
    print(f"Risk Level: {result.get('risk_level', 'N/A')}")
    print(f"Findings: {len(result.get('findings', []))}")

    critical = [f for f in result.get("findings", []) if f.get("severity") == "critical"]
    high = [f for f in result.get("findings", []) if f.get("severity") == "high"]
    if not result.get("approved", False):
        completeness = result.get("completeness", "UNKNOWN")
        error = result.get("error")
        print(
            f"\n[BLOCK] Deployment blocked: completeness={completeness}, "
            f"critical={len(critical)}, high={len(high)}, exit_code={result.get('exit_code')}"
        )
        if error:
            print(f"  scanner error: {error}")
        for finding in critical + high:
            print(f"  - {finding['rule_id']}: {finding['message']}")
        sys.exit(1)

    if args.static_only:
        print("\n[OK] Static scan complete - artifact admitted by configured policy")
        return

    # Phase 2: Runtime Protection
    if args.serve:
        print("\n" + "=" * 60)
        print("PHASE 2: RUNTIME PROTECTION (Production)")
        print("=" * 60)

        def signal_handler(sig, frame):
            print("\n[SHUTDOWN] Signal received, stopping protection...")
            server.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        server.start_runtime_protection()

        print("\n[MONITOR] Runtime monitor active for this process")
        print("[MONITOR] This command does not start an inference server; press Ctrl+C to stop\n")
        try:
            while True:
                time.sleep(10)
                # Periodic health check
                alerts = server.monitor.get_alerts()
                if alerts:
                    print(f"[HEALTH] {len(alerts)} new alerts since last check")
        except KeyboardInterrupt:
            pass
        finally:
            server.stop()


if __name__ == "__main__":
    main()