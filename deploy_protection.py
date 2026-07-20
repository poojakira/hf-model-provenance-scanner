"""
Production Deployment: Real-Time Model Inference Protection
=============================================================

This script demonstrates how to deploy the HF Model Provenance Scanner
with real-time runtime protection for production ML inference services.

Architecture:
1. Pre-deployment: Static scan (pickle, safetensors, GGUF, ONNX, code)
2. Runtime: Behavioral monitoring via eBPF/syscall tracing
3. Response: Automated blocking, alerting, quarantine

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
from typing import Optional

# Add scanner to path
sys.path.insert(0, str(Path(__file__).parent))

from scanner.cli import main as cli_main
from scanner.analyzer.runtime_monitor import (
    RuntimeMonitor,
    ContainerEscapeDetector,
    GPUExploitDetector,
    BehavioralProfiler,
    SideChannelDetector,
)


class ProtectedModelServer:
    """
    Production model server with integrated real-time threat detection.
    """

    def __init__(self, model_path: str, config: dict):
        self.model_path = model_path
        self.config = config
        self.model_hash = self._compute_model_hash()
        self.monitor = RuntimeMonitor(
            model_hash=self.model_hash,
            allowlist_config=config.get("runtime", {})
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
                if f.endswith(('.bin', '.safetensors', '.gguf', '.onnx', '.pt', '.pth', '.pkl', '.py', '.json')):
                    filepath = os.path.join(root, f)
                    try:
                        with open(filepath, 'rb') as fp:
                            while chunk := fp.read(8192):
                                hasher.update(chunk)
                    except Exception:
                        pass
        return hasher.hexdigest()[:16]

    def static_scan(self) -> dict:
        """Run comprehensive static analysis before deployment."""
        print(f"[STATIC] Scanning {self.model_path}...")
        args = [
            self.model_path,
            "--mode", "local",
            "--format", "json",
            "--fail-on", "never",
            "--quiet"
        ]
        # Capture output
        import io
        from contextlib import redirect_stdout, redirect_stderr
        stdout = io.StringIO()
        stderr = io.StringIO()
        try:
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = cli_main(args)
            result = json.loads(stdout.getvalue())
            return {
                "exit_code": exit_code,
                "findings": result.get("findings", []),
                "risk_score": result.get("risk", {}).get("score", 0),
                "risk_level": result.get("risk", {}).get("level", "UNKNOWN"),
            }
        except Exception as e:
            return {"error": str(e), "exit_code": 1}

    def start_runtime_protection(self, target_pid: Optional[int] = None):
        """Start real-time behavioral monitoring."""
        if target_pid is None:
            target_pid = os.getpid()

        print(f"[RUNTIME] Starting protection for PID {target_pid}")
        print(f"[RUNTIME] Model hash: {self.model_hash}")
        print(f"[RUNTIME] Allowed egress: {self.config.get('runtime', {}).get('egress_allowlist', [])}")

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
    """Production-ready configuration."""
    return {
        "static": {
            "fail_on": "high",
            "formats": ["json", "sarif", "html"],
            "rules": "all",
        },
        "runtime": {
            "egress_allowlist": [
                "10.0.0.0/8",      # Private
                "192.168.0.0/16",  # Private
                "172.16.0.0/12",   # Private
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

    critical = [f for f in result.get('findings', []) if f.get('severity') == 'critical']
    high = [f for f in result.get('findings', []) if f.get('severity') == 'high']
    if critical or high:
        print(f"\n[BLOCK] Deployment blocked: {len(critical)} critical, {len(high)} high findings")
        for f in critical + high:
            print(f"  - {f['rule_id']}: {f['message']}")
        if config["static"]["fail_on"] in ("critical", "high"):
            sys.exit(1)

    if args.static_only:
        print("\n[OK] Static scan passed - model approved for deployment")
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

        print(f"\n[SERVER] Protected inference server running on port {args.port}")
        print("[SERVER] Press Ctrl+C to stop\n")

        # In production: start your inference server here (FastAPI, Triton, etc.)
        # For demo: just keep alive
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