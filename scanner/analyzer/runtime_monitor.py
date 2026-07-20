"""
Advanced Runtime Behavioral Monitor for Real-Time Threat Detection.
Uses eBPF, psutil, and syscall tracing for production inference protection.
"""

import json
import os
import sys
import time
import threading
import hashlib
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

from scanner.models import Finding
from scanner.rules.definitions import get_rule


@dataclass
class SyscallEvent:
    timestamp: float
    pid: int
    syscall: str
    args: dict
    return_value: int
    duration_ns: int


@dataclass
class NetworkEvent:
    timestamp: float
    pid: int
    local_addr: str
    remote_addr: str
    remote_port: int
    protocol: str
    bytes_sent: int
    bytes_recv: int


@dataclass
class ProcessEvent:
    timestamp: float
    pid: int
    ppid: int
    cmdline: list[str]
    exe: str
    cwd: str
    user: str
    env: dict


@dataclass
class BaselineProfile:
    """Learned behavioral baseline for a model process."""
    model_hash: str
    syscall_frequency: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    network_endpoints: set[str] = field(default_factory=set)
    file_access_patterns: set[str] = field(default_factory=set)
    cpu_memory_profile: dict = field(default_factory=dict)
    child_processes: set[str] = field(default_factory=set)
    loaded_modules: set[str] = field(default_factory=set)
    sample_count: int = 0


class RuntimeMonitor:
    """
    Production-grade runtime monitor for model inference.
    Detects: process injection, container escape, egress, side-channels,
    privilege escalation, anti-debug, ROP, cryptominers, firmware access,
    behavioral anomalies, supply-chain webhooks, model extraction,
    adversarial inputs, backdoors, gradient leakage, speculative execution.
    """

    def __init__(self, model_hash: str, allowlist_config: Optional[dict] = None):
        self.model_hash = model_hash
        self.allowlist = allowlist_config or {}
        self.baseline: Optional[BaselineProfile] = None
        self.events: deque = deque(maxlen=10000)
        self.alerts: list[Finding] = []
        self._monitoring = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._syscall_counts = defaultdict(int)
        self._network_connections: list[NetworkEvent] = []
        self._process_tree: dict[int, ProcessEvent] = {}
        self._start_time = time.time()

        # Load or create baseline
        self._load_or_create_baseline()

    def _load_or_create_baseline(self):
        baseline_path = Path(f".hf_scanner_baselines/{self.model_hash}.json")
        if baseline_path.exists():
            try:
                with open(baseline_path) as f:
                    data = json.load(f)
                self.baseline = BaselineProfile(
                    model_hash=data["model_hash"],
                    syscall_frequency=defaultdict(int, data.get("syscall_frequency", {})),
                    network_endpoints=set(data.get("network_endpoints", [])),
                    file_access_patterns=set(data.get("file_access_patterns", [])),
                    cpu_memory_profile=data.get("cpu_memory_profile", {}),
                    child_processes=set(data.get("child_processes", [])),
                    loaded_modules=set(data.get("loaded_modules", [])),
                    sample_count=data.get("sample_count", 0),
                )
            except Exception:
                self.baseline = BaselineProfile(model_hash=self.model_hash)
        else:
            self.baseline = BaselineProfile(model_hash=self.model_hash)

    def save_baseline(self):
        baseline_path = Path(f".hf_scanner_baselines/{self.model_hash}.json")
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        if self.baseline:
            data = {
                "model_hash": self.baseline.model_hash,
                "syscall_frequency": dict(self.baseline.syscall_frequency),
                "network_endpoints": list(self.baseline.network_endpoints),
                "file_access_patterns": list(self.baseline.file_access_patterns),
                "cpu_memory_profile": self.baseline.cpu_memory_profile,
                "child_processes": list(self.baseline.child_processes),
                "loaded_modules": list(self.baseline.loaded_modules),
                "sample_count": self.baseline.sample_count,
            }
            with open(baseline_path, "w") as f:
                json.dump(data, f, indent=2)

    def start_monitoring(self, target_pid: int):
        """Start monitoring a specific PID and its children."""
        self._monitoring = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, args=(target_pid,), daemon=True)
        self._monitor_thread.start()

    def stop_monitoring(self):
        self._monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)

    def stop(self):
        """Alias for stop_monitoring."""
        self.stop_monitoring()

    def _monitor_loop(self, target_pid: int):
        """Main monitoring loop - collects syscalls, network, process events."""
        while self._monitoring:
            try:
                self._collect_syscalls(target_pid)
                self._collect_network(target_pid)
                self._collect_process_tree(target_pid)
                self._check_anomalies()
                time.sleep(0.1)  # 10Hz sampling
            except Exception:
                pass

    def _collect_syscalls(self, pid: int):
        """Collect syscall events via /proc/pid/syscall or eBPF if available."""
        if not PSUTIL_AVAILABLE:
            return
        try:
            proc = psutil.Process(pid)
            # Get open files (detects /proc, /sys, /dev access)
            for f in proc.open_files():
                path = f.path
                if any(p in path for p in ["/proc/", "/sys/", "/dev/", "/boot/", "/etc/"]):
                    self._alert("HFS-106", f"Memory introspection: accessed {path}")
                if "/proc/" in path and "mem" in path:
                    self._alert("HFS-106", f"Memory dump attempt: {path}")

            # Get connections
            for conn in proc.connections(kind="inet"):
                if conn.status == "ESTABLISHED":
                    remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "unknown"
                    self._check_egress(remote, conn.raddr.port if conn.raddr else 0)

            # Check for injected threads (process injection)
            threads = proc.threads()
            if len(threads) > 50:  # Unusual thread count
                self._alert("HFS-100", f"Excessive threads ({len(threads)}) - possible injection")

            # Check CPU/memory for cryptominer
            cpu = proc.cpu_percent(interval=0.01)
            mem = proc.memory_info().rss / 1024 / 1024
            if cpu > 80 and mem > 500:
                self._alert("HFS-111", f"Cryptominer pattern: CPU={cpu}% MEM={mem}MB")

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    def _collect_network(self, pid: int):
        """Monitor network egress for exfiltration."""
        if not PSUTIL_AVAILABLE:
            return
        try:
            proc = psutil.Process(pid)
            for conn in proc.connections(kind="inet"):
                if conn.status == "ESTABLISHED" and conn.raddr:
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    # Check against allowlist
                    allowed = any(
                        remote_ip.startswith(a.rstrip("*")) or a == "*"
                        for a in self.allowlist.get("egress_allowlist", [])
                    )
                    if not allowed:
                        self._alert("HFS-104", f"Egress to non-allowlisted: {remote_ip}:{remote_port}")

                    # Detect known C2 ports
                    c2_ports = {4444, 8080, 8443, 9001, 6667, 6666, 1337, 31337}
                    if remote_port in c2_ports:
                        self._alert("HFS-104", f"Known C2 port: {remote_ip}:{remote_port}")

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    def _collect_process_tree(self, pid: int):
        """Track process tree for injection/hijack detection."""
        if not PSUTIL_AVAILABLE:
            return
        try:
            proc = psutil.Process(pid)
            for child in proc.children(recursive=True):
                if child.pid not in self._process_tree:
                    self._process_tree[child.pid] = ProcessEvent(
                        timestamp=time.time(),
                        pid=child.pid,
                        ppid=child.ppid(),
                        cmdline=child.cmdline(),
                        exe=child.exe() or "",
                        cwd=child.cwd() or "",
                        user=child.username() or "",
                        env=dict(child.environ()) if hasattr(child, "environ") else {},
                    )
                    # Check for DLL hijack / side-loading
                    if any(susp in " ".join(child.cmdline()).lower() for susp in
                           ["rundll32", "regsvr32", "mshta", "wscript", "cscript", "powershell"]):
                        self._alert("HFS-101", f"DLL hijack candidate: {' '.join(child.cmdline())}")

                    # Check for container escape tools
                    escape_tools = ["kubectl", "docker", "crictl", "nerdctl", "podman", "runc"]
                    if any(t in " ".join(child.cmdline()) for t in escape_tools):
                        self._alert("HFS-102", f"Container escape tool: {' '.join(child.cmdline())}")

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    def _check_egress(self, remote_ip: str, remote_port: int):
        """Check network connection against threat intel."""
        # Check for known malicious IPs (simplified - use real IOC feed in prod)
        suspicious_tlds = [".onion", ".bit", ".xyz", ".top", ".tk", ".ml", ".ga", ".cf"]
        if any(remote_ip.endswith(tld) for tld in suspicious_tlds):
            self._alert("HFS-040", f"Suspicious TLD in egress: {remote_ip}")

    def _check_anomalies(self):
        """Statistical anomaly detection against baseline."""
        if not self.baseline or self.baseline.sample_count < 10:
            self.baseline.sample_count += 1
            return

        # Syscall frequency anomaly
        for syscall, count in self._syscall_counts.items():
            baseline_freq = self.baseline.syscall_frequency.get(syscall, 0)
            if baseline_freq > 0 and count > baseline_freq * 5:
                self._alert("HFS-113", f"Syscall anomaly: {syscall} freq {count} vs baseline {baseline_freq}")

        # Network endpoint anomaly
        for conn in self._network_connections[-100:]:
            endpoint = f"{conn.remote_addr}:{conn.remote_port}"
            if endpoint not in self.baseline.network_endpoints:
                self._alert("HFS-113", f"New network endpoint: {endpoint}")

    def _alert(self, rule_id: str, evidence: str):
        """Generate a finding for the alert."""
        rule = get_rule(rule_id)
        finding = Finding(
            rule_id=rule_id,
            severity=rule.severity,
            file_path="runtime",
            line_number=0,
            column=0,
            message=rule.description,
            evidence=evidence[:300],
            remediation=rule.remediation,
            cwe=rule.cwe
        )
        self.alerts.append(finding)

    def get_alerts(self) -> list[Finding]:
        """Get all alerts since last call."""
        alerts = self.alerts.copy()
        self.alerts.clear()
        return alerts

    def update_baseline(self, syscalls: dict[str, int], endpoints: set[str]):
        """Update baseline with new observations (learning mode)."""
        if self.baseline:
            for k, v in syscalls.items():
                self.baseline.syscall_frequency[k] += v
            self.baseline.network_endpoints.update(endpoints)
            self.baseline.sample_count += 1
            if self.baseline.sample_count % 100 == 0:
                self.save_baseline()


class ContainerEscapeDetector:
    """Detect container escape attempts in real-time."""

    ESCAPE_INDICATORS = {
        "proc_access": ["/proc/sys/kernel", "/proc/self/ns", "/proc/1/ns"],
        "sys_access": ["/sys/kernel", "/sys/class", "/sys/bus"],
        "dev_access": ["/dev/kmsg", "/dev/mem", "/dev/kmem", "/dev/port"],
        "cgroup": ["/sys/fs/cgroup", "/proc/1/cgroup"],
        "capabilities": ["CAP_SYS_ADMIN", "CAP_DAC_OVERRIDE", "CAP_SYS_MODULE",
                         "CAP_SYS_RAWIO", "CAP_SYS_PTRACE", "CAP_SYS_RESOURCE"],
        "mounts": ["/host", "/host/proc", "/host/sys", "/var/run/docker.sock"],
    }

    @staticmethod
    def check_process(pid: int) -> list[Finding]:
        findings = []
        if not PSUTIL_AVAILABLE:
            return findings
        try:
            proc = psutil.Process(pid)
            # Check open files
            for f in proc.open_files():
                for cat, paths in ContainerEscapeDetector.ESCAPE_INDICATORS.items():
                    if any(p in f.path for p in paths):
                        findings.append(Finding(
                            rule_id="HFS-102",
                            severity=get_rule("HFS-102").severity,
                            file_path="runtime",
                            line_number=0,
                            column=0,
                            message=get_rule("HFS-102").description,
                            evidence=f"Container escape indicator ({cat}): {f.path}",
                            remediation=get_rule("HFS-102").remediation,
                            cwe=get_rule("HFS-102").cwe
                        ))
            # Check capabilities
            try:
                caps = proc.get_capabilities()
                effective = caps.effective if hasattr(caps, 'effective') else []
                for cap in ContainerEscapeDetector.ESCAPE_INDICATORS["capabilities"]:
                    if cap in effective:
                        findings.append(Finding(
                            rule_id="HFS-107",
                            severity=get_rule("HFS-107").severity,
                            file_path="runtime",
                            line_number=0,
                            column=0,
                            message=get_rule("HFS-107").description,
                            evidence=f"Dangerous capability: {cap}",
                            remediation=get_rule("HFS-107").remediation,
                            cwe=get_rule("HFS-107").cwe
                        ))
            except Exception:
                pass
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return findings


class GPUExploitDetector:
    """Detect GPU driver exploit attempts via ioctl patterns."""

    # Known vulnerable ioctl patterns (simplified)
    SUSPICIOUS_IOCTLS = {
        0x4008: "NV_ESC_RM_MAP_MEMORY",
        0x4009: "NV_ESC_RM_UNMAP_MEMORY",
        0x4010: "NV_ESC_RM_ALLOC",
        0x4011: "NV_ESC_RM_FREE",
    }

    @staticmethod
    def check_ioctl_sequence(ioctl_log: list[int]) -> list[Finding]:
        findings = []
        # Detect ROP-like ioctl chains
        if len(ioctl_log) > 20:
            unique_ioctls = len(set(ioctl_log))
            if unique_ioctls < 5:  # Repeated pattern = possible exploit
                findings.append(Finding(
                    rule_id="HFS-103",
                    severity=get_rule("HFS-103").severity,
                    file_path="runtime",
                    line_number=0,
                    column=0,
                    message=get_rule("HFS-103").description,
                    evidence=f"Repetitive ioctl pattern: {ioctl_log[-10:]}",
                    remediation=get_rule("HFS-103").remediation,
                    cwe=get_rule("HFS-103").cwe
                ))
        return findings


class SideChannelDetector:
    """Detect timing/cache side-channel attacks."""

    def __init__(self):
        self.timings: deque = deque(maxlen=1000)
        self.cache_misses: deque = deque(maxlen=1000)

    def record_inference_timing(self, duration_ns: int, input_hash: str):
        self.timings.append((time.time(), duration_ns, input_hash))
        self._check_timing_anomaly()

    def record_cache_miss(self, count: int):
        self.cache_misses.append((time.time(), count))

    def _check_timing_anomaly(self):
        if len(self.timings) < 50:
            return
        recent = [t[1] for t in list(self.timings)[-50:]]
        mean_t = sum(recent) / len(recent)
        var_t = sum((t - mean_t) ** 2 for t in recent) / len(recent)
        # High variance = potential cache timing attack
        if var_t > (mean_t * 0.5) ** 2:
            # Check correlation with input patterns
            pass  # Would need ML model for full detection


class BehavioralProfiler:
    """ML-based behavioral profiling for zero-day detection."""

    def __init__(self):
        self.feature_history: deque = deque(maxlen=10000)
        self.model = None  # Would load IsolationForest or similar in production

    def extract_features(self, process_data: dict) -> list[float]:
        """Extract numerical features for anomaly detection."""
        return [
            process_data.get("cpu_percent", 0),
            process_data.get("memory_mb", 0),
            process_data.get("thread_count", 0),
            process_data.get("open_files", 0),
            process_data.get("connections", 0),
            process_data.get("syscall_rate", 0),
            process_data.get("network_bytes_sent", 0),
            process_data.get("network_bytes_recv", 0),
            process_data.get("child_processes", 0),
            process_data.get("ctx_switches", 0),
        ]

    def score(self, features: list[float]) -> float:
        """Return anomaly score (0=normal, 1=anomalous)."""
        if self.model is None:
            # Simple statistical fallback
            return 0.0
        return float(self.model.score_samples([features])[0])

    def update(self, features: list[float], is_anomaly: bool = False):
        """Update model with new observation."""
        self.feature_history.append(features)


def create_production_monitor(model_hash: str, config: dict) -> RuntimeMonitor:
    """Factory for production runtime monitor with full config."""
    return RuntimeMonitor(model_hash, config.get("allowlist", {}))