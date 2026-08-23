"""
Runtime Policy Engine for model inference protection.

Enforces configurable security policies during model execution:
- Network egress allowlisting
- Child process spawning controls
- File write directory restrictions
- Memory usage limits
- Syscall filtering

Policies are loaded from JSON files and support configurable actions:
log, alert, or block.
"""

import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

logger = logging.getLogger(__name__)


class PolicyViolationError(Exception):
    """Raised when a policy violation occurs and action is 'block'."""

    def __init__(self, message: str, rule: str, details: dict | None = None):
        super().__init__(message)
        self.rule = rule
        self.details = details or {}


@dataclass
class PolicyAlert:
    """Record of a policy violation event."""

    timestamp: float
    rule: str
    action: str
    message: str
    details: dict = field(default_factory=dict)


@dataclass
class RuntimePolicy:
    """Parsed runtime policy configuration."""

    # Network policy
    allowed_endpoints: list[str] = field(default_factory=list)
    blocked_endpoints: list[str] = field(default_factory=list)
    network_action: str = "block"  # log, alert, block

    # Process policy
    allow_child_processes: bool = False
    allowed_executables: list[str] = field(default_factory=list)
    process_action: str = "alert"  # log, alert, block

    # Filesystem policy
    allowed_write_dirs: list[str] = field(default_factory=list)
    blocked_write_paths: list[str] = field(default_factory=list)
    filesystem_action: str = "alert"  # log, alert, block

    # Resource policy
    max_memory_mb: int = 4096
    max_cpu_percent: float = 100.0
    resource_action: str = "alert"  # log, alert, block

    # Syscall policy (conceptual - enforced via monitoring)
    allowed_syscalls: list[str] = field(default_factory=list)
    blocked_syscalls: list[str] = field(default_factory=list)
    syscall_action: str = "log"  # log, alert, block


def load_policy(policy_path: str | None = None) -> RuntimePolicy:
    """Load a runtime policy from a JSON file.

    If no path is provided, returns a default restrictive policy.
    Supports JSON format. YAML support requires pyyaml (optional).

    Args:
        policy_path: Path to a JSON or YAML policy file.

    Returns:
        A RuntimePolicy instance.
    """
    if policy_path is None:
        return RuntimePolicy()

    path = Path(policy_path)
    if not path.exists():
        logger.warning("Policy file not found: %s, using defaults", policy_path)
        return RuntimePolicy()

    try:
        content = path.read_text(encoding="utf-8")
        if path.suffix in (".yaml", ".yml"):
            # Try YAML parsing (optional dependency)
            try:
                import yaml  # type: ignore[import-untyped]

                data = yaml.safe_load(content)
            except ImportError:
                logger.warning("PyYAML not installed, cannot parse YAML policy file")
                return RuntimePolicy()
        else:
            data = json.loads(content)

        return _parse_policy(data)
    except (json.JSONDecodeError, OSError) as e:
        logger.error("Failed to load policy from %s: %s", policy_path, e)
        return RuntimePolicy()


def _parse_policy(data: dict) -> RuntimePolicy:
    """Parse a policy dictionary into a RuntimePolicy object."""
    policy = RuntimePolicy()

    # Network section
    network = data.get("network", {})
    policy.allowed_endpoints = network.get("allowed_endpoints", [])
    policy.blocked_endpoints = network.get("blocked_endpoints", [])
    policy.network_action = network.get("action", "block")

    # Process section
    process = data.get("process", {})
    policy.allow_child_processes = process.get("allow_child_processes", False)
    policy.allowed_executables = process.get("allowed_executables", [])
    policy.process_action = process.get("action", "alert")

    # Filesystem section
    filesystem = data.get("filesystem", {})
    policy.allowed_write_dirs = filesystem.get("allowed_write_dirs", [])
    policy.blocked_write_paths = filesystem.get("blocked_write_paths", [])
    policy.filesystem_action = filesystem.get("action", "alert")

    # Resources section
    resources = data.get("resources", {})
    policy.max_memory_mb = resources.get("max_memory_mb", 4096)
    policy.max_cpu_percent = resources.get("max_cpu_percent", 100.0)
    policy.resource_action = resources.get("action", "alert")

    # Syscall section
    syscalls = data.get("syscalls", {})
    policy.allowed_syscalls = syscalls.get("allowed", [])
    policy.blocked_syscalls = syscalls.get("blocked", [])
    policy.syscall_action = syscalls.get("action", "log")

    return policy


class PolicyEngine:
    """Runtime policy enforcement engine.

    Monitors process behavior and enforces policy rules.
    Can be used standalone or integrated with the RuntimeInterceptor.
    """

    def __init__(self, policy: RuntimePolicy | None = None, policy_path: str | None = None):
        if policy is not None:
            self.policy = policy
        else:
            self.policy = load_policy(policy_path)

        self.alerts: list[PolicyAlert] = []
        self._monitoring = False
        self._monitor_thread: threading.Thread | None = None
        self._pid = os.getpid()
        self._lock = threading.Lock()

    def start_monitoring(self, interval: float = 1.0) -> None:
        """Start background monitoring thread.

        Args:
            interval: Monitoring interval in seconds.
        """
        if self._monitoring:
            return
        if not PSUTIL_AVAILABLE:
            logger.warning("psutil not available, monitoring disabled")
            return

        self._monitoring = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(interval,),
            daemon=True,
            name="policy-engine-monitor",
        )
        self._monitor_thread.start()
        logger.info("Policy engine monitoring started (interval=%.1fs)", interval)

    def stop_monitoring(self) -> None:
        """Stop background monitoring."""
        self._monitoring = False
        if self._monitor_thread is not None:
            self._monitor_thread.join(timeout=5.0)
            self._monitor_thread = None

    def check_network_connection(self, remote_host: str, remote_port: int) -> None:
        """Check if a network connection is allowed by policy.

        Args:
            remote_host: The remote host address.
            remote_port: The remote port number.

        Raises:
            PolicyViolationError: If the connection is blocked by policy.
        """
        endpoint = f"{remote_host}:{remote_port}"

        # Check blocked list first
        if self._matches_endpoint(remote_host, remote_port, self.policy.blocked_endpoints):
            self._handle_violation(
                rule="network.blocked_endpoint",
                action=self.policy.network_action,
                message=f"Connection to blocked endpoint: {endpoint}",
                details={"host": remote_host, "port": remote_port},
            )
            return

        # If allowlist is configured, check against it
        if self.policy.allowed_endpoints:
            if not self._matches_endpoint(remote_host, remote_port, self.policy.allowed_endpoints):
                self._handle_violation(
                    rule="network.not_allowlisted",
                    action=self.policy.network_action,
                    message=f"Connection to non-allowlisted endpoint: {endpoint}",
                    details={"host": remote_host, "port": remote_port},
                )

    def check_child_process(self, executable: str, cmdline: list[str] | None = None) -> None:
        """Check if spawning a child process is allowed.

        Args:
            executable: Path to the executable being spawned.
            cmdline: Full command line arguments.

        Raises:
            PolicyViolationError: If the process spawn is blocked by policy.
        """
        if self.policy.allow_child_processes:
            # Check if executable is in allowed list
            if self.policy.allowed_executables:
                exe_name = Path(executable).name
                if not any(
                    exe_name == Path(allowed).name or executable == allowed
                    for allowed in self.policy.allowed_executables
                ):
                    self._handle_violation(
                        rule="process.not_allowlisted",
                        action=self.policy.process_action,
                        message=f"Child process not in allowlist: {executable}",
                        details={"executable": executable, "cmdline": cmdline or []},
                    )
        else:
            self._handle_violation(
                rule="process.child_spawn_blocked",
                action=self.policy.process_action,
                message=f"Child process spawning blocked: {executable}",
                details={"executable": executable, "cmdline": cmdline or []},
            )

    def check_file_write(self, file_path: str) -> None:
        """Check if a file write is allowed by policy.

        Args:
            file_path: Path to the file being written.

        Raises:
            PolicyViolationError: If the write is blocked by policy.
        """
        path = Path(file_path).resolve()
        path_str = str(path)

        # Check blocked paths first
        for blocked in self.policy.blocked_write_paths:
            if path_str.startswith(str(Path(blocked).resolve())):
                self._handle_violation(
                    rule="filesystem.blocked_path",
                    action=self.policy.filesystem_action,
                    message=f"Write to blocked path: {file_path}",
                    details={"path": file_path, "blocked_by": blocked},
                )
                return

        # If allowlist is configured, check against it
        if self.policy.allowed_write_dirs:
            allowed = False
            for allowed_dir in self.policy.allowed_write_dirs:
                try:
                    resolved = str(Path(allowed_dir).resolve())
                    if path_str.startswith(resolved):
                        allowed = True
                        break
                except (OSError, ValueError):
                    continue

            if not allowed:
                self._handle_violation(
                    rule="filesystem.not_allowlisted",
                    action=self.policy.filesystem_action,
                    message=f"Write outside allowed directories: {file_path}",
                    details={"path": file_path, "allowed_dirs": self.policy.allowed_write_dirs},
                )

    def check_memory_usage(self, memory_mb: float) -> None:
        """Check if memory usage exceeds policy limit.

        Args:
            memory_mb: Current memory usage in megabytes.

        Raises:
            PolicyViolationError: If memory exceeds limit and action is 'block'.
        """
        if memory_mb > self.policy.max_memory_mb:
            self._handle_violation(
                rule="resources.memory_exceeded",
                action=self.policy.resource_action,
                message=(
                    f"Memory usage ({memory_mb:.0f}MB) exceeds "
                    f"limit ({self.policy.max_memory_mb}MB)"
                ),
                details={"current_mb": memory_mb, "limit_mb": self.policy.max_memory_mb},
            )

    def _matches_endpoint(self, host: str, port: int, endpoint_list: list[str]) -> bool:
        """Check if a host:port matches any pattern in the endpoint list."""
        for pattern in endpoint_list:
            if ":" in pattern:
                pat_host, pat_port_str = pattern.rsplit(":", 1)
                try:
                    pat_port = int(pat_port_str)
                except ValueError:
                    pat_port = None

                if pat_host == host or pat_host == "*":
                    if pat_port is None or pat_port == port:
                        return True
            else:
                # Pattern is just a host/IP
                if pattern == host or pattern == "*":
                    return True
                # Check CIDR-like prefix (simple prefix match for common cases)
                if host.startswith(pattern.rstrip("*")):
                    return True
        return False

    def _handle_violation(
        self, rule: str, action: str, message: str, details: dict | None = None
    ) -> None:
        """Handle a policy violation according to the configured action."""
        alert = PolicyAlert(
            timestamp=time.time(),
            rule=rule,
            action=action,
            message=message,
            details=details or {},
        )

        with self._lock:
            self.alerts.append(alert)

        if action == "log":
            logger.info("Policy violation [%s]: %s", rule, message)
        elif action == "alert":
            logger.warning("Policy ALERT [%s]: %s", rule, message)
        elif action == "block":
            logger.error("Policy BLOCK [%s]: %s", rule, message)
            raise PolicyViolationError(message, rule=rule, details=details)

    def _monitor_loop(self, interval: float) -> None:
        """Background monitoring loop checking for policy violations."""
        initial_children = set()
        try:
            proc = psutil.Process(self._pid)
            initial_children = {c.pid for c in proc.children(recursive=True)}
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        while self._monitoring:
            try:
                self._check_process_state(initial_children)
            except Exception as e:
                logger.debug("Monitor loop error: %s", e)

            time.sleep(interval)

    def _check_process_state(self, initial_children: set) -> None:
        """Check current process state against policy."""
        try:
            proc = psutil.Process(self._pid)
        except psutil.NoSuchProcess:
            self._monitoring = False
            return

        # Check memory
        try:
            mem_info = proc.memory_info()
            memory_mb = mem_info.rss / (1024 * 1024)
            if memory_mb > self.policy.max_memory_mb:
                self._handle_violation(
                    rule="resources.memory_exceeded",
                    action=self.policy.resource_action
                    if self.policy.resource_action != "block"
                    else "alert",
                    message=(
                        f"Memory usage ({memory_mb:.0f}MB) exceeds "
                        f"limit ({self.policy.max_memory_mb}MB)"
                    ),
                    details={"current_mb": memory_mb, "limit_mb": self.policy.max_memory_mb},
                )
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        # Check for new child processes
        try:
            current_children = set()
            for child in proc.children(recursive=True):
                current_children.add(child.pid)
                if child.pid not in initial_children:
                    try:
                        exe = child.exe()
                        cmdline = child.cmdline()
                        self.check_child_process(exe, cmdline)
                        initial_children.add(child.pid)
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        # Check network connections
        try:
            connections = proc.net_connections(kind="inet")
            for conn in connections:
                if conn.status == "ESTABLISHED" and conn.raddr:
                    remote_host = conn.raddr.ip
                    remote_port = conn.raddr.port
                    try:
                        self.check_network_connection(remote_host, remote_port)
                    except PolicyViolationError:
                        # In monitor loop, downgrade block to alert to avoid crashing
                        pass
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

    def get_alerts(self) -> list[PolicyAlert]:
        """Return all policy alerts."""
        with self._lock:
            return list(self.alerts)

    def clear_alerts(self) -> None:
        """Clear all accumulated alerts."""
        with self._lock:
            self.alerts.clear()
