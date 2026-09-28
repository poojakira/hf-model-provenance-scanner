"""Runtime isolation executor abstraction (Gap 1 — portable verifiable subset).

This package provides a fail-closed executor abstraction. It deliberately
distinguishes between:

* Controls that are ENFORCEABLE and VERIFIED portably (timeouts, output caps,
  working-directory confinement, environment scrubbing, and POSIX resource
  limits via the ``resource`` module) — implemented by
  :class:`RestrictedSubprocessBackend`.
* True kernel-level isolation (seccomp syscall filtering, Linux namespaces,
  cgroup v2, gVisor/Firecracker microVMs) — represented only by committed
  PROFILE config files and an UNVERIFIED stub backend that raises
  ``NotImplementedError``.

Nothing in this package claims to sandbox untrusted model code on Windows.
See ``scanner/isolation/README.md`` for the verified-vs-unverified matrix.
"""

from .executor import (
    ExecutionResult,
    ExecutorBackend,
    IsolationUnavailableError,
    RestrictedSubprocessBackend,
    UnverifiedKernelIsolationBackend,
    get_backend,
)

__all__ = [
    "ExecutionResult",
    "ExecutorBackend",
    "IsolationUnavailableError",
    "RestrictedSubprocessBackend",
    "UnverifiedKernelIsolationBackend",
    "get_backend",
]
