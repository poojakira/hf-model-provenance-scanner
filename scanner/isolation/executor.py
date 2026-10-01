"""Fail-closed executor abstraction for running untrusted commands.

Design goals
------------
* **Fail-closed by default.** A backend refuses to run anything unless the
  caller passes an explicit acknowledgment (``acknowledge_untrusted=True``),
  mirroring the existing ``scanner.analyzer.sandbox_executor`` gate which
  disables dynamic execution unless a verified boundary exists.
* **No overclaiming.** ``RestrictedSubprocessBackend`` implements ONLY the
  controls that are portably enforceable from Python:

  - wall-clock timeout with kill-on-expiry,
  - stdout/stderr size caps,
  - working-directory confinement,
  - environment scrubbing (allowlist),
  - on POSIX only (guarded by ``sys.platform``): resource limits via the
    ``resource`` module (RLIMIT_CPU / RLIMIT_AS / RLIMIT_NOFILE / RLIMIT_FSIZE)
    applied in a ``preexec_fn`` that also calls ``os.setsid`` to create a new
    session/process group so the whole tree can be killed.

  It does NOT provide syscall filtering, network isolation, or filesystem
  namespacing. Those require a kernel-backed backend (see profiles/ and the
  UNVERIFIED stub below).
"""

from __future__ import annotations

import abc
import logging
import os
import shutil
import subprocess  # nosec B404 - controlled command execution with fail-closed gate
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

# POSIX-only module; import guarded so Windows import does not crash.

logger = logging.getLogger(__name__)

if sys.platform != "win32":
    import resource  # type: ignore
else:  # pragma: no cover - exercised on Windows hosts
    resource = None  # type: ignore


class IsolationUnavailableError(RuntimeError):
    """Raised when execution is refused because isolation cannot be guaranteed.

    This is the fail-closed signal: rather than silently running untrusted
    code with weaker-than-advertised protection, the executor refuses.
    """


@dataclass
class ExecutionResult:
    """Outcome of a restricted execution."""

    returncode: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    killed: bool = False
    backend: str = ""
    # Human-readable notes about which controls were actually applied.
    applied_controls: list[str] = field(default_factory=list)


# Default environment variables preserved when scrubbing. Everything else is
# dropped. PATH is preserved so the interpreter/binary can be located; callers
# may override the allowlist.
DEFAULT_ENV_ALLOWLIST: tuple[str, ...] = (
    "PATH",
    "SYSTEMROOT",  # required for Python subprocess startup on Windows
    "SYSTEMDRIVE",
    "TEMP",
    "TMP",
    "LANG",
    "LC_ALL",
)


def scrub_environment(
    base_env: Mapping[str, str] | None = None,
    allowlist: Sequence[str] = DEFAULT_ENV_ALLOWLIST,
    extra: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return a minimal environment containing only allowlisted keys.

    Secrets and ambient configuration (tokens, cloud creds, HF_TOKEN, etc.)
    are dropped because they are not on the allowlist.
    """
    source = os.environ if base_env is None else base_env
    scrubbed = {k: v for k, v in source.items() if k in allowlist}
    if extra:
        scrubbed.update(extra)
    return scrubbed


class ExecutorBackend(abc.ABC):
    """Interface for isolation backends.

    Implementations MUST be fail-closed: :meth:`run` refuses to execute unless
    ``acknowledge_untrusted=True`` is passed explicitly.
    """

    #: short stable identifier for the backend
    name: str = "abstract"

    #: whether this backend provides a *verified* kernel isolation boundary.
    #: The portable subprocess backend is intentionally False.
    provides_kernel_isolation: bool = False

    @abc.abstractmethod
    def run(
        self,
        command: Sequence[str],
        *,
        acknowledge_untrusted: bool = False,
        cwd: str | os.PathLike[str] | None = None,
        timeout_seconds: float = 10.0,
        max_output_bytes: int = 1_000_000,
        env_allowlist: Sequence[str] = DEFAULT_ENV_ALLOWLIST,
        env_extra: Mapping[str, str] | None = None,
        cpu_seconds: int | None = None,
        address_space_bytes: int | None = None,
        max_open_files: int | None = None,
        max_file_size_bytes: int | None = None,
    ) -> ExecutionResult:
        """Execute ``command`` under this backend's constraints."""
        raise NotImplementedError


class RestrictedSubprocessBackend(ExecutorBackend):
    """Portable restricted-subprocess backend.

    Enforces the controls that Python can enforce on any platform, plus POSIX
    resource limits where available. This is NOT a security sandbox against a
    determined attacker (no syscall filtering / no namespace isolation) and it
    does not claim to be. It reduces blast radius (runaway CPU/memory/output,
    ambient secrets, wandering working directory) for lower-trust execution
    that the caller has explicitly acknowledged.
    """

    name = "restricted_subprocess"
    provides_kernel_isolation = False

    def run(
        self,
        command: Sequence[str],
        *,
        acknowledge_untrusted: bool = False,
        cwd: str | os.PathLike[str] | None = None,
        timeout_seconds: float = 10.0,
        max_output_bytes: int = 1_000_000,
        env_allowlist: Sequence[str] = DEFAULT_ENV_ALLOWLIST,
        env_extra: Mapping[str, str] | None = None,
        cpu_seconds: int | None = None,
        address_space_bytes: int | None = None,
        max_open_files: int | None = None,
        max_file_size_bytes: int | None = None,
    ) -> ExecutionResult:
        # ---- fail-closed gate -------------------------------------------------
        if not acknowledge_untrusted:
            raise IsolationUnavailableError(
                "Refusing to execute: this backend provides restricted-subprocess "
                "controls (timeouts, output caps, cwd confinement, env scrubbing, "
                "POSIX rlimits) but NOT kernel isolation. Pass "
                "acknowledge_untrusted=True to run anyway, consistent with the "
                "existing sandbox gate."
            )

        if not command:
            raise ValueError("command must be a non-empty sequence")

        applied: list[str] = []

        # ---- working-directory confinement -----------------------------------
        if cwd is not None:
            work_dir = Path(cwd).resolve()
            if not work_dir.is_dir():
                raise IsolationUnavailableError(
                    f"Refusing to execute: working directory does not exist: {work_dir}"
                )
            applied.append(f"cwd_confinement={work_dir}")
        else:
            work_dir = None

        # ---- environment scrubbing -------------------------------------------
        scrubbed_env = scrub_environment(allowlist=env_allowlist, extra=env_extra)
        applied.append(f"env_scrub(kept={sorted(scrubbed_env)})")

        # ---- POSIX resource limits (guarded) ---------------------------------
        preexec = self._build_preexec(
            cpu_seconds=cpu_seconds,
            address_space_bytes=address_space_bytes,
            max_open_files=max_open_files,
            max_file_size_bytes=max_file_size_bytes,
            applied=applied,
        )

        popen_kwargs: dict = dict(
            cwd=str(work_dir) if work_dir is not None else None,
            env=scrubbed_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if preexec is not None:
            popen_kwargs["preexec_fn"] = preexec  # noqa: PLW1509 - POSIX only

        proc = subprocess.Popen(command, **popen_kwargs)  # nosec B603

        timed_out = False
        killed = False
        try:
            stdout, stderr = proc.communicate(timeout=timeout_seconds)
            applied.append(f"timeout={timeout_seconds}s")
        except subprocess.TimeoutExpired:
            timed_out = True
            killed = True
            self._kill_tree(proc)
            # Drain whatever was produced before the kill.
            try:
                stdout, stderr = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                stdout, stderr = b"", b""
            applied.append(f"timeout_enforced_kill={timeout_seconds}s")

        # Popen uses binary pipes here; normalize the possible text type in its stubs.
        stdout = stdout.encode() if isinstance(stdout, str) else (stdout or b"")
        stderr = stderr.encode() if isinstance(stderr, str) else (stderr or b"")

        stdout_trunc = len(stdout) > max_output_bytes
        stderr_trunc = len(stderr) > max_output_bytes
        if stdout_trunc:
            stdout = stdout[:max_output_bytes]
        if stderr_trunc:
            stderr = stderr[:max_output_bytes]
        applied.append(f"output_cap={max_output_bytes}B")

        return ExecutionResult(
            returncode=proc.returncode,
            stdout=stdout,
            stderr=stderr,
            timed_out=timed_out,
            stdout_truncated=stdout_trunc,
            stderr_truncated=stderr_trunc,
            killed=killed,
            backend=self.name,
            applied_controls=applied,
        )

    # ------------------------------------------------------------------ helpers
    def _build_preexec(
        self,
        *,
        cpu_seconds: int | None,
        address_space_bytes: int | None,
        max_open_files: int | None,
        max_file_size_bytes: int | None,
        applied: list[str],
    ):
        """Return a preexec_fn on POSIX, or None on non-POSIX platforms.

        On Windows there is no ``resource`` module and no ``os.fork``/setsid,
        so we cleanly skip these controls and record that fact.
        """
        if sys.platform == "win32" or resource is None:
            applied.append("posix_rlimits=skipped(non-posix)")
            return None

        applied.append("posix_setsid=enabled")
        limits: list[tuple[int, int]] = []
        if cpu_seconds is not None:
            limits.append((resource.RLIMIT_CPU, cpu_seconds))
            applied.append(f"RLIMIT_CPU={cpu_seconds}")
        if address_space_bytes is not None:
            limits.append((resource.RLIMIT_AS, address_space_bytes))
            applied.append(f"RLIMIT_AS={address_space_bytes}")
        if max_open_files is not None:
            limits.append((resource.RLIMIT_NOFILE, max_open_files))
            applied.append(f"RLIMIT_NOFILE={max_open_files}")
        if max_file_size_bytes is not None:
            limits.append((resource.RLIMIT_FSIZE, max_file_size_bytes))
            applied.append(f"RLIMIT_FSIZE={max_file_size_bytes}")

        def _preexec():  # pragma: no cover - runs in POSIX child process
            # New session + process group so the entire tree is killable.
            os.setsid()
            for res, value in limits:
                try:
                    soft, hard = resource.getrlimit(res)
                    new_hard = value if hard == resource.RLIM_INFINITY else min(value, hard)
                    resource.setrlimit(res, (min(value, new_hard), new_hard))
                except (ValueError, OSError) as exc:
                    raise RuntimeError("failed to apply isolation resource limit") from exc

        return _preexec

    def _kill_tree(self, proc: subprocess.Popen) -> None:
        """Kill the process (and its group on POSIX)."""
        if sys.platform != "win32":
            group_killed = False
            try:
                os.killpg(os.getpgid(proc.pid), 9)  # SIGKILL the whole session
                group_killed = True
            except (ProcessLookupError, PermissionError, OSError):
                logger.debug("Process group termination unavailable; falling back to proc.kill()")
            if group_killed:
                return
        try:
            proc.kill()
        except (ProcessLookupError, OSError):
            logger.debug("Process already stopped while killing isolation worker")
            return


class UnverifiedKernelIsolationBackend(ExecutorBackend):
    """UNVERIFIED stub for gVisor / Firecracker kernel isolation.

    This backend is intentionally NOT implemented. Kernel isolation requires a
    Linux host with KVM and a separately verified runtime. The committed
    profiles under ``scanner/isolation/profiles/`` describe the intended
    seccomp / namespace / cgroup configuration, but none of it is verified on a
    Windows host. Calling :meth:`run` fails closed with a clear message.
    """

    name = "gvisor_firecracker_unverified"
    provides_kernel_isolation = False  # NOT verified anywhere in this repo

    def run(self, *args, **kwargs) -> ExecutionResult:  # noqa: D102
        raise NotImplementedError(
            "gVisor/Firecracker kernel isolation is UNVERIFIED and not implemented. "
            "It requires a Linux host with KVM, the runsc/firecracker binaries, and "
            "separate verification. See scanner/isolation/profiles/ for the intended "
            "seccomp allowlist, namespace launch spec, and cgroup v2 limits, and "
            "scanner/isolation/README.md for the Linux verification runbook."
        )


_BACKENDS: dict[str, type[ExecutorBackend]] = {
    RestrictedSubprocessBackend.name: RestrictedSubprocessBackend,
    "gvisor": UnverifiedKernelIsolationBackend,
    "firecracker": UnverifiedKernelIsolationBackend,
    UnverifiedKernelIsolationBackend.name: UnverifiedKernelIsolationBackend,
}


def get_backend(name: str = RestrictedSubprocessBackend.name) -> ExecutorBackend:
    """Return an instantiated backend by name (fail-closed on unknown names)."""
    try:
        cls = _BACKENDS[name]
    except KeyError:
        raise IsolationUnavailableError(
            f"Unknown executor backend {name!r}. Known: {sorted(_BACKENDS)}"
        ) from None
    return cls()


def which(binary: str) -> str | None:
    """Convenience wrapper around shutil.which for runbook checks."""
    return shutil.which(binary)
