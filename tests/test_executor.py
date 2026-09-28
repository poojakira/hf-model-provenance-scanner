"""Tests for the fail-closed isolation executor (Gap 1 portable subset).

These tests verify only the PORTABLE, VERIFIABLE controls:
* fail-closed refusal without acknowledgment,
* timeout enforcement (a sleep is killed),
* output size cap,
* environment scrubbing,
* on Windows, POSIX-only rlimits are cleanly skipped (no crash).

They do NOT and cannot verify kernel isolation (seccomp/namespaces/gVisor)
on a Windows host.
"""

import sys
import time

import pytest

from scanner.isolation import (
    ExecutionResult,
    IsolationUnavailableError,
    RestrictedSubprocessBackend,
    UnverifiedKernelIsolationBackend,
    get_backend,
)
from scanner.isolation.executor import DEFAULT_ENV_ALLOWLIST, scrub_environment

PY = sys.executable


def test_fail_closed_refusal_without_ack():
    backend = RestrictedSubprocessBackend()
    with pytest.raises(IsolationUnavailableError, match="Refusing to execute"):
        backend.run([PY, "-c", "print(1)"])  # no acknowledge_untrusted


def test_runs_when_acknowledged():
    backend = RestrictedSubprocessBackend()
    result = backend.run(
        [PY, "-c", "print('hello')"],
        acknowledge_untrusted=True,
        timeout_seconds=15,
    )
    assert isinstance(result, ExecutionResult)
    assert result.returncode == 0
    assert b"hello" in result.stdout
    assert not result.timed_out


def test_timeout_enforcement_kills_sleep():
    backend = RestrictedSubprocessBackend()
    start = time.monotonic()
    result = backend.run(
        [PY, "-c", "import time; time.sleep(30)"],
        acknowledge_untrusted=True,
        timeout_seconds=2,
    )
    elapsed = time.monotonic() - start
    assert result.timed_out is True
    assert result.killed is True
    # Must have been killed well before the 30s sleep would finish.
    assert elapsed < 20, f"process was not killed promptly (elapsed={elapsed:.1f}s)"


def test_output_cap_truncates_stdout():
    backend = RestrictedSubprocessBackend()
    result = backend.run(
        [PY, "-c", "import sys; sys.stdout.write('A' * 100000)"],
        acknowledge_untrusted=True,
        timeout_seconds=15,
        max_output_bytes=1000,
    )
    assert result.stdout_truncated is True
    assert len(result.stdout) == 1000


def test_env_scrubbing_drops_secrets(monkeypatch):
    monkeypatch.setenv("HF_TOKEN", "super-secret-value")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "also-secret")
    scrubbed = scrub_environment()
    assert "HF_TOKEN" not in scrubbed
    assert "AWS_SECRET_ACCESS_KEY" not in scrubbed
    # allowlisted keys survive if present
    for k in scrubbed:
        assert k in DEFAULT_ENV_ALLOWLIST


def test_env_scrubbing_end_to_end(monkeypatch):
    monkeypatch.setenv("HF_TOKEN", "leak-me")
    backend = RestrictedSubprocessBackend()
    code = "import os; print('HF_TOKEN' in os.environ)"
    result = backend.run(
        [PY, "-c", code],
        acknowledge_untrusted=True,
        timeout_seconds=15,
    )
    assert result.returncode == 0
    assert b"False" in result.stdout


def test_cwd_confinement(tmp_path):
    backend = RestrictedSubprocessBackend()
    result = backend.run(
        [PY, "-c", "import os; print(os.getcwd())"],
        acknowledge_untrusted=True,
        timeout_seconds=15,
        cwd=tmp_path,
    )
    assert result.returncode == 0
    assert str(tmp_path.resolve()) in result.stdout.decode()


def test_cwd_confinement_rejects_missing_dir(tmp_path):
    backend = RestrictedSubprocessBackend()
    missing = tmp_path / "does-not-exist"
    with pytest.raises(IsolationUnavailableError, match="working directory does not exist"):
        backend.run(
            [PY, "-c", "print(1)"],
            acknowledge_untrusted=True,
            cwd=missing,
        )


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX rlimits only")
def test_posix_rlimits_applied():
    backend = RestrictedSubprocessBackend()
    result = backend.run(
        [PY, "-c", "print('ok')"],
        acknowledge_untrusted=True,
        timeout_seconds=15,
        cpu_seconds=5,
        address_space_bytes=512 * 1024 * 1024,
        max_open_files=64,
        max_file_size_bytes=10 * 1024 * 1024,
    )
    assert any("RLIMIT_CPU" in c for c in result.applied_controls)
    assert any("posix_setsid" in c for c in result.applied_controls)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only skip behavior")
def test_windows_rlimits_cleanly_skipped():
    # On Windows the POSIX-only rlimits must be skipped without crashing even
    # when the caller passes them.
    backend = RestrictedSubprocessBackend()
    result = backend.run(
        [PY, "-c", "print('ok')"],
        acknowledge_untrusted=True,
        timeout_seconds=15,
        cpu_seconds=5,
        address_space_bytes=512 * 1024 * 1024,
        max_open_files=64,
        max_file_size_bytes=10 * 1024 * 1024,
    )
    assert result.returncode == 0
    assert b"ok" in result.stdout
    assert any("posix_rlimits=skipped" in c for c in result.applied_controls)
    # No RLIMIT_* should have been applied on Windows.
    assert not any("RLIMIT_" in c for c in result.applied_controls)


def test_unverified_kernel_backend_raises():
    for name in ("gvisor", "firecracker"):
        backend = get_backend(name)
        assert isinstance(backend, UnverifiedKernelIsolationBackend)
        with pytest.raises(NotImplementedError, match="UNVERIFIED"):
            backend.run([PY, "-c", "print(1)"], acknowledge_untrusted=True)


def test_unknown_backend_fails_closed():
    with pytest.raises(IsolationUnavailableError, match="Unknown executor backend"):
        get_backend("definitely-not-a-backend")


def test_empty_command_rejected():
    backend = RestrictedSubprocessBackend()
    with pytest.raises(ValueError, match="non-empty"):
        backend.run([], acknowledge_untrusted=True)
