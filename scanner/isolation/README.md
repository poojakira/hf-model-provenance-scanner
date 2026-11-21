# Portable executor and illustrative isolation profiles

This package is **separate from the Linux local inspector worker** in `scanner/workbench/worker.py`. The inspector uses its own actual libseccomp seal and bounded parent protocol. These portable executor classes/profiles do not configure that worker, and the local UI cannot select an arbitrary command/backend.

`RestrictedSubprocessBackend` exposes a fixed-argv subprocess API only after the caller explicitly sets acknowledge_untrusted=True. That acknowledgment is a refusal gate, not a security proof or permission to execute arbitrary untrusted code. The backend scrubs the environment, chooses a working directory, applies timeout/output handling and POSIX resource limits where available. Setting cwd does not confine filesystem access. Output truncation after collection is not the inspector's bounded nonblocking-pipe protocol. Platform behavior and process-tree termination differ; inspect `executor.py` and its actual tests before integrating.

The portable backend provides no syscall filter, filesystem namespace, network isolation or VM boundary. Its Windows/POSIX unit results must be tied to the platform/source that ran them; historical checkmarks were not fresh cross-platform proof. It must not be used to claim model-code execution is safe.

## Implemented versus illustrative

| Component | Actual role | Status boundary |
|---|---|---|
| ExecutorBackend / restricted subprocess | Command-result abstraction, acknowledgment requirement, environment/timeout/resource helpers | Source/tests exist; current pass results belong to an exact generated manifest, not a permanent VERIFIED table |
| UnverifiedKernelIsolationBackend | Raises NotImplementedError | Not an implemented gVisor/Firecracker/kernel backend |
| profiles/seccomp-allowlist.json | Example OCI profile | Not automatically installed/exercised by this package; not the local worker's filter |
| profiles/namespace-launch-spec.yaml | Example namespace launch configuration | Requires external runtime/privileges and independent validation |
| profiles/cgroup-v2-limits.yaml | Example resource settings | Requires operator-controlled delegated cgroups; not proof of applied host limits |

Use `python -m pytest tests/test_executor.py` in the reviewed verification environment for the portable unit cases; it is not the complete suite or hostile-code containment certification. Windows-specific behavior can be skipped on Linux and must remain visibly skipped. See [TESTING.md](../../docs/TESTING.md).

No namespace/cgroup/KVM provisioning, host-policy changes or resource-exhaustion command is needed for the supported browser workflow. Do not run fork bombs or alter host cgroups merely to validate a document. External isolation integration needs its own reviewed runtime, minimal filesystem/network/credential policy, resource/cleanup proof and target-specific authorization. Dynamic CLI `--sandbox` remains disabled. The [current local boundary](../../docs/INSPECTOR.md#architecture-and-decisions) and [release limitations](../../LIMITATIONS.md) remain authoritative.
