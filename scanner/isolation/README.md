# Runtime Isolation — Portable Verifiable Subset (Gap 1)

This package provides a **fail-closed executor abstraction**. It is deliberately
honest about the difference between:

1. Controls that are **portably enforceable and verified here** (from Python,
   on any OS) — implemented by `RestrictedSubprocessBackend`.
2. **True kernel isolation** (seccomp, Linux namespaces, cgroup v2,
   gVisor/Firecracker) — represented only by committed *profile* config files
   and an **UNVERIFIED** stub backend that raises `NotImplementedError`.

> ⚠️ **`RestrictedSubprocessBackend` is NOT a security sandbox against a
> determined attacker.** It has no syscall filtering, no network isolation, and
> no filesystem namespacing. It reduces blast radius (runaway CPU/memory/output,
> ambient secrets, wandering working directory) for execution the caller has
> **explicitly acknowledged** as untrusted. Consistent with the existing
> `scanner/analyzer/sandbox_executor.py` gate, it refuses to run at all unless
> `acknowledge_untrusted=True` is passed.

## What is enforced, and where it is verified

| Control | Mechanism | Windows (this host) | Linux |
|---|---|:---:|:---:|
| Fail-closed refusal without ack | `acknowledge_untrusted` flag | ✅ VERIFIED (pytest) | ✅ (same code) |
| Wall-clock timeout + kill | `Popen.communicate(timeout=…)` + kill tree | ✅ VERIFIED (pytest) | ✅ |
| Output size cap | truncate stdout/stderr to `max_output_bytes` | ✅ VERIFIED (pytest) | ✅ |
| Working-dir confinement | `Popen(cwd=…)`, existence check | ✅ VERIFIED (pytest) | ✅ |
| Environment scrubbing (allowlist) | drop all env not on allowlist | ✅ VERIFIED (pytest) | ✅ |
| Kill whole process tree | POSIX `setsid` + `killpg`; `proc.kill()` fallback | ⚠️ single-process `kill()` only | ✅ session kill |
| RLIMIT_CPU / AS / NOFILE / FSIZE | `resource.setrlimit` in `preexec_fn` | ⛔ N/A — **cleanly skipped** (verified no-crash) | ✅ (see runbook) |
| `os.fork` + `os.setsid` | `preexec_fn` | ⛔ N/A — no `preexec_fn` | ✅ |
| **seccomp syscall filter** | `profiles/seccomp-allowlist.json` | ❌ **UNVERIFIED** | 🔬 requires Linux |
| **namespaces (user/pid/net/mnt/…)** | `profiles/namespace-launch-spec.yaml` | ❌ **UNVERIFIED** | 🔬 requires Linux |
| **cgroup v2 limits** | `profiles/cgroup-v2-limits.yaml` | ❌ **UNVERIFIED** | 🔬 requires cgroup v2 |
| **gVisor / Firecracker microVM** | `UnverifiedKernelIsolationBackend` (stub) | ❌ **UNVERIFIED — raises `NotImplementedError`** | 🔬 requires Linux host + KVM |

Legend: ✅ verified by tests on this Windows host · ⚠️ partial · ⛔ platform N/A,
skipped safely · ❌ not verified · 🔬 verifiable only on Linux.

**Explicit statement:** true kernel isolation (seccomp / namespaces / cgroups /
gVisor / Firecracker) is **NOT verified on Windows**. On Windows the profiles are
inert config files and the kernel-isolation backend is a stub that fails closed.

## Files in this package

```
scanner/isolation/
├── __init__.py                       # public API surface
├── executor.py                       # ExecutorBackend + RestrictedSubprocessBackend + stub
├── README.md                         # this file
└── profiles/
    ├── seccomp-allowlist.json        # OCI seccomp allowlist (default-deny)  [UNVERIFIED]
    ├── namespace-launch-spec.yaml    # unshare(1) namespace launch spec      [UNVERIFIED]
    └── cgroup-v2-limits.yaml         # cgroup v2 cpu/memory/pids limits       [UNVERIFIED]
```

## Public API

```python
from scanner.isolation import get_backend

backend = get_backend("restricted_subprocess")
result = backend.run(
    ["python", "-c", "print('hi')"],
    acknowledge_untrusted=True,      # REQUIRED — omitting it raises IsolationUnavailableError
    timeout_seconds=5,
    max_output_bytes=1_000_000,
    cwd="/some/confined/dir",
    cpu_seconds=5,                   # POSIX only; skipped on Windows
    address_space_bytes=512*1024*1024,
    max_open_files=64,
    max_file_size_bytes=10*1024*1024,
)
```

## Linux verification runbook (for the UNVERIFIED controls)

Run these on a Linux host to verify the profiles that cannot be verified on
Windows. None of this is executed automatically by the portable backend.

### 0. Prerequisites
```bash
uname -r                                  # kernel >= 5.10 recommended
grep cgroup2 /proc/filesystems            # expect: nodev cgroup2
mount | grep 'type cgroup2'               # unified hierarchy present
sysctl kernel.unprivileged_userns_clone   # 1 for rootless namespaces
```

### 1. seccomp allowlist
```bash
# With Docker/OCI runtime — attach the committed profile:
docker run --rm --security-opt no-new-privileges \
  --security-opt seccomp=scanner/isolation/profiles/seccomp-allowlist.json \
  python:3.11-slim python3 -I -c "print('seccomp ok')"

# Negative test — a denied syscall (socket) must fail:
docker run --rm \
  --security-opt seccomp=scanner/isolation/profiles/seccomp-allowlist.json \
  python:3.11-slim python3 -I -c \
  "import socket; socket.socket()"      # expect PermissionError / errno
```

### 2. namespaces (rootless unshare)
```bash
# Uses the reference_command documented in namespace-launch-spec.yaml:
unshare --user --map-root-user --mount --pid --fork --net --uts --ipc --cgroup \
  --mount-proc \
  env -i PATH=/usr/bin:/bin \
  /usr/bin/python3 -I -S -B -c \
  "import os,socket; print('pid', os.getpid()); \
   import urllib.request; \
   \
   # net namespace is empty -> outbound must fail:
   \
   ok=True; \
   \
   \
   \
   \
   print('uid', os.getuid())"
# Expect: PID small (new pid ns), no network reachability.
```

### 3. cgroup v2 limits
```bash
# Requires delegated subtree or root. Applies cgroup-v2-limits.yaml values:
sudo mkdir -p /sys/fs/cgroup/hf-scanner/untrusted
echo "+cpu +memory +pids" | sudo tee /sys/fs/cgroup/hf-scanner/cgroup.subtree_control
echo "50000 100000" | sudo tee /sys/fs/cgroup/hf-scanner/untrusted/cpu.max
echo 1073741824     | sudo tee /sys/fs/cgroup/hf-scanner/untrusted/memory.max
echo 0              | sudo tee /sys/fs/cgroup/hf-scanner/untrusted/memory.swap.max
echo 128            | sudo tee /sys/fs/cgroup/hf-scanner/untrusted/pids.max
# Move a shell in and try a fork bomb / big alloc; expect throttle/OOM/pids cap.
```

### 4. gVisor / Firecracker (microVM)
```bash
# gVisor:
docker run --rm --runtime=runsc python:3.11-slim python3 -c "print('gvisor ok')"
# Firecracker requires /dev/kvm and a jailer + rootfs image; out of scope here.
ls -l /dev/kvm                            # must exist for Firecracker
```
The `UnverifiedKernelIsolationBackend` in `executor.py` intentionally raises
`NotImplementedError` until one of the above is wired in and separately verified
on a Linux host with KVM.

## Running the portable tests

```bash
python -m pytest tests/test_executor.py -v
```
On Windows, the POSIX-rlimit test is skipped and a dedicated Windows test asserts
the rlimits are skipped without crashing.
