"""Fail-closed Linux syscall allowlist and process resource limits."""

import ctypes
import errno
import resource


def seal() -> str:
    """Disallow filesystem opens, network, execution and child processes after imports.

    libseccomp resolves architecture-specific syscall numbers. This is syscall
    containment, not a container/VM and not protection against kernel flaws.
    """
    resource.setrlimit(resource.RLIMIT_AS, (384 * 1024**2, 384 * 1024**2))
    resource.setrlimit(resource.RLIMIT_CPU, (4, 4))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        raise RuntimeError("no_new_privs unavailable")
    lib = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    ctx = lib.seccomp_init(0x00050000 | errno.EPERM)
    if not ctx:
        raise RuntimeError("seccomp initialization failed")
    try:
        for name in (
            "read",
            "write",
            "close",
            "fstat",
            "newfstatat",
            "lseek",
            "brk",
            "mmap",
            "mprotect",
            "munmap",
            "mremap",
            "madvise",
            "rt_sigaction",
            "rt_sigprocmask",
            "rt_sigreturn",
            "sigaltstack",
            "futex",
            "clock_gettime",
            "gettimeofday",
            "getpid",
            "gettid",
            "getrandom",
            "exit",
            "exit_group",
            "sched_yield",
            "restart_syscall",
            "getrusage",
        ):
            number = lib.seccomp_syscall_resolve_name(name.encode())
            if number >= 0 and lib.seccomp_rule_add(ctx, 0x7FFF0000, number, 0) != 0:
                raise RuntimeError("seccomp rule installation failed")
        if lib.seccomp_load(ctx) != 0:
            raise RuntimeError("seccomp unavailable")
    finally:
        lib.seccomp_release(ctx)
    return "Linux seccomp syscall allowlist + no_new_privs + RLIMIT"
