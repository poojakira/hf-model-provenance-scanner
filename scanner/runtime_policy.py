"""Runtime sandbox policy generation for hardened model execution."""

import json


def build_runtime_policy(target: str) -> dict:
    """Build a hardened Docker/K8s sandbox policy for model execution.

    Returns a JSON-serializable policy dictionary with security constraints.
    """
    policy = {
        "apiVersion": "hf-scanner/v1",
        "kind": "RuntimePolicy",
        "metadata": {
            "target": target,
            "generator": "hf-scanner/0.2.0",
        },
        "spec": {
            "container": {
                "image": "python:3.11-slim",
                "readOnlyRootFilesystem": True,
                "runAsNonRoot": True,
                "runAsUser": 65534,
                "allowPrivilegeEscalation": False,
                "capabilities": {
                    "drop": ["ALL"],
                },
            },
            "network": {
                "egressPolicy": "deny",
                "allowedEgress": [],
            },
            "filesystem": {
                "readOnlyPaths": ["/model", "/usr", "/lib"],
                "writablePaths": ["/tmp", "/output"],
                "blockedPaths": ["/proc/kcore", "/sys"],
            },
            "resources": {
                "limits": {
                    "memory": "4Gi",
                    "cpu": "2",
                    "ephemeral-storage": "10Gi",
                },
                "requests": {
                    "memory": "512Mi",
                    "cpu": "500m",
                },
            },
            "seccomp": {
                "type": "RuntimeDefault",
            },
            "apparmor": {
                "type": "RuntimeDefault",
            },
            "process": {
                "noNewPrivileges": True,
                "blockedSyscalls": [
                    "ptrace", "mount", "umount2", "pivot_root",
                    "kexec_load", "open_by_handle_at",
                ],
            },
        },
    }
    return policy


def format_runtime_policy(target: str) -> str:
    """Format the runtime policy as a JSON string."""
    policy = build_runtime_policy(target)
    return json.dumps(policy, indent=2)
