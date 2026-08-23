"""
Runtime protection for ML model loading.

Provides monkey-patching interceptors that scan models before they are loaded,
blocking malicious payloads from executing.

Usage:
    from scanner.runtime import enable_protection
    enable_protection()

Or via environment variable:
    HF_SCANNER_PROTECT=1 python my_script.py
"""

import os

from scanner.runtime.interceptor import RuntimeInterceptor

_interceptor: RuntimeInterceptor | None = None


def enable_protection(policy_path: str | None = None) -> RuntimeInterceptor:
    """Enable runtime protection by monkey-patching torch.load and transformers loaders.

    Args:
        policy_path: Optional path to a JSON/YAML policy file for the policy engine.

    Returns:
        The active RuntimeInterceptor instance.
    """
    global _interceptor
    if _interceptor is None:
        _interceptor = RuntimeInterceptor(policy_path=policy_path)
    _interceptor.activate()
    return _interceptor


def disable_protection() -> None:
    """Disable runtime protection and restore original functions."""
    global _interceptor
    if _interceptor is not None:
        _interceptor.deactivate()
        _interceptor = None


def is_protected() -> bool:
    """Check if runtime protection is currently active."""
    return _interceptor is not None and _interceptor.active


# Auto-activate if environment variable is set
if os.environ.get("HF_SCANNER_PROTECT", "").strip() in ("1", "true", "yes"):
    enable_protection(policy_path=os.environ.get("HF_SCANNER_POLICY_PATH"))
