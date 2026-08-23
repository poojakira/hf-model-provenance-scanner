"""
Runtime interceptor that monkey-patches torch.load() and transformers loading functions.

Inspects pickle/model files BEFORE they are loaded, blocking execution if the
scanner detects critical findings (e.g., embedded code execution payloads).

Uses try/except ImportError so torch and transformers remain optional dependencies.
"""

import io
import logging
import os
import sys
from pathlib import Path

from scanner.analyzer.pickle_scanner import scan_pickle_bytes
from scanner.models import Finding, Severity

logger = logging.getLogger(__name__)


class SecurityError(Exception):
    """Raised when a model file is blocked from loading due to security findings."""

    def __init__(self, message: str, findings: list[Finding] | None = None):
        super().__init__(message)
        self.findings = findings or []


class RuntimeInterceptor:
    """Monkey-patching interceptor for ML model loading functions.

    Wraps torch.load() and transformers.AutoModel.from_pretrained() to scan
    model files before they are deserialized.
    """

    def __init__(self, policy_path: str | None = None):
        self.active = False
        self.policy_path = policy_path
        self._original_torch_load = None
        self._original_from_pretrained = None
        self._blocked_count = 0
        self._scanned_count = 0

    def activate(self) -> None:
        """Activate interception by monkey-patching target functions."""
        if self.active:
            return
        self._patch_torch_load()
        self._patch_transformers()
        self.active = True
        logger.info("Runtime protection activated")

    def deactivate(self) -> None:
        """Deactivate interception and restore original functions."""
        if not self.active:
            return
        self._unpatch_torch_load()
        self._unpatch_transformers()
        self.active = False
        logger.info("Runtime protection deactivated")

    @property
    def stats(self) -> dict:
        """Return interception statistics."""
        return {
            "scanned": self._scanned_count,
            "blocked": self._blocked_count,
            "active": self.active,
        }

    def _scan_file(self, file_path: str | Path) -> list[Finding]:
        """Scan a file using the pickle scanner. Returns list of findings."""
        path = Path(file_path)
        if not path.exists():
            return []

        try:
            data = path.read_bytes()
            findings = scan_pickle_bytes(str(path), data)
            self._scanned_count += 1
            return findings
        except Exception as e:
            logger.warning("Scanner error on %s: %s", path, e)
            return []

    def _scan_bytes(self, data: bytes) -> list[Finding]:
        """Scan bytes content using the pickle scanner. Returns list of findings."""
        try:
            findings = scan_pickle_bytes("<stream>", data)
            self._scanned_count += 1
            return findings
        except Exception as e:
            logger.warning("Scanner error on bytes input: %s", e)
            return []

    def _has_critical_findings(self, findings: list[Finding]) -> bool:
        """Check if any findings are critical severity."""
        return any(f.severity == Severity.CRITICAL for f in findings)

    def _check_and_block(self, findings: list[Finding], source: str) -> None:
        """Raise SecurityError if critical findings detected."""
        if self._has_critical_findings(findings):
            self._blocked_count += 1
            critical = [f for f in findings if f.severity == Severity.CRITICAL]
            messages = [f.message for f in critical[:3]]
            raise SecurityError(
                f"Blocked loading of '{source}': {len(critical)} critical "
                f"security finding(s) detected. First: {messages[0] if messages else 'unknown'}",
                findings=critical,
            )

    # --- torch.load() patching ---

    def _patch_torch_load(self) -> None:
        """Monkey-patch torch.load() if torch is available."""
        try:
            import torch  # noqa: F401
        except ImportError:
            # torch not installed; check if it's mocked in sys.modules
            if "torch" not in sys.modules:
                return

        torch_module = sys.modules.get("torch")
        if torch_module is None:
            return

        if not hasattr(torch_module, "load"):
            return

        self._original_torch_load = torch_module.load

        interceptor = self

        def safe_torch_load(f, *args, **kwargs):
            """Intercepted torch.load that scans before loading."""
            findings = []

            if isinstance(f, str | os.PathLike):
                findings = interceptor._scan_file(f)
                source = str(f)
            elif isinstance(f, io.BufferedReader | io.FileIO):
                # Read content, scan, then seek back
                if hasattr(f, "name"):
                    findings = interceptor._scan_file(f.name)
                    source = f.name
                else:
                    pos = f.tell()
                    data = f.read()
                    f.seek(pos)
                    findings = interceptor._scan_bytes(data)
                    source = "<stream>"
            elif isinstance(f, io.BytesIO):
                pos = f.tell()
                data = f.getvalue()
                f.seek(pos)
                findings = interceptor._scan_bytes(data)
                source = "<bytes>"
            else:
                source = str(f)
                # Try scanning as path
                try:
                    findings = interceptor._scan_file(str(f))
                except Exception:
                    pass

            interceptor._check_and_block(findings, source)

            # No critical findings - proceed with original load
            return interceptor._original_torch_load(f, *args, **kwargs)

        torch_module.load = safe_torch_load

    def _unpatch_torch_load(self) -> None:
        """Restore original torch.load()."""
        if self._original_torch_load is None:
            return
        torch_module = sys.modules.get("torch")
        if torch_module is not None:
            torch_module.load = self._original_torch_load
        self._original_torch_load = None

    # --- transformers.AutoModel.from_pretrained() patching ---

    def _patch_transformers(self) -> None:
        """Monkey-patch transformers.AutoModel.from_pretrained() if available."""
        try:
            import transformers  # noqa: F401
        except ImportError:
            if "transformers" not in sys.modules:
                return

        transformers_module = sys.modules.get("transformers")
        if transformers_module is None:
            return

        auto_model = getattr(transformers_module, "AutoModel", None)
        if auto_model is None:
            return

        self._original_from_pretrained = auto_model.from_pretrained

        interceptor = self

        @classmethod  # type: ignore[misc]
        def safe_from_pretrained(cls, pretrained_model_name_or_path, *args, **kwargs):
            """Intercepted from_pretrained that scans model directory before loading."""
            model_path = Path(str(pretrained_model_name_or_path))
            findings = []

            if model_path.is_dir():
                # Scan all pickle-like files in the model directory
                for ext in ("*.pkl", "*.pt", "*.pth", "*.bin"):
                    for f in model_path.glob(ext):
                        file_findings = interceptor._scan_file(f)
                        findings.extend(file_findings)
            elif model_path.is_file():
                findings = interceptor._scan_file(model_path)

            source = str(pretrained_model_name_or_path)
            interceptor._check_and_block(findings, source)

            # No critical findings - proceed with original load
            return interceptor._original_from_pretrained.__func__(
                cls, pretrained_model_name_or_path, *args, **kwargs
            )

        auto_model.from_pretrained = safe_from_pretrained

    def _unpatch_transformers(self) -> None:
        """Restore original transformers.AutoModel.from_pretrained()."""
        if self._original_from_pretrained is None:
            return
        transformers_module = sys.modules.get("transformers")
        if transformers_module is not None:
            auto_model = getattr(transformers_module, "AutoModel", None)
            if auto_model is not None:
                auto_model.from_pretrained = self._original_from_pretrained
        self._original_from_pretrained = None
