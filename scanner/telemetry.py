"""Production telemetry and structured logging for hf-scanner.

Uses only stdlib (logging + json). No external dependencies.
Emits JSON lines to stderr or a configurable log file.
Respects opt-out via --no-telemetry flag or HF_SCANNER_TELEMETRY=0 env var.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

# ─── JSON Formatter ───────────────────────────────────────────────────────────


class JSONFormatter(logging.Formatter):
    """Formats log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Merge any extra structured data attached to the record
        if hasattr(record, "structured_data"):
            log_entry.update(record.structured_data)
        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = str(record.exc_info[1])
        return json.dumps(log_entry, default=str)


# ─── ScanMetrics Dataclass ────────────────────────────────────────────────────


@dataclass
class ScanMetrics:
    """Collects timing and count metrics for a scan operation."""

    model_id: str = ""
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    duration_ms: float = 0.0
    files_analyzed: int = 0
    bytes_fetched: int = 0
    findings_count: int = 0
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    operations: dict[str, float] = field(default_factory=dict)

    def finalize(self) -> None:
        """Mark the scan as complete and compute duration."""
        self.end_time = time.time()
        self.duration_ms = (self.end_time - self.start_time) * 1000.0

    def summary(self) -> dict[str, Any]:
        """Return all collected metrics as a dict."""
        return {
            "model_id": self.model_id,
            "duration_ms": round(self.duration_ms, 2),
            "files_analyzed": self.files_analyzed,
            "bytes_fetched": self.bytes_fetched,
            "findings_count": self.findings_count,
            "findings_by_severity": self.findings_by_severity,
            "operations": {k: round(v, 2) for k, v in self.operations.items()},
        }


# ─── Telemetry Manager ───────────────────────────────────────────────────────


class TelemetryManager:
    """Central telemetry controller.

    Handles structured logging and metric collection.
    Can be disabled via the `enabled` flag.
    """

    _instance_counter: int = 0

    def __init__(
        self,
        enabled: bool = True,
        log_file: str | None = None,
        log_level: str = "WARNING",
    ) -> None:
        self.enabled = enabled
        self._metrics: ScanMetrics | None = None
        # Use unique logger name per instance to avoid shared state
        TelemetryManager._instance_counter += 1
        logger_name = f"hf_scanner.telemetry.{TelemetryManager._instance_counter}"
        self._logger = logging.getLogger(logger_name)
        self._logger.propagate = False
        # Remove existing handlers to avoid duplicates
        self._logger.handlers.clear()

        if self.enabled:
            level = getattr(logging, log_level.upper(), logging.WARNING)
            self._logger.setLevel(level)
            handler: logging.Handler
            if log_file:
                handler = logging.FileHandler(log_file, encoding="utf-8")
            else:
                handler = logging.StreamHandler(sys.stderr)
            handler.setFormatter(JSONFormatter())
            self._logger.addHandler(handler)
        else:
            self._logger.setLevel(logging.CRITICAL + 1)  # suppress all

    @property
    def logger(self) -> logging.Logger:
        return self._logger

    def start_scan(self, model_id: str = "") -> ScanMetrics:
        """Begin tracking metrics for a scan."""
        self._metrics = ScanMetrics(model_id=model_id)
        self.log_info("scan_started", model_id=model_id)
        return self._metrics

    def finish_scan(self) -> ScanMetrics | None:
        """Finalize the current scan metrics and emit summary."""
        if self._metrics is None:
            return None
        self._metrics.finalize()
        self.log_info("scan_completed", **self._metrics.summary())
        return self._metrics

    @property
    def metrics(self) -> ScanMetrics | None:
        return self._metrics

    @contextmanager
    def track_operation(self, name: str) -> Generator[None, None, None]:
        """Context manager to time a named operation."""
        start = time.time()
        try:
            yield
        finally:
            elapsed_ms = (time.time() - start) * 1000.0
            if self._metrics is not None:
                self._metrics.operations[name] = elapsed_ms
            self.log_debug("operation_timed", operation=name, duration_ms=round(elapsed_ms, 2))

    # ─── Logging helpers ──────────────────────────────────────────────────

    def _log(self, level: int, event: str, **kwargs: Any) -> None:
        if not self.enabled:
            return
        if not self._logger.isEnabledFor(level):
            return
        record = self._logger.makeRecord(
            name=self._logger.name,
            level=level,
            fn="",
            lno=0,
            msg=event,
            args=(),
            exc_info=None,
        )
        record.structured_data = kwargs  # type: ignore[attr-defined]
        self._logger.handle(record)

    def log_debug(self, event: str, **kwargs: Any) -> None:
        self._log(logging.DEBUG, event, **kwargs)

    def log_info(self, event: str, **kwargs: Any) -> None:
        self._log(logging.INFO, event, **kwargs)

    def log_warning(self, event: str, **kwargs: Any) -> None:
        self._log(logging.WARNING, event, **kwargs)

    def log_error(self, event: str, **kwargs: Any) -> None:
        self._log(logging.ERROR, event, **kwargs)

    def summary(self) -> dict[str, Any]:
        """Return collected metrics as a dict (empty if no scan started)."""
        if self._metrics is None:
            return {}
        return self._metrics.summary()

    def close(self) -> None:
        """Close and remove all log handlers (needed for file cleanup on Windows)."""
        for handler in self._logger.handlers[:]:
            handler.close()
            self._logger.removeHandler(handler)


# ─── Module-level convenience ─────────────────────────────────────────────────

_global_telemetry: TelemetryManager | None = None


def init_telemetry(
    enabled: bool | None = None,
    log_file: str | None = None,
    log_level: str = "WARNING",
) -> TelemetryManager:
    """Initialize the global telemetry manager.

    Respects HF_SCANNER_TELEMETRY=0 env var if `enabled` is not explicitly set.
    """
    global _global_telemetry
    if enabled is None:
        env_val = os.environ.get("HF_SCANNER_TELEMETRY", "1")
        enabled = env_val not in ("0", "false", "no", "off")
    _global_telemetry = TelemetryManager(enabled=enabled, log_file=log_file, log_level=log_level)
    return _global_telemetry


def get_telemetry() -> TelemetryManager:
    """Get the global telemetry manager (initializes with defaults if needed)."""
    global _global_telemetry
    if _global_telemetry is None:
        _global_telemetry = init_telemetry()
    return _global_telemetry


@contextmanager
def track_operation(name: str) -> Generator[None, None, None]:
    """Module-level convenience for timing operations."""
    with get_telemetry().track_operation(name):
        yield
