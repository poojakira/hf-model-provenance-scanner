"""Tests for scanner.telemetry module."""

import json
import logging
import os
import tempfile
import time

from scanner.telemetry import (
    JSONFormatter,
    ScanMetrics,
    TelemetryManager,
    init_telemetry,
    track_operation,
)


class TestJSONFormatter:
    """Verify JSON log output is valid JSON."""

    def test_format_produces_valid_json(self):
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="hello world",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["level"] == "INFO"
        assert parsed["message"] == "hello world"
        assert "timestamp" in parsed

    def test_format_includes_structured_data(self):
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.WARNING,
            pathname="",
            lineno=0,
            msg="event_name",
            args=(),
            exc_info=None,
        )
        record.structured_data = {"model_id": "bert-base", "count": 5}  # type: ignore[attr-defined]
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["model_id"] == "bert-base"
        assert parsed["count"] == 5

    def test_format_handles_exception(self):
        formatter = JSONFormatter()
        try:
            raise ValueError("test error")
        except ValueError:
            import sys

            exc_info = sys.exc_info()
        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="",
            lineno=0,
            msg="failed",
            args=(),
            exc_info=exc_info,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert "exception" in parsed
        assert "test error" in parsed["exception"]


class TestScanMetrics:
    """Verify timing metrics are captured."""

    def test_finalize_computes_duration(self):
        metrics = ScanMetrics(model_id="test-model")
        time.sleep(0.01)  # 10ms minimum
        metrics.finalize()
        assert metrics.duration_ms >= 10.0
        assert metrics.end_time > metrics.start_time

    def test_summary_returns_all_fields(self):
        metrics = ScanMetrics(model_id="bert-base")
        metrics.files_analyzed = 10
        metrics.bytes_fetched = 4096
        metrics.findings_count = 3
        metrics.findings_by_severity = {"high": 1, "medium": 2}
        metrics.operations = {"pickle_scan": 150.5, "ast_analysis": 42.3}
        metrics.finalize()

        summary = metrics.summary()
        assert summary["model_id"] == "bert-base"
        assert summary["files_analyzed"] == 10
        assert summary["bytes_fetched"] == 4096
        assert summary["findings_count"] == 3
        assert summary["findings_by_severity"] == {"high": 1, "medium": 2}
        assert "pickle_scan" in summary["operations"]
        assert summary["duration_ms"] >= 0

    def test_operations_tracked_via_context_manager(self):
        tm = TelemetryManager(enabled=True, log_level="DEBUG")
        metrics = tm.start_scan(model_id="test")
        with tm.track_operation("pickle_scan"):
            time.sleep(0.01)
        assert "pickle_scan" in metrics.operations
        assert metrics.operations["pickle_scan"] >= 10.0


class TestTelemetryManager:
    """Test the telemetry manager lifecycle."""

    def test_start_and_finish_scan(self):
        tm = TelemetryManager(enabled=True, log_level="DEBUG")
        metrics = tm.start_scan(model_id="gpt2")
        time.sleep(0.01)
        result = tm.finish_scan()
        assert result is not None
        assert result.duration_ms >= 10.0
        assert result.model_id == "gpt2"

    def test_summary_method(self):
        tm = TelemetryManager(enabled=True, log_level="DEBUG")
        tm.start_scan(model_id="model-x")
        tm.finish_scan()
        summary = tm.summary()
        assert summary["model_id"] == "model-x"
        assert "duration_ms" in summary

    def test_log_to_file_produces_valid_json_lines(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            log_path = f.name

        try:
            tm = TelemetryManager(enabled=True, log_file=log_path, log_level="DEBUG")
            tm.start_scan(model_id="test-file-log")
            tm.log_info("test_event", key="value")
            tm.finish_scan()

            # Force flush
            for handler in tm.logger.handlers:
                handler.flush()

            with open(log_path, encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]

            assert len(lines) >= 2  # at least start and finish
            for line in lines:
                parsed = json.loads(line)
                assert "timestamp" in parsed
                assert "level" in parsed
                assert "message" in parsed
        finally:
            tm.close()
            os.unlink(log_path)


class TestNoTelemetry:
    """Verify --no-telemetry suppresses output."""

    def test_disabled_produces_no_log_output(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            log_path = f.name

        try:
            tm = TelemetryManager(enabled=False, log_file=log_path, log_level="DEBUG")
            tm.start_scan(model_id="suppressed")
            tm.log_info("should_not_appear")
            tm.log_warning("also_suppressed")
            tm.log_error("even_errors_suppressed")
            tm.finish_scan()

            for handler in tm.logger.handlers:
                handler.flush()

            with open(log_path, encoding="utf-8") as f:
                content = f.read()

            assert content == ""
        finally:
            tm.close()
            os.unlink(log_path)

    def test_disabled_via_env_var(self, monkeypatch):
        monkeypatch.setenv("HF_SCANNER_TELEMETRY", "0")
        tm = init_telemetry()
        assert tm.enabled is False

    def test_enabled_by_default(self, monkeypatch):
        monkeypatch.delenv("HF_SCANNER_TELEMETRY", raising=False)
        tm = init_telemetry()
        assert tm.enabled is True

    def test_disabled_summary_returns_empty(self):
        tm = TelemetryManager(enabled=False)
        # No scan started
        assert tm.summary() == {}

    def test_track_operation_still_works_when_disabled(self):
        """track_operation should not raise when telemetry is disabled."""
        tm = TelemetryManager(enabled=False)
        tm.start_scan(model_id="noop")
        with tm.track_operation("test_op"):
            time.sleep(0.005)
        # Operations are still tracked in the metrics dataclass
        assert "test_op" in tm.metrics.operations


class TestLogLevelFiltering:
    """Verify log levels filter correctly."""

    def test_warning_level_filters_info(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            log_path = f.name

        try:
            tm = TelemetryManager(enabled=True, log_file=log_path, log_level="WARNING")
            tm.log_debug("debug_msg")
            tm.log_info("info_msg")
            tm.log_warning("warning_msg")
            tm.log_error("error_msg")

            for handler in tm.logger.handlers:
                handler.flush()

            with open(log_path, encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]

            messages = [json.loads(line)["message"] for line in lines]
            assert "debug_msg" not in messages
            assert "info_msg" not in messages
            assert "warning_msg" in messages
            assert "error_msg" in messages
        finally:
            tm.close()
            os.unlink(log_path)

    def test_error_level_filters_warning(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            log_path = f.name

        try:
            tm = TelemetryManager(enabled=True, log_file=log_path, log_level="ERROR")
            tm.log_warning("should_not_appear")
            tm.log_error("should_appear")

            for handler in tm.logger.handlers:
                handler.flush()

            with open(log_path, encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]

            messages = [json.loads(line)["message"] for line in lines]
            assert "should_not_appear" not in messages
            assert "should_appear" in messages
        finally:
            tm.close()
            os.unlink(log_path)

    def test_debug_level_shows_all(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            log_path = f.name

        try:
            tm = TelemetryManager(enabled=True, log_file=log_path, log_level="DEBUG")
            tm.log_debug("debug_visible")
            tm.log_info("info_visible")
            tm.log_warning("warning_visible")
            tm.log_error("error_visible")

            for handler in tm.logger.handlers:
                handler.flush()

            with open(log_path, encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]

            messages = [json.loads(line)["message"] for line in lines]
            assert "debug_visible" in messages
            assert "info_visible" in messages
            assert "warning_visible" in messages
            assert "error_visible" in messages
        finally:
            tm.close()
            os.unlink(log_path)


class TestModuleLevelConvenience:
    """Test the module-level track_operation context manager."""

    def test_track_operation_convenience(self):
        tm = init_telemetry(enabled=True, log_level="DEBUG")
        tm.start_scan(model_id="convenience-test")
        with track_operation("my_operation"):
            time.sleep(0.005)
        assert "my_operation" in tm.metrics.operations
        assert tm.metrics.operations["my_operation"] >= 5.0
