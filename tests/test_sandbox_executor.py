"""Regression tests for the disabled dynamic execution boundary."""

from unittest.mock import patch

import pytest

from scanner.analyzer.sandbox_executor import DynamicExecutionUnavailableError, sandbox_execute
from scanner.cli import main


@pytest.mark.parametrize("backend", ["subprocess", "gvisor", "firecracker", "unknown"])
def test_untrusted_code_is_never_executed(monkeypatch, backend):
    monkeypatch.setenv("HF_SANDBOX_BACKEND", backend)
    with patch("subprocess.run") as run:
        with pytest.raises(DynamicExecutionUnavailableError, match="disabled"):
            sandbox_execute("model.py", "__import__('os').system('id')")
    run.assert_not_called()


def test_cli_rejects_sandbox_before_loading_target(tmp_path, capsys):
    target = tmp_path / "model.py"
    target.write_text("__import__('os').system('id')", encoding="utf-8")
    with patch("subprocess.run") as run:
        with pytest.raises(SystemExit) as error:
            main([str(target), "--mode", "local", "--sandbox"])
    assert error.value.code == 2
    assert "disabled" in capsys.readouterr().err
    run.assert_not_called()
