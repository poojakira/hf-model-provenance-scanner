"""Fail closed for dynamic execution of untrusted model repository code.

The previous Python subprocess harness did not provide an isolation boundary.
The experimental runsc path also exposed the host filesystem through its
convenience mode. Keep this API explicit until a separately verified container
runtime with a minimal root filesystem and mount policy is implemented.
"""


class DynamicExecutionUnavailableError(RuntimeError):
    """Dynamic scanning is unavailable without a verified isolation boundary."""


def sandbox_execute(file_path: str, source: str) -> list:
    """Reject execution regardless of backend selection or scanned source."""
    raise DynamicExecutionUnavailableError(
        "Dynamic execution is disabled: no verified isolation backend is configured. "
        "Run the default static scan without --sandbox."
    )


def _check_gvisor_available() -> bool:
    """A runsc binary alone does not establish a safe execution environment."""
    return False


if __name__ == "__main__":
    raise SystemExit("Dynamic execution is disabled: no verified isolation backend is configured")
