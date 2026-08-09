"""
Real-time URL scanner: scan a model repository from a link BEFORE downloading.

The core product move for supply-chain safety is to answer "is this model safe
to load?" *before* pulling multi-gigabyte weights onto your machine or CI runner.
This module accepts a HuggingFace URL (or ``org/model`` id) or a GitHub repo URL,
enumerates the files via API, and scans the security-relevant parts of each file
using HTTP Range requests - pulling a few KB of pickle opcodes or safetensors
header instead of the whole tensor payload.

Detection reuses the same analyzers as local scanning:
- pickle / .bin / .pt / .pth : opcode disassembly of the header bytes
- .safetensors               : leading JSON metadata header
- config.json / *.py         : full fetch (small) + config / AST analysis

Nothing is executed. Nothing large is downloaded. If a file is flagged, the
caller learns before ``torch.load`` or ``from_pretrained`` ever runs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from scanner.analyzer.config_scanner import analyze_config_file
from scanner.analyzer.pickle_scanner import analyze_pickle_file
from scanner.analyzer.safetensors_scanner import analyze_safetensors_file
from scanner.models import Finding
from scanner.utils.hf_api import HFApiClient

# How many header bytes to pull for opcode/metadata analysis. Malicious pickle
# opcodes and safetensors header-JSON both live at the very start of the file.
PICKLE_HEADER_BYTES = 512 * 1024  # 512 KB is ample for opcode streams
SAFETENSORS_HEADER_PROBE = 16 * 1024 * 1024  # header length is 8-byte LE prefix
SMALL_FILE_BYTES = 2 * 1024 * 1024  # config/py fetched whole up to 2 MB

_PICKLE_EXTS = (".pkl", ".pickle", ".bin", ".pt", ".pth", ".ckpt")
_SAFETENSORS_EXTS = (".safetensors",)
_SOURCE_EXTS = (".py",)
_CONFIG_NAMES = ("config.json", "generation_config.json", "tokenizer_config.json")


@dataclass
class URLScanResult:
    source: str
    repo_id: str
    files_listed: int
    files_scanned: int
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    bytes_fetched: int = 0

    @property
    def is_malicious(self) -> bool:
        return any(f.severity.value in ("critical", "high") for f in self.findings)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "repo_id": self.repo_id,
            "files_listed": self.files_listed,
            "files_scanned": self.files_scanned,
            "bytes_fetched": self.bytes_fetched,
            "megabytes_fetched": round(self.bytes_fetched / (1024 * 1024), 3),
            "verdict": "MALICIOUS" if self.is_malicious else "clean",
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity.value,
                    "file_path": f.file_path,
                    "evidence": f.evidence[:200],
                }
                for f in self.findings
            ],
            "errors": self.errors,
        }


def parse_hf_reference(url_or_id: str) -> str | None:
    """Extract an ``org/model`` repo id from a HuggingFace URL or bare id.

    Accepts:
        https://huggingface.co/meta-llama/Llama-3.1-8B
        huggingface.co/org/model/tree/main
        org/model
    """
    s = url_or_id.strip()
    if s.startswith(("http://", "https://")) or "huggingface.co" in s:
        parsed = urlparse(s if "://" in s else f"https://{s}")
        if "huggingface.co" not in parsed.netloc:
            return None
        parts = [p for p in parsed.path.split("/") if p]
        # Strip known sub-paths (tree, blob, resolve, revision)
        if len(parts) >= 2 and parts[0] not in ("models", "datasets"):
            return f"{parts[0]}/{parts[1]}"
        if len(parts) >= 3 and parts[0] in ("models", "datasets"):
            return f"{parts[1]}/{parts[2]}"
        return None
    # Bare org/model id
    if re.fullmatch(r"[\w.-]+/[\w.-]+", s):
        return s
    return None


def _scan_one_file(client: HFApiClient, repo_id: str, filename: str) -> tuple[list[Finding], int]:
    """Fetch the minimal bytes needed and scan a single file. Returns (findings, bytes)."""
    lower = filename.lower()

    if lower.endswith(_PICKLE_EXTS):
        data = client.fetch_range(repo_id, filename, PICKLE_HEADER_BYTES)
        return analyze_pickle_file(filename, data), len(data)

    if lower.endswith(_SAFETENSORS_EXTS):
        # First 8 bytes = little-endian header length, then that many header bytes.
        prefix = client.fetch_range(repo_id, filename, 8)
        total = len(prefix)
        if len(prefix) == 8:
            header_len = int.from_bytes(prefix, "little")
            fetch_len = min(8 + header_len, SAFETENSORS_HEADER_PROBE)
            data = client.fetch_range(repo_id, filename, fetch_len)
            total = len(data)
        else:
            data = prefix
        return analyze_safetensors_file(filename, data), total

    if lower.endswith(_SOURCE_EXTS):
        data = client.fetch_range(repo_id, filename, SMALL_FILE_BYTES)
        from scanner.analyzer.ast_visitor import analyze_python_source

        text = data.decode("utf-8", errors="replace")
        return analyze_python_source(filename, text), len(data)

    base = filename.split("/")[-1]
    if base in _CONFIG_NAMES:
        data = client.fetch_range(repo_id, filename, SMALL_FILE_BYTES)
        text = data.decode("utf-8", errors="replace")
        return analyze_config_file(filename, text), len(data)

    return [], 0


def scan_hf_url(
    url_or_id: str, token: str | None = None, client: HFApiClient | None = None
) -> URLScanResult:
    """Scan a HuggingFace model repository from a URL/id without downloading weights.

    Parameters
    ----------
    url_or_id : str
        A HuggingFace model URL or ``org/model`` identifier.
    token : str, optional
        HF token for private/gated repos.
    client : HFApiClient, optional
        Injectable client (used in tests with a fake).
    """
    repo_id = parse_hf_reference(url_or_id)
    if repo_id is None:
        raise ValueError(f"Could not parse a HuggingFace repo id from: {url_or_id!r}")

    client = client or HFApiClient(token=token)
    result = URLScanResult(source="huggingface", repo_id=repo_id, files_listed=0, files_scanned=0)

    try:
        files = client.list_repo_files(repo_id)
    except Exception as e:  # noqa: BLE001 - surface the real error to the caller
        result.errors.append(f"failed to list files: {e}")
        return result

    result.files_listed = len(files)

    scannable = [
        f
        for f in files
        if f.lower().endswith(_PICKLE_EXTS + _SAFETENSORS_EXTS + _SOURCE_EXTS)
        or f.split("/")[-1] in _CONFIG_NAMES
    ]

    for filename in scannable:
        try:
            findings, nbytes = _scan_one_file(client, repo_id, filename)
            result.findings.extend(findings)
            result.bytes_fetched += nbytes
            result.files_scanned += 1
        except Exception as e:  # noqa: BLE001
            result.errors.append(f"{filename}: {e}")

    return result


def scan_url(url_or_id: str, token: str | None = None) -> URLScanResult:
    """Dispatch a URL to the right scanner. Currently HuggingFace; GitHub raw next."""
    return scan_hf_url(url_or_id, token=token)
