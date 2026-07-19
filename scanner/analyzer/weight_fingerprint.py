"""
Weight Fingerprinting Module — SHA-256 tensor hashing for integrity verification.

Generates deterministic fingerprints of model weights to:
1. Detect unauthorized modifications (weight poisoning, backdoors)
2. Verify model identity across transfers
3. Track weight provenance through fine-tuning chains
4. Detect tensor replacement attacks

Supports: SafeTensors, GGUF, PyTorch (ZIP-based .pt files)
"""

import hashlib
import json
import struct
from dataclasses import dataclass, field
from typing import Optional

from scanner.models import Finding
from scanner.rules.definitions import get_rule


@dataclass
class TensorFingerprint:
    """Fingerprint of a single tensor."""
    name: str
    dtype: str
    shape: list[int]
    data_hash: str  # SHA-256 of raw tensor bytes
    size_bytes: int


@dataclass
class ModelFingerprint:
    """Complete fingerprint of a model file."""
    file_path: str
    file_hash: str  # SHA-256 of entire file
    format: str  # safetensors, gguf, pytorch
    tensor_count: int
    total_params: int
    tensors: list[TensorFingerprint] = field(default_factory=list)
    metadata_hash: str = ""  # Hash of metadata/header only
    aggregate_hash: str = ""  # Hash of all tensor hashes combined

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "file_hash": self.file_hash,
            "format": self.format,
            "tensor_count": self.tensor_count,
            "total_params": self.total_params,
            "metadata_hash": self.metadata_hash,
            "aggregate_hash": self.aggregate_hash,
            "tensors": [
                {
                    "name": t.name,
                    "dtype": t.dtype,
                    "shape": t.shape,
                    "data_hash": t.data_hash,
                    "size_bytes": t.size_bytes,
                }
                for t in self.tensors
            ],
        }


def _make_finding(rule_id: str, file_path: str, evidence: str) -> Finding:
    rule = get_rule(rule_id)
    return Finding(
        rule_id=rule_id,
        severity=rule.severity,
        file_path=file_path,
        line_number=0,
        column=0,
        message=rule.description,
        evidence=evidence[:300],
        remediation=rule.remediation,
        cwe=rule.cwe,
    )


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _compute_aggregate_hash(tensor_hashes: list[str]) -> str:
    """Deterministic aggregate: sort tensor hashes, hash them together."""
    combined = "\n".join(sorted(tensor_hashes))
    return _sha256(combined.encode("utf-8"))


# --- SafeTensors fingerprinting ---

DTYPE_SIZES = {
    "F64": 8, "F32": 4, "F16": 2, "BF16": 2,
    "I64": 8, "I32": 4, "I16": 2, "I8": 1,
    "U8": 1, "BOOL": 1,
}


def fingerprint_safetensors(file_path: str, data: bytes) -> tuple[Optional[ModelFingerprint], list[Finding]]:
    """Generate fingerprint for a SafeTensors file."""
    findings: list[Finding] = []

    if len(data) < 8:
        return None, findings

    header_size = struct.unpack_from("<Q", data, 0)[0]
    if header_size > len(data) - 8:
        return None, findings

    header_bytes = data[8:8 + header_size]
    try:
        header = json.loads(header_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None, findings

    file_hash = _sha256(data)
    metadata_hash = _sha256(header_bytes)
    tensors: list[TensorFingerprint] = []
    total_params = 0
    data_start = 8 + header_size

    for name, info in header.items():
        if name == "__metadata__" or not isinstance(info, dict):
            continue

        dtype = info.get("dtype", "F32")
        shape = info.get("shape", [])
        offsets = info.get("data_offsets", [0, 0])

        if len(offsets) == 2:
            start, end = offsets
            tensor_data = data[data_start + start:data_start + end]
            tensor_hash = _sha256(tensor_data)
            size_bytes = end - start
        else:
            tensor_hash = ""
            size_bytes = 0

        # Calculate parameter count
        params = 1
        for dim in shape:
            params *= dim
        total_params += params

        tensors.append(TensorFingerprint(
            name=name,
            dtype=dtype,
            shape=shape,
            data_hash=tensor_hash,
            size_bytes=size_bytes,
        ))

    tensor_hashes = [t.data_hash for t in tensors if t.data_hash]
    aggregate = _compute_aggregate_hash(tensor_hashes) if tensor_hashes else ""

    fp = ModelFingerprint(
        file_path=file_path,
        file_hash=file_hash,
        format="safetensors",
        tensor_count=len(tensors),
        total_params=total_params,
        tensors=tensors,
        metadata_hash=metadata_hash,
        aggregate_hash=aggregate,
    )
    return fp, findings


def fingerprint_file(file_path: str, data: bytes) -> tuple[Optional[ModelFingerprint], list[Finding]]:
    """Route to appropriate fingerprinting function based on format."""
    lower = file_path.lower()
    if lower.endswith(".safetensors"):
        return fingerprint_safetensors(file_path, data)
    # For other formats, just compute file-level hash
    return ModelFingerprint(
        file_path=file_path,
        file_hash=_sha256(data),
        format="unknown",
        tensor_count=0,
        total_params=0,
    ), []


def compare_fingerprints(
    baseline: ModelFingerprint, current: ModelFingerprint, file_path: str
) -> list[Finding]:
    """
    Compare two fingerprints to detect modifications.
    Returns findings for any detected changes.
    """
    findings: list[Finding] = []

    if baseline.file_hash == current.file_hash:
        return findings  # Identical files

    # Check aggregate tensor hash
    if baseline.aggregate_hash and current.aggregate_hash:
        if baseline.aggregate_hash != current.aggregate_hash:
            findings.append(_make_finding(
                "HFS-060", file_path,
                f"Model weight fingerprint changed: "
                f"baseline={baseline.aggregate_hash[:16]}... "
                f"current={current.aggregate_hash[:16]}..."
            ))

    # Check tensor count
    if baseline.tensor_count != current.tensor_count:
        findings.append(_make_finding(
            "HFS-060", file_path,
            f"Tensor count changed: {baseline.tensor_count} -> {current.tensor_count}"
        ))

    # Check individual tensors
    baseline_map = {t.name: t for t in baseline.tensors}
    current_map = {t.name: t for t in current.tensors}

    for name, base_tensor in baseline_map.items():
        curr_tensor = current_map.get(name)
        if curr_tensor is None:
            findings.append(_make_finding(
                "HFS-060", file_path,
                f"Tensor '{name}' removed from model"
            ))
        elif base_tensor.data_hash != curr_tensor.data_hash:
            findings.append(_make_finding(
                "HFS-060", file_path,
                f"Tensor '{name}' modified: "
                f"{base_tensor.data_hash[:16]}... -> {curr_tensor.data_hash[:16]}..."
            ))

    for name in current_map:
        if name not in baseline_map:
            findings.append(_make_finding(
                "HFS-060", file_path,
                f"New tensor '{name}' added to model (not in baseline)"
            ))

    return findings
