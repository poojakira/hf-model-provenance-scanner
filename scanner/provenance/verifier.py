"""
scanner/provenance/verifier.py - Independent ledger verification.

Provides standalone verification of a provenance ledger file without
requiring the original ProvenanceLedger instance. Checks hash chain
continuity, signature validity, timestamp ordering, and detects
tampering, deletion, reordering, and forged entries.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from scanner.signing.ed25519 import ModelSigner

from .ledger import GENESIS_HASH, VALID_EVENT_TYPES


@dataclass
class VerificationResult:
    """Detailed result of ledger verification."""

    valid: bool = True
    total_entries: int = 0
    checks_passed: list[str] = field(default_factory=list)
    checks_failed: list[str] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)

    def add_pass(self, check: str) -> None:
        self.checks_passed.append(check)

    def add_failure(self, check: str, detail: str = "", index: int | None = None) -> None:
        self.valid = False
        self.checks_failed.append(check)
        error = {"check": check, "detail": detail}
        if index is not None:
            error["entry_index"] = index
        self.errors.append(error)

    @property
    def summary(self) -> str:
        status = "VALID" if self.valid else "INVALID"
        return (
            f"Ledger verification: {status} | "
            f"{self.total_entries} entries | "
            f"{len(self.checks_passed)} passed | "
            f"{len(self.checks_failed)} failed"
        )


def verify_ledger(path: str | Path, public_key_pem: bytes) -> VerificationResult:
    """Independently verify a provenance ledger file.

    Checks:
    - Hash chain continuity (each entry's previous_hash matches the hash of the prior entry)
    - Signature validity (each entry's Ed25519 signature is valid)
    - Timestamp ordering (entries are in chronological order)
    - No gaps in the chain (first entry references genesis hash)
    - Valid event types

    Detects:
    - Tampering (modified entries break hash chain or signature)
    - Deletion (missing entries cause hash chain discontinuity)
    - Reordering (out-of-order entries break hash chain)
    - Forged entries (invalid signatures)

    Args:
        path: Path to the .jsonl ledger file.
        public_key_pem: Ed25519 public key PEM for signature verification.

    Returns:
        VerificationResult with detailed pass/fail information.
    """
    result = VerificationResult()
    path = Path(path)

    # Check file exists
    if not path.exists():
        result.add_failure("file_exists", f"Ledger file not found: {path}")
        return result
    result.add_pass("file_exists")

    # Load entries
    entries: list[dict[str, Any]] = []
    try:
        with open(path, encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    entries.append(data)
                except json.JSONDecodeError as e:
                    result.add_failure("json_parse", f"Line {line_num}: {e}", index=line_num - 1)
    except OSError as e:
        result.add_failure("file_read", str(e))
        return result

    result.total_entries = len(entries)

    if not entries:
        result.add_pass("empty_ledger_valid")
        return result

    # Check required fields
    required_fields = {
        "timestamp",
        "event_type",
        "actor",
        "subject",
        "details",
        "previous_hash",
        "signature",
    }
    for i, entry_data in enumerate(entries):
        missing = required_fields - set(entry_data.keys())
        if missing:
            result.add_failure("required_fields", f"Entry {i} missing fields: {missing}", index=i)
    if not result.valid:
        return result
    result.add_pass("required_fields")

    # Check valid event types
    event_type_valid = True
    for i, entry_data in enumerate(entries):
        if entry_data["event_type"] not in VALID_EVENT_TYPES:
            result.add_failure(
                "event_type_valid",
                f"Entry {i}: invalid event_type '{entry_data['event_type']}'",
                index=i,
            )
            event_type_valid = False
    if event_type_valid:
        result.add_pass("event_type_valid")

    # Check genesis hash
    if entries[0]["previous_hash"] != GENESIS_HASH:
        result.add_failure(
            "genesis_hash",
            f"First entry's previous_hash should be genesis ({GENESIS_HASH}), "
            f"got: {entries[0]['previous_hash']}",
            index=0,
        )
    else:
        result.add_pass("genesis_hash")

    # Check hash chain continuity
    chain_valid = True
    expected_previous_hash = GENESIS_HASH
    for i, entry_data in enumerate(entries):
        if entry_data["previous_hash"] != expected_previous_hash:
            result.add_failure(
                "hash_chain_continuity",
                f"Entry {i}: expected previous_hash={expected_previous_hash[:16]}..., "
                f"got={entry_data['previous_hash'][:16]}...",
                index=i,
            )
            chain_valid = False
            break
        # Compute hash of this entry for next iteration
        canonical = json.dumps(entry_data, sort_keys=True).encode()
        expected_previous_hash = hashlib.sha256(canonical).hexdigest()

    if chain_valid:
        result.add_pass("hash_chain_continuity")

    # Check signatures
    sig_valid = True
    for i, entry_data in enumerate(entries):
        payload = {
            "timestamp": entry_data["timestamp"],
            "event_type": entry_data["event_type"],
            "actor": entry_data["actor"],
            "subject": entry_data["subject"],
            "details": entry_data["details"],
            "previous_hash": entry_data["previous_hash"],
        }
        if not ModelSigner.verify_manifest(public_key_pem, payload, entry_data["signature"]):
            result.add_failure(
                "signature_valid",
                f"Entry {i}: invalid Ed25519 signature",
                index=i,
            )
            sig_valid = False
    if sig_valid:
        result.add_pass("signature_valid")

    # Check timestamp ordering
    timestamps_ordered = True
    prev_ts = None
    for i, entry_data in enumerate(entries):
        try:
            ts = datetime.fromisoformat(entry_data["timestamp"])
            if prev_ts is not None and ts < prev_ts:
                result.add_failure(
                    "timestamp_ordering",
                    f"Entry {i}: timestamp {entry_data['timestamp']} is before "
                    f"previous entry's timestamp",
                    index=i,
                )
                timestamps_ordered = False
            prev_ts = ts
        except ValueError as e:
            result.add_failure(
                "timestamp_format",
                f"Entry {i}: invalid ISO 8601 timestamp: {e}",
                index=i,
            )
            timestamps_ordered = False

    if timestamps_ordered:
        result.add_pass("timestamp_ordering")

    return result
