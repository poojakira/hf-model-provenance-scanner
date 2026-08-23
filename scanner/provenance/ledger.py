"""
scanner/provenance/ledger.py - Append-only signed event log with hash chain.

Provides a blockchain-like provenance ledger where each entry is:
- Hash-chained (SHA-256 of previous entry)
- Signed with Ed25519
- Stored as append-only JSON Lines (.jsonl)
- Thread-safe via threading.Lock
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from scanner.signing.ed25519 import ModelSigner

    _HAS_SIGNING = True
except ImportError:
    _HAS_SIGNING = False
    ModelSigner = None  # type: ignore[assignment,misc]

# Valid event types for the provenance ledger
VALID_EVENT_TYPES = frozenset(
    [
        "model_uploaded",
        "model_modified",
        "model_scanned",
        "model_deployed",
        "model_signed",
        "access_granted",
        "access_revoked",
    ]
)

# Sentinel hash for the first entry in a ledger (no previous entry)
GENESIS_HASH = "0" * 64


class LedgerEntry:
    """A single entry in the provenance ledger."""

    def __init__(
        self,
        timestamp: str,
        event_type: str,
        actor: str,
        subject: str,
        details: dict[str, Any],
        previous_hash: str,
        signature: str,
    ):
        self.timestamp = timestamp
        self.event_type = event_type
        self.actor = actor
        self.subject = subject
        self.details = details
        self.previous_hash = previous_hash
        self.signature = signature

    def to_dict(self) -> dict[str, Any]:
        """Serialize entry to a dictionary."""
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "actor": self.actor,
            "subject": self.subject,
            "details": self.details,
            "previous_hash": self.previous_hash,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LedgerEntry:
        """Deserialize entry from a dictionary."""
        return cls(
            timestamp=data["timestamp"],
            event_type=data["event_type"],
            actor=data["actor"],
            subject=data["subject"],
            details=data["details"],
            previous_hash=data["previous_hash"],
            signature=data["signature"],
        )

    def signable_payload(self) -> dict[str, Any]:
        """Return the dict that gets signed (everything except signature)."""
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "actor": self.actor,
            "subject": self.subject,
            "details": self.details,
            "previous_hash": self.previous_hash,
        }

    def compute_hash(self) -> str:
        """Compute SHA-256 hash of this entry (used as previous_hash for next entry)."""
        # Hash the full serialized entry including signature
        canonical = json.dumps(self.to_dict(), sort_keys=True).encode()
        return hashlib.sha256(canonical).hexdigest()


class ProvenanceLedger:
    """Append-only, hash-chained, Ed25519-signed provenance ledger.

    Usage:
        private_pem, public_pem = ModelSigner.generate_keypair()
        ledger = ProvenanceLedger("provenance.jsonl", private_pem, public_pem)
        ledger.append_event("model_uploaded", "alice", "gpt2", {"version": "1.0"})
        assert ledger.verify_chain()
    """

    def __init__(self, path: str | Path, private_key_pem: bytes, public_key_pem: bytes):
        """Initialize ledger.

        Args:
            path: Path to the .jsonl ledger file (created if doesn't exist).
            private_key_pem: Ed25519 private key PEM for signing entries.
            public_key_pem: Ed25519 public key PEM for verification.
        """
        self.path = Path(path)
        self._private_key_pem = private_key_pem
        self._public_key_pem = public_key_pem
        self._lock = threading.Lock()
        self._entries: list[LedgerEntry] = []
        self._last_hash: str = GENESIS_HASH

        # Load existing entries if file exists
        if self.path.exists():
            self._load()

    def _load(self) -> None:
        """Load existing entries from the JSONL file."""
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
                entry = LedgerEntry.from_dict(data)
                self._entries.append(entry)
                self._last_hash = entry.compute_hash()

    def append_event(
        self,
        event_type: str,
        actor: str,
        subject: str,
        details: dict[str, Any] | None = None,
    ) -> LedgerEntry:
        """Append a new event to the ledger.

        Args:
            event_type: One of the VALID_EVENT_TYPES.
            actor: Who performed the action (user ID, service name, etc.).
            subject: What model/resource is affected (model ID).
            details: Additional context as a dict.

        Returns:
            The created LedgerEntry.

        Raises:
            ValueError: If event_type is not valid.
        """
        if event_type not in VALID_EVENT_TYPES:
            raise ValueError(
                f"Invalid event_type '{event_type}'. Must be one of: {sorted(VALID_EVENT_TYPES)}"
            )

        if details is None:
            details = {}

        with self._lock:
            timestamp = datetime.now(tz=timezone.utc).isoformat()

            # Build the signable payload
            payload = {
                "timestamp": timestamp,
                "event_type": event_type,
                "actor": actor,
                "subject": subject,
                "details": details,
                "previous_hash": self._last_hash,
            }

            # Sign with Ed25519
            signature = ModelSigner.sign_manifest(self._private_key_pem, payload)

            # Create entry
            entry = LedgerEntry(
                timestamp=timestamp,
                event_type=event_type,
                actor=actor,
                subject=subject,
                details=details,
                previous_hash=self._last_hash,
                signature=signature,
            )

            # Update hash chain
            self._last_hash = entry.compute_hash()
            self._entries.append(entry)

            # Append to file
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry.to_dict(), sort_keys=True) + "\n")

            return entry

    def get_entries(self) -> list[LedgerEntry]:
        """Return a copy of all ledger entries."""
        with self._lock:
            return list(self._entries)

    def verify_chain(self) -> bool:
        """Verify the integrity of the entire hash chain and all signatures.

        Returns:
            True if the chain is valid, False otherwise.
        """
        with self._lock:
            return self._verify_chain_internal()

    def _verify_chain_internal(self) -> bool:
        """Internal chain verification (caller must hold lock)."""
        expected_previous_hash = GENESIS_HASH

        for entry in self._entries:
            # Check hash chain continuity
            if entry.previous_hash != expected_previous_hash:
                return False

            # Verify signature
            payload = entry.signable_payload()
            if not ModelSigner.verify_manifest(self._public_key_pem, payload, entry.signature):
                return False

            # Advance the chain
            expected_previous_hash = entry.compute_hash()

        return True

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)
