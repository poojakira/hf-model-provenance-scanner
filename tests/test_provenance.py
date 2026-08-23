"""
tests/test_provenance.py - Comprehensive tests for the cryptographic provenance ledger.

Tests cover:
- Event appending with hash chain
- Chain verification for valid ledgers
- Tamper detection (modified, deleted, reordered entries)
- Ed25519 signature validity
- Query functionality
- Thread safety under concurrent writes
"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from scanner.provenance.ledger import (
    GENESIS_HASH,
    VALID_EVENT_TYPES,
    LedgerEntry,
    ProvenanceLedger,
)
from scanner.provenance.query import (
    full_history,
    query_by_actor,
    query_by_model,
    query_by_time_range,
    who_modified,
)
from scanner.provenance.verifier import verify_ledger
from scanner.signing.ed25519 import ModelSigner


@pytest.fixture
def keypair():
    """Generate a fresh Ed25519 keypair for testing."""
    private_pem, public_pem = ModelSigner.generate_keypair()
    return private_pem, public_pem


@pytest.fixture
def ledger_path(tmp_path):
    """Return a temporary path for a ledger file."""
    return tmp_path / "test_provenance.jsonl"


@pytest.fixture
def ledger(ledger_path, keypair):
    """Create a fresh ProvenanceLedger instance."""
    private_pem, public_pem = keypair
    return ProvenanceLedger(ledger_path, private_pem, public_pem)


class TestEventAppending:
    """Test that events append correctly with hash chain."""

    def test_append_single_event(self, ledger):
        """Single event appends with correct structure."""
        entry = ledger.append_event("model_uploaded", "alice", "gpt2", {"version": "1.0"})
        assert entry.event_type == "model_uploaded"
        assert entry.actor == "alice"
        assert entry.subject == "gpt2"
        assert entry.details == {"version": "1.0"}
        assert entry.previous_hash == GENESIS_HASH
        assert entry.signature != ""

    def test_append_multiple_events_hash_chain(self, ledger):
        """Multiple events form a proper hash chain."""
        entry1 = ledger.append_event("model_uploaded", "alice", "gpt2")
        entry2 = ledger.append_event("model_modified", "bob", "gpt2")
        entry3 = ledger.append_event("model_scanned", "scanner-svc", "gpt2")

        # First entry references genesis
        assert entry1.previous_hash == GENESIS_HASH
        # Second entry references hash of first
        assert entry2.previous_hash == entry1.compute_hash()
        # Third entry references hash of second
        assert entry3.previous_hash == entry2.compute_hash()

    def test_append_creates_file(self, ledger_path, keypair):
        """Appending events creates the JSONL file."""
        private_pem, public_pem = keypair
        ledger = ProvenanceLedger(ledger_path, private_pem, public_pem)
        assert not ledger_path.exists()
        ledger.append_event("model_uploaded", "alice", "gpt2")
        assert ledger_path.exists()

    def test_append_jsonl_format(self, ledger, ledger_path):
        """Events are stored as valid JSON Lines."""
        ledger.append_event("model_uploaded", "alice", "gpt2")
        ledger.append_event("model_modified", "bob", "gpt2")

        lines = ledger_path.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2
        for line in lines:
            data = json.loads(line)
            assert "timestamp" in data
            assert "event_type" in data
            assert "signature" in data

    def test_append_iso8601_timestamp(self, ledger):
        """Timestamps are valid ISO 8601."""
        entry = ledger.append_event("model_uploaded", "alice", "gpt2")
        # Should parse without error
        ts = datetime.fromisoformat(entry.timestamp)
        assert ts.tzinfo is not None  # Should be timezone-aware

    def test_invalid_event_type_raises(self, ledger):
        """Invalid event types raise ValueError."""
        with pytest.raises(ValueError, match="Invalid event_type"):
            ledger.append_event("invalid_event", "alice", "gpt2")

    def test_all_valid_event_types(self, ledger):
        """All defined event types can be appended."""
        for event_type in VALID_EVENT_TYPES:
            entry = ledger.append_event(event_type, "alice", "gpt2")
            assert entry.event_type == event_type

    def test_ledger_length(self, ledger):
        """Ledger length reflects number of entries."""
        assert len(ledger) == 0
        ledger.append_event("model_uploaded", "alice", "gpt2")
        assert len(ledger) == 1
        ledger.append_event("model_modified", "bob", "gpt2")
        assert len(ledger) == 2


class TestChainVerification:
    """Test chain verification passes/fails correctly."""

    def test_verify_valid_chain(self, ledger):
        """verify_chain() returns True for a valid ledger."""
        ledger.append_event("model_uploaded", "alice", "gpt2")
        ledger.append_event("model_modified", "bob", "gpt2")
        ledger.append_event("model_scanned", "scanner-svc", "gpt2")
        assert ledger.verify_chain() is True

    def test_verify_empty_chain(self, ledger):
        """verify_chain() returns True for empty ledger."""
        assert ledger.verify_chain() is True

    def test_verify_single_entry_chain(self, ledger):
        """verify_chain() returns True for single-entry ledger."""
        ledger.append_event("model_uploaded", "alice", "gpt2")
        assert ledger.verify_chain() is True


class TestTamperDetection:
    """Test that chain verification FAILS when entries are tampered."""

    def test_tampered_entry_detected(self, ledger, ledger_path, keypair):
        """Modifying an entry's content breaks verification."""
        private_pem, public_pem = keypair
        ledger.append_event("model_uploaded", "alice", "gpt2")
        ledger.append_event("model_modified", "bob", "gpt2")
        ledger.append_event("model_scanned", "scanner-svc", "gpt2")

        # Tamper with the file: modify entry 1's actor
        lines = ledger_path.read_text(encoding="utf-8").strip().split("\n")
        entry_data = json.loads(lines[1])
        entry_data["actor"] = "evil_actor"
        lines[1] = json.dumps(entry_data, sort_keys=True)
        ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        # Verification should fail
        result = verify_ledger(ledger_path, public_pem)
        assert result.valid is False

    def test_tampered_signature_detected(self, ledger, ledger_path, keypair):
        """Modifying an entry's signature breaks verification."""
        private_pem, public_pem = keypair
        ledger.append_event("model_uploaded", "alice", "gpt2")

        # Tamper with signature
        lines = ledger_path.read_text(encoding="utf-8").strip().split("\n")
        entry_data = json.loads(lines[0])
        entry_data["signature"] = "AAAA" + entry_data["signature"][4:]
        lines[0] = json.dumps(entry_data, sort_keys=True)
        ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = verify_ledger(ledger_path, public_pem)
        assert result.valid is False
        assert any("signature" in f for f in result.checks_failed)


class TestDeletionDetection:
    """Test that chain verification FAILS when entries are deleted."""

    def test_deleted_middle_entry_detected(self, ledger, ledger_path, keypair):
        """Deleting a middle entry breaks the hash chain."""
        private_pem, public_pem = keypair
        ledger.append_event("model_uploaded", "alice", "gpt2")
        ledger.append_event("model_modified", "bob", "gpt2")
        ledger.append_event("model_scanned", "scanner-svc", "gpt2")

        # Delete the middle entry
        lines = ledger_path.read_text(encoding="utf-8").strip().split("\n")
        del lines[1]
        ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = verify_ledger(ledger_path, public_pem)
        assert result.valid is False
        assert any("hash_chain" in f for f in result.checks_failed)

    def test_deleted_first_entry_detected(self, ledger, ledger_path, keypair):
        """Deleting the first entry breaks genesis hash check."""
        private_pem, public_pem = keypair
        ledger.append_event("model_uploaded", "alice", "gpt2")
        ledger.append_event("model_modified", "bob", "gpt2")

        # Delete the first entry
        lines = ledger_path.read_text(encoding="utf-8").strip().split("\n")
        del lines[0]
        ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = verify_ledger(ledger_path, public_pem)
        assert result.valid is False


class TestReorderingDetection:
    """Test that chain verification FAILS when entries are reordered."""

    def test_reordered_entries_detected(self, ledger, ledger_path, keypair):
        """Swapping entry order breaks the hash chain."""
        private_pem, public_pem = keypair
        ledger.append_event("model_uploaded", "alice", "gpt2")
        ledger.append_event("model_modified", "bob", "gpt2")
        ledger.append_event("model_scanned", "scanner-svc", "gpt2")

        # Swap entries 1 and 2
        lines = ledger_path.read_text(encoding="utf-8").strip().split("\n")
        lines[1], lines[2] = lines[2], lines[1]
        ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = verify_ledger(ledger_path, public_pem)
        assert result.valid is False
        assert any("hash_chain" in f for f in result.checks_failed)


class TestSignatureValidity:
    """Test Ed25519 signature validity."""

    def test_signatures_are_valid_ed25519(self, ledger, keypair):
        """Each entry's signature is a valid Ed25519 signature."""
        private_pem, public_pem = keypair
        ledger.append_event("model_uploaded", "alice", "gpt2")
        ledger.append_event("model_modified", "bob", "gpt2")

        for entry in ledger.get_entries():
            payload = entry.signable_payload()
            assert ModelSigner.verify_manifest(public_pem, payload, entry.signature)

    def test_wrong_key_fails_verification(self, ledger, keypair):
        """Signatures fail with a different public key."""
        private_pem, public_pem = keypair
        ledger.append_event("model_uploaded", "alice", "gpt2")

        # Generate a different keypair
        _, other_public = ModelSigner.generate_keypair()

        for entry in ledger.get_entries():
            payload = entry.signable_payload()
            assert not ModelSigner.verify_manifest(other_public, payload, entry.signature)

    def test_forged_entry_detected(self, ledger, ledger_path, keypair):
        """An entry signed with a different key is detected."""
        private_pem, public_pem = keypair
        ledger.append_event("model_uploaded", "alice", "gpt2")

        # Forge an entry with a different key
        other_private, other_public = ModelSigner.generate_keypair()
        forged_payload = {
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "event_type": "model_modified",
            "actor": "evil",
            "subject": "gpt2",
            "details": {},
            "previous_hash": GENESIS_HASH,
        }
        forged_sig = ModelSigner.sign_manifest(other_private, forged_payload)
        forged_payload["signature"] = forged_sig

        # Overwrite the file
        ledger_path.write_text(json.dumps(forged_payload, sort_keys=True) + "\n", encoding="utf-8")

        result = verify_ledger(ledger_path, public_pem)
        assert result.valid is False
        assert any("signature" in f for f in result.checks_failed)


class TestIndependentVerifier:
    """Test the independent verify_ledger function."""

    def test_verify_valid_ledger_file(self, ledger, ledger_path, keypair):
        """verify_ledger returns valid=True for a correctly formed ledger."""
        private_pem, public_pem = keypair
        ledger.append_event("model_uploaded", "alice", "gpt2")
        ledger.append_event("model_modified", "bob", "gpt2")

        result = verify_ledger(ledger_path, public_pem)
        assert result.valid is True
        assert result.total_entries == 2
        assert "hash_chain_continuity" in result.checks_passed
        assert "signature_valid" in result.checks_passed
        assert "timestamp_ordering" in result.checks_passed

    def test_verify_nonexistent_file(self, tmp_path, keypair):
        """verify_ledger fails gracefully for missing file."""
        private_pem, public_pem = keypair
        result = verify_ledger(tmp_path / "nonexistent.jsonl", public_pem)
        assert result.valid is False
        assert "file_exists" in result.checks_failed

    def test_verification_result_summary(self, ledger, ledger_path, keypair):
        """VerificationResult.summary provides human-readable output."""
        private_pem, public_pem = keypair
        ledger.append_event("model_uploaded", "alice", "gpt2")

        result = verify_ledger(ledger_path, public_pem)
        assert "VALID" in result.summary
        assert "1 entries" in result.summary


class TestQueries:
    """Test query functions return correct results."""

    def test_query_by_model(self, ledger):
        """query_by_model filters correctly."""
        ledger.append_event("model_uploaded", "alice", "gpt2")
        ledger.append_event("model_uploaded", "bob", "llama")
        ledger.append_event("model_modified", "alice", "gpt2")

        results = query_by_model(ledger, "gpt2")
        assert len(results) == 2
        assert all(e.subject == "gpt2" for e in results)

    def test_query_by_actor(self, ledger):
        """query_by_actor filters correctly."""
        ledger.append_event("model_uploaded", "alice", "gpt2")
        ledger.append_event("model_uploaded", "bob", "llama")
        ledger.append_event("model_modified", "alice", "gpt2")

        results = query_by_actor(ledger, "alice")
        assert len(results) == 2
        assert all(e.actor == "alice" for e in results)

    def test_query_by_time_range(self, ledger):
        """query_by_time_range filters by timestamp."""
        ledger.append_event("model_uploaded", "alice", "gpt2")
        time.sleep(0.01)  # Ensure different timestamps
        ledger.append_event("model_modified", "bob", "gpt2")

        entries = ledger.get_entries()
        # Query for range that includes only the first event
        t0 = datetime.fromisoformat(entries[0].timestamp)
        t1 = t0 + timedelta(milliseconds=1)

        results = query_by_time_range(ledger, t0, t1)
        assert len(results) >= 1
        assert results[0].actor == "alice"

    def test_who_modified(self, ledger):
        """who_modified returns actors who performed model_modified."""
        ledger.append_event("model_uploaded", "alice", "gpt2")
        ledger.append_event("model_modified", "bob", "gpt2")
        ledger.append_event("model_modified", "charlie", "gpt2")
        ledger.append_event("model_scanned", "scanner-svc", "gpt2")

        results = who_modified(ledger, "gpt2")
        assert len(results) == 2
        actors = [r["actor"] for r in results]
        assert "bob" in actors
        assert "charlie" in actors

    def test_full_history(self, ledger):
        """full_history returns chronological events for a model."""
        ledger.append_event("model_uploaded", "alice", "gpt2")
        ledger.append_event("model_uploaded", "bob", "llama")
        ledger.append_event("model_modified", "bob", "gpt2")
        ledger.append_event("model_scanned", "scanner-svc", "gpt2")

        history = full_history(ledger, "gpt2")
        assert len(history) == 3
        assert history[0].event_type == "model_uploaded"
        assert history[1].event_type == "model_modified"
        assert history[2].event_type == "model_scanned"

    def test_query_empty_results(self, ledger):
        """Queries return empty list when no matches."""
        ledger.append_event("model_uploaded", "alice", "gpt2")

        assert query_by_model(ledger, "nonexistent") == []
        assert query_by_actor(ledger, "nonexistent") == []
        assert who_modified(ledger, "nonexistent") == []


class TestThreadSafety:
    """Test thread safety under concurrent writes."""

    def test_concurrent_writes_no_corruption(self, ledger_path, keypair):
        """Concurrent writes produce a valid chain."""
        private_pem, public_pem = keypair
        ledger = ProvenanceLedger(ledger_path, private_pem, public_pem)

        num_threads = 10
        events_per_thread = 5
        errors = []

        def writer(thread_id):
            try:
                for i in range(events_per_thread):
                    ledger.append_event(
                        "model_modified",
                        f"thread-{thread_id}",
                        "shared-model",
                        {"iteration": i},
                    )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer, args=(t,)) for t in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(ledger) == num_threads * events_per_thread
        assert ledger.verify_chain() is True

    def test_concurrent_writes_file_integrity(self, ledger_path, keypair):
        """Concurrent writes produce a valid file that passes independent verification."""
        private_pem, public_pem = keypair
        ledger = ProvenanceLedger(ledger_path, private_pem, public_pem)

        num_threads = 5
        events_per_thread = 4

        def writer(thread_id):
            for i in range(events_per_thread):
                ledger.append_event(
                    "model_scanned",
                    f"worker-{thread_id}",
                    "model-x",
                    {"step": i},
                )

        threads = [threading.Thread(target=writer, args=(t,)) for t in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Verify with the independent verifier
        result = verify_ledger(ledger_path, public_pem)
        assert result.valid is True
        assert result.total_entries == num_threads * events_per_thread


class TestLedgerPersistence:
    """Test that ledger persists and reloads correctly."""

    def test_reload_from_file(self, ledger_path, keypair):
        """Ledger reloads correctly from existing file."""
        private_pem, public_pem = keypair

        # Create and populate
        ledger1 = ProvenanceLedger(ledger_path, private_pem, public_pem)
        ledger1.append_event("model_uploaded", "alice", "gpt2")
        ledger1.append_event("model_modified", "bob", "gpt2")

        # Reload from same file
        ledger2 = ProvenanceLedger(ledger_path, private_pem, public_pem)
        assert len(ledger2) == 2
        assert ledger2.verify_chain() is True

    def test_append_after_reload(self, ledger_path, keypair):
        """Appending after reload maintains valid hash chain."""
        private_pem, public_pem = keypair

        # Create and populate
        ledger1 = ProvenanceLedger(ledger_path, private_pem, public_pem)
        ledger1.append_event("model_uploaded", "alice", "gpt2")

        # Reload and append
        ledger2 = ProvenanceLedger(ledger_path, private_pem, public_pem)
        ledger2.append_event("model_modified", "bob", "gpt2")

        assert len(ledger2) == 2
        assert ledger2.verify_chain() is True

        # Verify the file independently
        result = verify_ledger(ledger_path, public_pem)
        assert result.valid is True


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_details_with_nested_dict(self, ledger):
        """Details can contain nested structures."""
        details = {
            "version": "2.0",
            "changes": ["weights", "config"],
            "metadata": {"source": "training-run-42"},
        }
        entry = ledger.append_event("model_modified", "alice", "gpt2", details)
        assert entry.details == details
        assert ledger.verify_chain() is True

    def test_empty_details(self, ledger):
        """Events work with empty details."""
        entry = ledger.append_event("model_uploaded", "alice", "gpt2")
        assert entry.details == {}
        assert ledger.verify_chain() is True

    def test_hash_chain_deterministic(self, ledger):
        """Hash computation is deterministic."""
        entry = ledger.append_event("model_uploaded", "alice", "gpt2")
        hash1 = entry.compute_hash()
        hash2 = entry.compute_hash()
        assert hash1 == hash2

    def test_entry_serialization_roundtrip(self, ledger):
        """LedgerEntry survives serialization/deserialization."""
        entry = ledger.append_event("model_uploaded", "alice", "gpt2", {"key": "value"})
        data = entry.to_dict()
        restored = LedgerEntry.from_dict(data)
        assert restored.timestamp == entry.timestamp
        assert restored.event_type == entry.event_type
        assert restored.actor == entry.actor
        assert restored.subject == entry.subject
        assert restored.details == entry.details
        assert restored.previous_hash == entry.previous_hash
        assert restored.signature == entry.signature
