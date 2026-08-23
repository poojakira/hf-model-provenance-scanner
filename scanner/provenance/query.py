"""
scanner/provenance/query.py - Query the provenance ledger.

Provides functions to query ledger entries by model, actor, time range,
and to retrieve modification history.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .ledger import LedgerEntry, ProvenanceLedger


def query_by_model(ledger: ProvenanceLedger, model_id: str) -> list[LedgerEntry]:
    """Return all events related to a specific model.

    Args:
        ledger: The provenance ledger to query.
        model_id: The model identifier (subject field).

    Returns:
        List of matching LedgerEntry objects.
    """
    return [entry for entry in ledger.get_entries() if entry.subject == model_id]


def query_by_actor(ledger: ProvenanceLedger, actor_id: str) -> list[LedgerEntry]:
    """Return all events performed by a specific actor.

    Args:
        ledger: The provenance ledger to query.
        actor_id: The actor identifier.

    Returns:
        List of matching LedgerEntry objects.
    """
    return [entry for entry in ledger.get_entries() if entry.actor == actor_id]


def query_by_time_range(
    ledger: ProvenanceLedger,
    start: datetime,
    end: datetime,
) -> list[LedgerEntry]:
    """Return all events within a time range (inclusive).

    Args:
        ledger: The provenance ledger to query.
        start: Start of time range (inclusive).
        end: End of time range (inclusive).

    Returns:
        List of matching LedgerEntry objects within the range.
    """
    results = []
    for entry in ledger.get_entries():
        entry_ts = datetime.fromisoformat(entry.timestamp)
        if start <= entry_ts <= end:
            results.append(entry)
    return results


def who_modified(ledger: ProvenanceLedger, model_id: str) -> list[dict[str, Any]]:
    """Return a list of actors who modified a model, with timestamps.

    Args:
        ledger: The provenance ledger to query.
        model_id: The model identifier.

    Returns:
        List of dicts with 'actor' and 'timestamp' keys for model_modified events.
    """
    return [
        {"actor": entry.actor, "timestamp": entry.timestamp}
        for entry in ledger.get_entries()
        if entry.subject == model_id and entry.event_type == "model_modified"
    ]


def full_history(ledger: ProvenanceLedger, model_id: str) -> list[LedgerEntry]:
    """Return the full chronological event history for a model.

    Args:
        ledger: The provenance ledger to query.
        model_id: The model identifier.

    Returns:
        List of LedgerEntry objects in chronological order.
    """
    entries = [entry for entry in ledger.get_entries() if entry.subject == model_id]
    # Sort by timestamp (entries are already chronological, but be explicit)
    entries.sort(key=lambda e: e.timestamp)
    return entries
