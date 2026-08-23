"""
scanner/provenance - Cryptographic provenance ledger for ML model lifecycle tracking.

Provides an append-only, hash-chained, Ed25519-signed event log for tracking
model uploads, modifications, scans, deployments, and access control changes.

Also re-exports legacy provenance verification utilities used by the CLI.
"""

# Legacy exports used by scanner.cli
from ._legacy import (
    is_sbom_file,
    is_signature_file,
    parse_sbom_hashes,
    sha256_bytes,
    verify_local_signatures,
    verify_sbom_artifacts,
)
from .ledger import ProvenanceLedger
from .query import (
    full_history,
    query_by_actor,
    query_by_model,
    query_by_time_range,
    who_modified,
)
from .verifier import VerificationResult, verify_ledger

__all__ = [
    "ProvenanceLedger",
    "verify_ledger",
    "VerificationResult",
    "query_by_model",
    "query_by_actor",
    "query_by_time_range",
    "who_modified",
    "full_history",
    "is_sbom_file",
    "is_signature_file",
    "verify_local_signatures",
    "verify_sbom_artifacts",
    "sha256_bytes",
    "parse_sbom_hashes",
]
