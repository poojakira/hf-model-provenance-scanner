"""
scanner/signing/ed25519.py
Ed25519 model artifact signing and verification.

Provides cryptographic signing of ML model artifacts to detect
supply chain tampering (MITRE ATT&CK T1683.001).

Requires: cryptography>=42.0.0

Usage:
    from scanner.signing.ed25519 import ModelSigner
    private_pem, public_pem = ModelSigner.generate_keypair()
    sig = ModelSigner.sign_artifact(private_pem, 'model.safetensors')
    ok = ModelSigner.verify_artifact(public_pem, 'model.safetensors', sig['signature_b64'])
"""
from __future__ import annotations
import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class ModelSigner:
    """Ed25519 signing and verification for ML model artifacts."""

    @staticmethod
    def generate_keypair() -> tuple[bytes, bytes]:
        """Generate a new Ed25519 keypair.
        Returns: (private_key_pem, public_key_pem)
        """
        private_key = Ed25519PrivateKey.generate()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return private_pem, public_pem

    @staticmethod
    def _load_private_key(private_key_pem: bytes) -> Ed25519PrivateKey:
        return serialization.load_pem_private_key(private_key_pem, password=None)

    @staticmethod
    def _load_public_key(public_key_pem: bytes) -> Ed25519PublicKey:
        return serialization.load_pem_public_key(public_key_pem)

    @staticmethod
    def _sha256_file(path: str) -> str:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def sign_artifact(private_key_pem: bytes, artifact_path: str) -> dict[str, Any]:
        """Sign a model artifact file.
        Returns dict with: artifact_path, sha256, signature_b64, algorithm, signed_at
        """
        sha256 = ModelSigner._sha256_file(artifact_path)
        payload = json.dumps({'path': artifact_path, 'sha256': sha256}, sort_keys=True).encode()
        private_key = ModelSigner._load_private_key(private_key_pem)
        signature = private_key.sign(payload)
        return {
            'artifact_path': artifact_path,
            'sha256': sha256,
            'signature_b64': base64.b64encode(signature).decode(),
            'algorithm': 'Ed25519',
            'signed_at': datetime.now(tz=timezone.utc).isoformat(),
        }

    @staticmethod
    def verify_artifact(public_key_pem: bytes, artifact_path: str, signature_b64: str) -> bool:
        """Verify a model artifact signature. Returns True if valid."""
        from cryptography.exceptions import InvalidSignature
        try:
            sha256 = ModelSigner._sha256_file(artifact_path)
            payload = json.dumps({'path': artifact_path, 'sha256': sha256}, sort_keys=True).encode()
            public_key = ModelSigner._load_public_key(public_key_pem)
            signature = base64.b64decode(signature_b64)
            public_key.verify(signature, payload)
            return True
        except (InvalidSignature, Exception):
            return False

    @staticmethod
    def sign_manifest(private_key_pem: bytes, manifest: dict[str, Any]) -> str:
        """Sign a manifest dict. Returns base64 signature string."""
        payload = json.dumps(manifest, sort_keys=True).encode()
        private_key = ModelSigner._load_private_key(private_key_pem)
        return base64.b64encode(private_key.sign(payload)).decode()

    @staticmethod
    def verify_manifest(public_key_pem: bytes, manifest: dict[str, Any], signature_b64: str) -> bool:
        """Verify a signed manifest. Returns True if valid."""
        from cryptography.exceptions import InvalidSignature
        try:
            payload = json.dumps(manifest, sort_keys=True).encode()
            public_key = ModelSigner._load_public_key(public_key_pem)
            public_key.verify(base64.b64decode(signature_b64), payload)
            return True
        except (InvalidSignature, Exception):
            return False
