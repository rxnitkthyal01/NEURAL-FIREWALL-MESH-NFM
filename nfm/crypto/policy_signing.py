"""Ed25519 signatures for portable policy bundles."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from nfm.policy.engine import validate_policy


def create_signing_key(private_path: Path, public_path: Path) -> None:
    """Create controller signing key material without overwriting existing keys."""
    if private_path.exists() or public_path.exists():
        if private_path.is_file() and public_path.is_file():
            private_key = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
            public_key = serialization.load_pem_public_key(public_path.read_bytes())
            if not isinstance(private_key, Ed25519PrivateKey) or not isinstance(public_key, Ed25519PublicKey):
                raise ValueError("existing policy signing keypair must use Ed25519")
            expected = private_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            actual = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            if expected != actual:
                raise ValueError("existing policy signing private and public keys do not match")
            return
        raise FileExistsError("incomplete policy signing keypair; refusing to overwrite")
    private_path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    private_bytes = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    descriptor = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as private_file:
            private_file.write(private_bytes)
    except OSError:
        private_path.unlink(missing_ok=True)
        raise
    public_bytes = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with public_path.open("xb") as public_file:
        public_file.write(public_bytes)


def _canonical(policy: dict[str, Any]) -> bytes:
    return json.dumps(policy, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def create_bundle(policy: dict[str, Any], private_path: Path) -> dict[str, Any]:
    checked = validate_policy(policy)
    key = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("policy signing key must be Ed25519")
    signature = key.sign(_canonical(checked))
    return {
        "algorithm": "Ed25519",
        "policy": checked,
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def verify_bundle(bundle: Any, public_path: Path) -> dict[str, Any]:
    if not isinstance(bundle, dict) or set(bundle) != {"algorithm", "policy", "signature"}:
        raise ValueError("bundle must contain exactly algorithm, policy, and signature")
    if bundle["algorithm"] != "Ed25519" or not isinstance(bundle["signature"], str):
        raise ValueError("unsupported signature algorithm or malformed signature")
    policy = validate_policy(bundle["policy"])
    try:
        signature = base64.b64decode(bundle["signature"], validate=True)
        key = serialization.load_pem_public_key(public_path.read_bytes())
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("trusted policy key must be Ed25519")
        key.verify(signature, _canonical(policy))
    except (OSError, ValueError, InvalidSignature) as exc:
        raise ValueError("policy bundle signature verification failed") from exc
    return policy
