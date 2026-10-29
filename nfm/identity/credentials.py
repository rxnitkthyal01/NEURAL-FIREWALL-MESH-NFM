"""Local CA and short-lived node certificate issuance using X.509 and ECDSA."""

from __future__ import annotations

import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as private_file:
            private_file.write(data)
    except OSError:
        path.unlink(missing_ok=True)
        raise


def _load_ca(ca_directory: Path) -> tuple[
    ec.EllipticCurvePrivateKey, x509.Certificate, ec.EllipticCurvePublicKey
]:
    loaded_key = serialization.load_pem_private_key(
        (ca_directory / "ca-key.pem").read_bytes(), password=None
    )
    if not isinstance(loaded_key, ec.EllipticCurvePrivateKey) or not isinstance(
        loaded_key.curve, ec.SECP256R1
    ):
        raise ValueError("CA private key must use ECDSA P-256")
    ca_cert = x509.load_pem_x509_certificate((ca_directory / "ca-cert.pem").read_bytes())
    loaded_public_key = ca_cert.public_key()
    if not isinstance(loaded_public_key, ec.EllipticCurvePublicKey) or not isinstance(
        loaded_public_key.curve, ec.SECP256R1
    ):
        raise ValueError("CA certificate must use ECDSA P-256")
    try:
        constraints = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("CA certificate is missing BasicConstraints") from exc
    if not constraints.ca:
        raise ValueError("certificate is not a CA")
    expected_public_key = loaded_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    actual_public_key = loaded_public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if expected_public_key != actual_public_key:
        raise ValueError("CA private key does not match the CA certificate")
    return loaded_key, ca_cert, loaded_public_key


def create_ca(directory: Path, *, common_name: str = "NFM Local CA") -> None:
    """Create a local P-256 CA. Refuses to overwrite existing CA material."""
    key_path, cert_path = directory / "ca-key.pem", directory / "ca-cert.pem"
    if key_path.exists() or cert_path.exists():
        raise FileExistsError("CA files already exist; refusing to overwrite")
    directory.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    _write_private(key_path, key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    with cert_path.open("xb") as cert_file:
        cert_file.write(cert.public_bytes(serialization.Encoding.PEM))


def issue_node(directory: Path, ca_directory: Path, node_id: str, role: str, *, days: int = 30) -> None:
    """Issue a client/server certificate with node ID in a URI SAN."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", node_id):
        raise ValueError("node ID must be 1-128 letters, digits, dots, underscores, or hyphens")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}", role):
        raise ValueError("role must be 1-63 letters, digits, dots, underscores, or hyphens")
    if not 1 <= days <= 90:
        raise ValueError("credential lifetime must be between 1 and 90 days")
    directory.mkdir(parents=True, exist_ok=True)
    key_path, cert_path = directory / f"{node_id}-key.pem", directory / f"{node_id}-cert.pem"
    if key_path.exists() or cert_path.exists():
        raise FileExistsError(f"identity files already exist for {node_id}")
    ca_key, ca_cert, ca_public_key = _load_ca(ca_directory)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node_id)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([
            x509.UniformResourceIdentifier(f"urn:nfm:node:{node_id}"),
            x509.UniformResourceIdentifier(f"urn:nfm:role:{role}"),
        ]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_public_key), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    _write_private(key_path, key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    with cert_path.open("xb") as cert_file:
        cert_file.write(cert.public_bytes(serialization.Encoding.PEM))


def certificate_node_id(cert: x509.Certificate) -> str:
    """Extract a node ID from the required NFM URI SAN."""
    try:
        uris = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.UniformResourceIdentifier)
    except x509.ExtensionNotFound as exc:
        raise ValueError("peer certificate has no NFM identity SAN") from exc
    matches = [uri.removeprefix("urn:nfm:node:") for uri in uris if uri.startswith("urn:nfm:node:")]
    if len(matches) != 1 or not matches[0]:
        raise ValueError("peer certificate must contain exactly one NFM node identity")
    return matches[0]


def create_enrollment_csr(directory: Path, node_id: str, role: str) -> bytes:
    """Create a local private key and signed CSR; only the CSR leaves this node."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", node_id):
        raise ValueError("invalid node ID")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}", role):
        raise ValueError("invalid role")
    directory.mkdir(parents=True, exist_ok=True)
    key_path = directory / f"{node_id}-key.pem"
    csr_path = directory / f"{node_id}.csr.pem"
    if key_path.exists() or csr_path.exists():
        raise FileExistsError(f"local enrollment material already exists for {node_id}")
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node_id)])
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(x509.SubjectAlternativeName([
            x509.UniformResourceIdentifier(f"urn:nfm:node:{node_id}"),
            x509.UniformResourceIdentifier(f"urn:nfm:role:{role}"),
        ]), critical=False)
        .sign(key, hashes.SHA256())
    )
    _write_private(key_path, key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    csr_bytes = csr.public_bytes(serialization.Encoding.PEM)
    with csr_path.open("xb") as csr_file:
        csr_file.write(csr_bytes)
    return csr_bytes


def issue_from_csr(csr_pem: bytes, ca_directory: Path, node_id: str, role: str, *, days: int = 30) -> x509.Certificate:
    """CA-sign a validated P-256 CSR after an administrator approves enrollment."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", node_id):
        raise ValueError("invalid node ID")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}", role):
        raise ValueError("invalid role")
    if not 1 <= days <= 90:
        raise ValueError("credential lifetime must be between 1 and 90 days")
    csr = x509.load_pem_x509_csr(csr_pem)
    if not csr.is_signature_valid:
        raise ValueError("CSR signature is invalid")
    common_names = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(common_names) != 1 or common_names[0].value != node_id:
        raise ValueError("CSR common name does not match requested node ID")
    csr_public_key = csr.public_key()
    if not isinstance(csr_public_key, ec.EllipticCurvePublicKey) or not isinstance(
        csr_public_key.curve, ec.SECP256R1
    ):
        raise ValueError("only ECDSA P-256 enrollment keys are supported")
    ca_key, ca_cert, ca_public_key = _load_ca(ca_directory)
    now = datetime.now(UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node_id)])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([
            x509.UniformResourceIdentifier(f"urn:nfm:node:{node_id}"),
            x509.UniformResourceIdentifier(f"urn:nfm:role:{role}"),
        ]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr_public_key), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_public_key), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
