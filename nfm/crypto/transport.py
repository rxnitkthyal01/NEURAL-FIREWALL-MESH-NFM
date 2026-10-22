"""Standards-based TLS 1.3 client transport; no custom encryption protocol."""

from __future__ import annotations

import asyncio
import ssl
from pathlib import Path

from cryptography import x509

from nfm.identity.credentials import certificate_node_id


def client_context(*, ca_cert: Path, cert: Path, key: Path) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_cert))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = False  # Server identity is checked against the NFM URI SAN below.
    context.load_cert_chain(certfile=str(cert), keyfile=str(key))
    return context


async def exchange(*, host: str, port: int, server_node_id: str, ca_cert: Path,
                   cert: Path, key: Path, payload: bytes, timeout: float = 5.0) -> bytes:
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=client_context(ca_cert=ca_cert, cert=cert, key=key),
                                server_hostname="nfm-peer"), timeout=timeout)
    try:
        ssl_object = writer.get_extra_info("ssl_object")
        der = ssl_object.getpeercert(binary_form=True) if ssl_object else None
        if not der or certificate_node_id(x509.load_der_x509_certificate(der)) != server_node_id:
            raise ssl.SSLCertVerificationError("server NFM identity does not match expected node")
        writer.write(payload)
        await writer.drain()
        return await asyncio.wait_for(reader.read(1024 * 1024), timeout=timeout)
    finally:
        writer.close()
        await writer.wait_closed()
