"""Mutual-TLS TCP proxy for explicitly protected services."""

from __future__ import annotations

import asyncio
import os
import ssl
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509

from nfm.identity.credentials import certificate_node_id
from nfm.policy.engine import evaluate
from nfm.storage.database import Store


@dataclass(slots=True)
class LiveSession:
    node_id: str
    role: str
    session_id: str
    cert_serial: str
    credential_expires_at: datetime
    client: asyncio.StreamWriter
    upstream: asyncio.StreamWriter


class ProtectedProxy:
    def __init__(self, *, store: Store, ca_cert: Path, cert: Path, key: Path,
                 service: str, target_host: str, target_port: int):
        self.store = store
        self.ca_cert = ca_cert
        self.cert = cert
        self.key = key
        self.service = service
        self.target_host = target_host
        self.target_port = target_port
        self.live: dict[str, LiveSession] = {}
        try:
            self.max_offline_age = int(os.environ.get("NFM_MAX_OFFLINE_AGE_SECONDS", "300"))
        except ValueError as exc:
            raise ValueError("NFM_MAX_OFFLINE_AGE_SECONDS must be a positive integer") from exc
        if self.max_offline_age < 1:
            raise ValueError("NFM_MAX_OFFLINE_AGE_SECONDS must be a positive integer")

    def server_context(self) -> ssl.SSLContext:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=str(self.ca_cert))
        context.load_cert_chain(certfile=str(self.cert), keyfile=str(self.key))
        return context

    async def start(self, host: str, port: int) -> None:
        server = await asyncio.start_server(self.handle, host, port, ssl=self.server_context(), backlog=128)
        watcher = asyncio.create_task(self.watch_revocations())
        async with server:
            print(f"NFM protected service {self.service} listening on {host}:{port}; upstream {self.target_host}:{self.target_port}")
            try:
                await server.serve_forever()
            finally:
                watcher.cancel()

    async def watch_revocations(self) -> None:
        while True:
            await asyncio.sleep(1)
            for session_id, session in list(self.live.items()):
                if self.store.session_status(session_id) != "active":
                    self.store.event(session.node_id, "session_terminated", "high",
                                     {"session_id": session_id, "reason": "session_revocation_requested"})
                    await self.close_session(session, "revoked")
                    continue
                revoked = self.store.revoked(session.node_id)
                node = next((item for item in self.store.nodes() if item["node_id"] == session.node_id), None)
                credential_replaced = node is None or node["cert_serial"] != session.cert_serial
                policy = self.store.active_policy()
                decision = evaluate(
                    policy, node_id=session.node_id, role=session.role, service=self.service,
                    operation="connect", credential_valid=datetime.now(UTC) < session.credential_expires_at,
                    revoked=revoked, security_state=node["security_state"] if node else "ISOLATED",
                )
                if not self.store.sync_is_fresh(self.max_offline_age):
                    decision = type(decision)(False, "controller_sync_stale")
                if not decision.allowed or credential_replaced:
                    reason = "identity_revoked" if revoked else "credential_replaced" if credential_replaced else decision.reason
                    self.store.event(session.node_id, "session_terminated", "high" if revoked else "warning",
                                     {"session_id": session_id, "reason": reason})
                    await self.close_session(session, "revoked" if revoked else "denied")

    async def close_session(self, session: LiveSession, status: str) -> None:
        if session.session_id not in self.live:
            return
        for writer in (session.client, session.upstream):
            writer.close()
        await asyncio.gather(*(writer.wait_closed() for writer in (session.client, session.upstream)), return_exceptions=True)
        self.store.end_session(session.session_id, status)
        self.live.pop(session.session_id, None)

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        ssl_object = writer.get_extra_info("ssl_object")
        peer_der = ssl_object.getpeercert(binary_form=True) if ssl_object else None
        node_id = "unknown"
        if not peer_der:
            writer.close()
            await writer.wait_closed()
            return
        try:
            cert = x509.load_der_x509_certificate(peer_der)
            node_id = certificate_node_id(cert)
            uris = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.UniformResourceIdentifier)
            role_values = [uri.removeprefix("urn:nfm:role:") for uri in uris if uri.startswith("urn:nfm:role:")]
            role = role_values[0] if len(role_values) == 1 else "unknown"
            node = next((n for n in self.store.nodes() if n["node_id"] == node_id and n["status"] == "active"), None)
            policy = self.store.active_policy()
            decision = evaluate(policy, node_id=node_id, role=role, service=self.service,
                                operation="connect", credential_valid=True,
                                revoked=self.store.revoked(node_id),
                                security_state=node["security_state"] if node else "ISOLATED")
            if not self.store.sync_is_fresh(self.max_offline_age):
                decision = type(decision)(False, "controller_sync_stale")
            if node is None or node["role"] != role or node["cert_serial"] != str(cert.serial_number):
                decision = type(decision)(False, "identity_not_enrolled_or_role_mismatch")
            self.store.event(node_id, "authorization_decision", "info" if decision.allowed else "warning",
                             {"allowed": decision.allowed, "reason": decision.reason, "service": self.service,
                              "policy_id": decision.policy_id, "policy_version": decision.version})
            if not decision.allowed:
                writer.close()
                await writer.wait_closed()
                return
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(self.target_host, self.target_port), timeout=5)
            session_id = str(uuid.uuid4())
            session = LiveSession(node_id, role, session_id, str(cert.serial_number),
                                  cert.not_valid_after_utc, writer, upstream_writer)
            self.live[session_id] = session
            self.store.start_session(session_id, node_id, self.service)
            tasks = [asyncio.create_task(self.pipe(reader, upstream_writer)),
                     asyncio.create_task(self.pipe(upstream_reader, writer))]
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*done, *pending, return_exceptions=True)
            await self.close_session(session, "closed")
        except (ValueError, OSError) as exc:
            self.store.event(node_id, "protected_connection_failed", "warning", {"error": type(exc).__name__})
            writer.close()
            await writer.wait_closed()

    @staticmethod
    async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
