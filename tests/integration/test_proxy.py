import asyncio

from cryptography import x509

from nfm.crypto.transport import client_context, exchange
from nfm.enforcement.proxy import ProtectedProxy
from nfm.identity.credentials import create_ca, issue_node
from nfm.storage.database import Store


def test_mtls_policy_allows_then_revocation_denies(tmp_path):
    async def scenario():
        ca, identities = tmp_path / "ca", tmp_path / "identities"
        create_ca(ca)
        issue_node(identities, ca, "client-a", "application")
        issue_node(identities, ca, "server-b", "database")
        db = Store(tmp_path / "state.sqlite3")
        for node_id, role in (("client-a", "application"), ("server-b", "database")):
            cert = x509.load_pem_x509_certificate((identities / f"{node_id}-cert.pem").read_bytes())
            db.enroll(node_id, role, str(cert.serial_number), cert.not_valid_after_utc.isoformat())
        db.set_policy({"policy_id": "integration", "version": 1, "rules": [
            {"effect": "allow", "source_roles": ["application"], "services": ["echo"], "operations": ["connect"]}
        ]})

        async def echo(reader, writer):
            payload = await reader.readexactly(5)
            writer.write(payload)
            await writer.drain()
            writer.close()

        upstream = await asyncio.start_server(echo, "127.0.0.1", 0)
        upstream_port = upstream.sockets[0].getsockname()[1]
        proxy = ProtectedProxy(store=db, ca_cert=ca / "ca-cert.pem",
                               cert=identities / "server-b-cert.pem", key=identities / "server-b-key.pem",
                               service="echo", target_host="127.0.0.1", target_port=upstream_port)
        protected = await asyncio.start_server(proxy.handle, "127.0.0.1", 0, ssl=proxy.server_context())
        protected_port = protected.sockets[0].getsockname()[1]
        try:
            kwargs = dict(host="127.0.0.1", port=protected_port, server_node_id="server-b",
                          ca_cert=ca / "ca-cert.pem", cert=identities / "client-a-cert.pem",
                          key=identities / "client-a-key.pem", payload=b"hello")
            assert await exchange(**kwargs) == b"hello"
            # Agents that have entered controller-sync mode fail closed after the cache expires.
            db.mark_sync_required()
            db.connection.execute(
                "UPDATE agent_sync_state SET last_success_at='2000-01-01T00:00:00+00:00' WHERE singleton=1"
            )
            assert await exchange(**kwargs) == b""
            db.mark_sync_success()
            db.set_security_state("client-a", "ISOLATED")
            assert await exchange(**kwargs) == b""
            db.set_security_state("client-a", "HEALTHY", recovery_approved=True)
            db.revoke("client-a")
            assert await exchange(**kwargs) == b""
            assert any(e["event_type"] == "authorization_decision" for e in db.events())
        finally:
            protected.close()
            upstream.close()
            await protected.wait_closed()
            await upstream.wait_closed()
            db.connection.close()

    asyncio.run(scenario())


def test_revocation_terminates_an_established_session(tmp_path):
    async def scenario():
        ca, identities = tmp_path / "ca", tmp_path / "identities"
        create_ca(ca)
        issue_node(identities, ca, "client-a", "application")
        issue_node(identities, ca, "server-b", "database")
        db = Store(tmp_path / "state.sqlite3")
        for node_id, role in (("client-a", "application"), ("server-b", "database")):
            cert = x509.load_pem_x509_certificate((identities / f"{node_id}-cert.pem").read_bytes())
            db.enroll(node_id, role, str(cert.serial_number), cert.not_valid_after_utc.isoformat())
        db.set_policy({"policy_id": "session-revocation", "version": 1, "rules": [
            {"effect": "allow", "source_roles": ["application"], "services": ["echo"], "operations": ["connect"]}
        ]})

        async def hold(reader, writer):
            payload = await reader.readexactly(5)
            writer.write(payload)
            await writer.drain()
            await reader.read()
            writer.close()

        upstream = await asyncio.start_server(hold, "127.0.0.1", 0)
        proxy = ProtectedProxy(store=db, ca_cert=ca / "ca-cert.pem",
                               cert=identities / "server-b-cert.pem", key=identities / "server-b-key.pem",
                               service="echo", target_host="127.0.0.1", target_port=upstream.sockets[0].getsockname()[1])
        protected = await asyncio.start_server(proxy.handle, "127.0.0.1", 0, ssl=proxy.server_context())
        watcher = asyncio.create_task(proxy.watch_revocations())
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", protected.sockets[0].getsockname()[1],
            ssl=client_context(ca_cert=ca / "ca-cert.pem", cert=identities / "client-a-cert.pem",
                               key=identities / "client-a-key.pem"), server_hostname="nfm-peer")
        try:
            writer.write(b"hello")
            await writer.drain()
            assert await asyncio.wait_for(reader.readexactly(5), timeout=2) == b"hello"
            session_id = db.sessions()[0]["session_id"]
            assert db.revoke_session(session_id)
            assert await asyncio.wait_for(reader.read(1), timeout=3) == b""
            assert any(event["event_type"] == "session_terminated" for event in db.events())
        finally:
            writer.close()
            await writer.wait_closed()
            watcher.cancel()
            protected.close()
            upstream.close()
            await protected.wait_closed()
            await upstream.wait_closed()
            db.connection.close()

    asyncio.run(scenario())
