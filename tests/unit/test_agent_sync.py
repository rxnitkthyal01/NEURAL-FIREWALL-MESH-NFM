import urllib.error
from datetime import UTC, datetime, timedelta

import pytest

from nfm.crypto.policy_signing import create_bundle, create_signing_key
from nfm.mesh.sync import sync_once
from nfm.policy.engine import evaluate
from nfm.storage.database import Store


def test_agent_sync_verifies_policy_and_applies_remote_revocations(tmp_path, monkeypatch):
    private, public = tmp_path / "signing.pem", tmp_path / "signing.pub.pem"
    create_signing_key(private, public)
    policy = {"policy_id": "mesh", "version": 1, "rules": [
        {"effect": "allow", "source_roles": ["app"], "services": ["db"], "operations": ["connect"]}
    ]}
    snapshot = {
        "policy_bundle": create_bundle(policy, private),
        "nodes": [
            {"node_id": "node-a", "role": "app", "cert_serial": "11", "cert_expires_at": "2030-01-01T00:00:00+00:00", "status": "active", "security_state": "HEALTHY"},
            {"node_id": "node-b", "role": "app", "cert_serial": "12", "cert_expires_at": "2030-01-01T00:00:00+00:00", "status": "revoked", "security_state": "ISOLATED"},
        ],
    }
    monkeypatch.setattr("nfm.mesh.sync.controller_request", lambda *args: snapshot)
    db = Store(tmp_path / "agent.sqlite3")
    result = sync_once("https://controller.example", "t" * 40, store=db, trusted_policy_key=public)
    assert result == {"nodes": 2, "policy_version": 1}
    assert db.active_policy() == policy
    assert not db.revoked("node-a")
    assert db.revoked("node-b")
    assert next(node for node in db.nodes() if node["node_id"] == "node-b")["security_state"] == "ISOLATED"
    assert any(event["event_type"] == "security_state_changed" for event in db.events())
    sync_once("https://controller.example", "t" * 40, store=db, trusted_policy_key=public)
    policy_activations = [event for event in db.events() if event["event_type"] == "policy_activated"]
    assert len(policy_activations) == 1
    db.connection.close()


def test_controller_outage_keeps_cached_policy_but_expired_identity_denies(tmp_path, monkeypatch):
    db = Store(tmp_path / "offline.sqlite3")
    policy = {"policy_id": "offline", "version": 1, "rules": [
        {"effect": "allow", "source_roles": ["app"], "services": ["db"], "operations": ["connect"]}
    ]}
    db.set_policy(policy)

    def unavailable(*args):
        raise urllib.error.URLError("controller unavailable")

    monkeypatch.setattr("nfm.mesh.sync.controller_request", unavailable)
    with pytest.raises(urllib.error.URLError):
        sync_once("https://controller.example", "t" * 40, store=db, trusted_policy_key=tmp_path / "missing.pem")
    assert db.active_policy() == policy
    assert not db.sync_is_fresh(300)
    decision = evaluate(db.active_policy(), node_id="node-a", role="app", service="db",
                        operation="connect", credential_valid=False, revoked=False)
    assert not decision.allowed
    assert decision.reason == "credential_invalid"
    db.connection.close()


def test_sync_freshness_has_a_bounded_offline_window(tmp_path):
    db = Store(tmp_path / "freshness.sqlite3")
    db.mark_sync_required()
    now = datetime.now(UTC)
    assert not db.sync_is_fresh(300, now=now)
    db.connection.execute(
        "UPDATE agent_sync_state SET last_success_at=? WHERE singleton=1",
        ((now - timedelta(seconds=301)).isoformat(),),
    )
    assert not db.sync_is_fresh(300, now=now)
    db.mark_sync_success()
    assert db.sync_is_fresh(300)
    with pytest.raises(ValueError, match="must be positive"):
        db.sync_is_fresh(0)
    db.connection.close()


def test_sync_rejects_malformed_inventory_before_policy_mutation(tmp_path, monkeypatch):
    private, public = tmp_path / "signing.pem", tmp_path / "signing.pub.pem"
    create_signing_key(private, public)
    db = Store(tmp_path / "atomic-sync.sqlite3")
    old_policy = {"policy_id": "mesh", "version": 1, "rules": [
        {"effect": "deny", "source_roles": ["*"], "services": ["*"], "operations": ["*"]}
    ]}
    new_policy = {"policy_id": "mesh", "version": 2, "rules": [
        {"effect": "allow", "source_roles": ["app"], "services": ["db"], "operations": ["connect"]}
    ]}
    db.set_policy(old_policy)
    snapshot = {
        "policy_bundle": create_bundle(new_policy, private),
        "nodes": [{
            "node_id": "node-a", "role": "app", "cert_serial": "12",
            "cert_expires_at": "not-a-timestamp", "status": "active", "security_state": "HEALTHY",
        }],
    }
    monkeypatch.setattr("nfm.mesh.sync.controller_request", lambda *args: snapshot)
    with pytest.raises(ValueError, match="credential expiration"):
        sync_once("https://controller.example", "t" * 40, store=db, trusted_policy_key=public)
    assert db.active_policy() == old_policy
    assert db.nodes() == []
    db.connection.close()
