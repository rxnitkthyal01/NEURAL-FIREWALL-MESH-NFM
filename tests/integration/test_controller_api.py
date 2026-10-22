import pytest
from fastapi.testclient import TestClient

from nfm.controller.api import create_app
from nfm.crypto.policy_signing import create_signing_key, verify_bundle
from nfm.storage.database import Store


def test_controller_api_requires_admin_token_and_serves_real_state(tmp_path):
    db = Store(tmp_path / "state.sqlite3")
    db.enroll("node-a", "application", "123", "2030-01-01T00:00:00+00:00")
    client = TestClient(create_app(db, "a" * 40))
    assert client.get("/api/nodes").status_code == 401
    headers = {"Authorization": "Bearer " + "a" * 40}
    response = client.get("/api/nodes", headers=headers)
    assert response.status_code == 200
    assert response.json()[0]["node_id"] == "node-a"
    assert response.json()[0]["security_state"] == "HEALTHY"
    assert client.get("/api/sessions", headers=headers).status_code == 200
    assert client.post("/api/nodes/node-a/state", json={"security_state": "ISOLATED"}, headers=headers).json()["security_state"] == "ISOLATED"
    assert client.post("/api/nodes/node-a/state", json={"security_state": "HEALTHY"}, headers=headers).status_code == 422
    assert client.post("/api/nodes/node-a/state", json={"security_state": "HEALTHY", "recovery_approved": True}, headers=headers).status_code == 200
    db.start_session("session-1", "node-a", "database")
    assert client.post("/api/sessions/session-1/revoke", headers=headers).json()["status"] == "revocation_requested"
    assert db.session_status("session-1") == "revocation_requested"
    policy = {"policy_id": "api-policy", "version": 1, "rules": [
        {"effect": "allow", "source_roles": ["application"], "services": ["db"], "operations": ["connect"]}
    ]}
    assert client.post("/api/policies/validate", json=policy, headers=headers).json()["valid"] is True
    assert client.post("/api/nodes/node-a/revoke", headers=headers).json()["status"] == "revoked"


def test_agent_snapshot_is_authenticated_and_carries_signed_policy_and_state(tmp_path, monkeypatch):
    db = Store(tmp_path / "state.sqlite3")
    db.enroll("node-a", "application", "123", "2030-01-01T00:00:00+00:00")
    db.set_security_state("node-a", "ISOLATED")
    policy = {"policy_id": "snapshot-policy", "version": 1, "rules": [
        {"effect": "allow", "source_roles": ["application"], "services": ["db"], "operations": ["connect"]}
    ]}
    db.set_policy(policy)
    signing_key, public_key = tmp_path / "signing.pem", tmp_path / "signing.pub.pem"
    create_signing_key(signing_key, public_key)
    monkeypatch.setenv("NFM_AGENT_TOKEN", "s" * 48)
    client = TestClient(create_app(db, "a" * 48, policy_signing_key=signing_key))
    assert client.get("/api/mesh/snapshot").status_code == 401
    response = client.get("/api/mesh/snapshot", headers={"Authorization": "Bearer " + "s" * 48})
    assert response.status_code == 200
    assert verify_bundle(response.json()["policy_bundle"], public_key) == policy
    assert response.json()["nodes"][0]["security_state"] == "ISOLATED"
    db.connection.close()


def test_controller_rejects_reused_admin_and_agent_tokens(tmp_path, monkeypatch):
    monkeypatch.setenv("NFM_AGENT_TOKEN", "a" * 40)
    with pytest.raises(ValueError, match="must be distinct"):
        create_app(Store(tmp_path / "state.sqlite3"), "a" * 40)
