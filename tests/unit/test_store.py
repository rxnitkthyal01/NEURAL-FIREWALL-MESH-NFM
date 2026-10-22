import sqlite3

from nfm.storage.database import Store


def test_enrollment_revocation_and_audit_are_persistent(tmp_path):
    path = tmp_path / "state.sqlite3"
    db = Store(path)
    assert db.revoked("missing")
    db.enroll("node-a", "application", "123", "2030-01-01T00:00:00+00:00")
    assert not db.revoked("node-a")
    assert db.revoke("node-a")
    assert db.revoked("node-a")
    assert any(row["event_type"] == "identity_revoked" for row in db.events())
    db.connection.close()
    assert Store(path).revoked("node-a")


def test_stale_policy_versions_are_rejected(tmp_path):
    db = Store(tmp_path / "state.sqlite3")
    rule = {"effect": "allow", "source_roles": ["app"], "services": ["db"], "operations": ["connect"]}
    db.set_policy({"policy_id": "p", "version": 2, "rules": [rule]})
    try:
        db.set_policy({"policy_id": "p", "version": 1, "rules": [rule]})
    except ValueError as exc:
        assert "stale" in str(exc)
    else:
        raise AssertionError("stale policy was activated")


def test_security_state_restriction_and_approved_recovery_are_audited(tmp_path):
    db = Store(tmp_path / "state.sqlite3")
    db.enroll("node-a", "application", "123", "2030-01-01T00:00:00+00:00")
    db.set_security_state("node-a", "ISOLATED")
    try:
        db.set_security_state("node-a", "RESTRICTED")
    except ValueError as exc:
        assert "recovery approval" in str(exc)
    else:
        raise AssertionError("partial recovery without approval was accepted")
    try:
        db.set_security_state("node-a", "HEALTHY")
    except ValueError as exc:
        assert "recovery approval" in str(exc)
    else:
        raise AssertionError("recovery without approval was accepted")
    db.set_security_state("node-a", "HEALTHY", recovery_approved=True)
    node = next(item for item in db.nodes() if item["node_id"] == "node-a")
    assert node["security_state"] == "HEALTHY"
    transitions = [event for event in db.events() if event["event_type"] == "security_state_changed"]
    assert len(transitions) == 2
    db.connection.close()


def test_store_adds_security_state_to_existing_schema(tmp_path):
    path = tmp_path / "old-state.sqlite3"
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE nodes (node_id TEXT PRIMARY KEY, role TEXT NOT NULL, cert_serial TEXT NOT NULL, "
        "cert_expires_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', enrolled_at TEXT NOT NULL, revoked_at TEXT)"
    )
    connection.execute(
        "INSERT INTO nodes(node_id,role,cert_serial,cert_expires_at,enrolled_at) "
        "VALUES('old-node','app','99','2030-01-01T00:00:00+00:00','2026-01-01T00:00:00+00:00')"
    )
    connection.commit()
    connection.close()
    db = Store(path)
    assert db.nodes()[0]["security_state"] == "HEALTHY"
    assert db.connection.execute("SELECT version FROM schema_migrations").fetchone()[0] == 1
    db.connection.close()
