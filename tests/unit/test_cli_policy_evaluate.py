from typer.testing import CliRunner

from nfm.cli.main import app
from nfm.storage.database import Store


def _prepare_state(path):
    db = Store(path)
    db.enroll("node-a", "application", "123", "2030-01-01T00:00:00+00:00")
    db.set_policy({"policy_id": "cli-test", "version": 1, "rules": [
        {"effect": "allow", "source_roles": ["application"], "services": ["db"], "operations": ["connect"]}
    ]})
    return db


def test_policy_evaluate_denies_stale_controller_state(tmp_path, monkeypatch):
    monkeypatch.setenv("NFM_HOME", str(tmp_path))
    monkeypatch.setenv("NFM_MAX_OFFLINE_AGE_SECONDS", "300")
    db = _prepare_state(tmp_path / "nfm.sqlite3")
    db.mark_sync_required()
    db.connection.execute(
        "UPDATE agent_sync_state SET last_success_at='2000-01-01T00:00:00+00:00' WHERE singleton=1"
    )
    db.connection.commit()
    db.connection.close()

    result = CliRunner().invoke(app, ["policy", "evaluate", "node-a", "application", "db"])
    assert result.exit_code == 1
    assert "DENY: controller_sync_stale" in result.output


def test_policy_evaluate_uses_current_local_state_before_sync_is_configured(tmp_path, monkeypatch):
    monkeypatch.setenv("NFM_HOME", str(tmp_path))
    _prepare_state(tmp_path / "nfm.sqlite3").connection.close()

    result = CliRunner().invoke(app, ["policy", "evaluate", "node-a", "application", "db"])
    assert result.exit_code == 0
    assert "ALLOW: explicit_allow" in result.output


def test_policy_evaluate_fails_closed_on_malformed_local_expiration(tmp_path, monkeypatch):
    monkeypatch.setenv("NFM_HOME", str(tmp_path))
    db = Store(tmp_path / "nfm.sqlite3")
    db.enroll("node-a", "application", "123", "not-a-timestamp")
    db.set_policy({"policy_id": "cli-test", "version": 1, "rules": [
        {"effect": "allow", "source_roles": ["application"], "services": ["db"], "operations": ["connect"]}
    ]})
    db.connection.close()

    result = CliRunner().invoke(app, ["policy", "evaluate", "node-a", "application", "db"])
    assert result.exit_code == 1
    assert "DENY: credential_invalid" in result.output
