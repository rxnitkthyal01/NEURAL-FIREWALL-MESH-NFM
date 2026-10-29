from typer.testing import CliRunner

from nfm.cli.main import app


def test_node_fetch_rejects_path_traversal_before_network_or_file_access(tmp_path, monkeypatch):
    monkeypatch.setenv("NFM_HOME", str(tmp_path))
    monkeypatch.setenv("NFM_ENROLLMENT_TOKEN", "e" * 40)
    monkeypatch.setattr(
        "nfm.cli.main.controller_request",
        lambda *args: (_ for _ in ()).throw(AssertionError("network request must not run")),
    )
    result = CliRunner().invoke(
        app,
        ["node", "fetch", "../outside", "00000000-0000-0000-0000-000000000001",
         "--controller-url", "https://controller.example"],
    )
    assert result.exit_code == 2
    assert "invalid node ID" in result.output
    assert not (tmp_path / "outside-key.pem").exists()


def test_node_fetch_rejects_non_uuid_request_id(tmp_path, monkeypatch):
    monkeypatch.setenv("NFM_HOME", str(tmp_path))
    monkeypatch.setenv("NFM_ENROLLMENT_TOKEN", "e" * 40)
    result = CliRunner().invoke(
        app,
        ["node", "fetch", "node-a", "../../outside", "--controller-url", "https://controller.example"],
    )
    assert result.exit_code == 2
    assert "request ID must be a UUID" in result.output
