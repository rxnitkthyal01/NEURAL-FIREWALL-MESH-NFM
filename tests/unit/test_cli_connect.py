from typer.testing import CliRunner

from nfm.cli.main import app


def test_connect_reports_empty_response_as_ambiguous_failure(monkeypatch):
    monkeypatch.setattr("nfm.cli.main.exchange", lambda **kwargs: b"")
    monkeypatch.setattr("nfm.cli.main.asyncio.run", lambda coroutine: b"")
    result = CliRunner().invoke(
        app,
        ["connect", "--node-id", "client-a", "--server-node-id", "server-b",
         "--host", "127.0.0.1", "--port", "9443", "--data", "hello"],
    )
    assert result.exit_code == 1
    assert "distinguish a policy denial" in result.output
