from io import StringIO

from rich.console import Console

from nfm.cli.dashboard import build_dashboard
from nfm.storage.database import Store


def test_terminal_dashboard_uses_local_store_and_fits_small_terminal(tmp_path):
    db = Store(tmp_path / "state.sqlite3")
    db.enroll("client-a", "application", "123", "2030-01-01T00:00:00+00:00")
    db.set_policy({
        "policy_id": "example",
        "version": 1,
        "rules": [{
            "effect": "allow",
            "source_roles": ["application"],
            "services": ["database"],
            "operations": ["connect"],
        }],
    })
    db.start_session("session-1", "client-a", "database")
    db.event("client-a", "authorization_decision", "info", {"allowed": True})

    output = StringIO()
    Console(file=output, width=72, color_system=None).print(build_dashboard(db))
    rendered = output.getvalue()

    assert "NODES" in rendered
    assert "client-a" in rendered
    assert "example v1" in rendered
    assert "database" in rendered
    assert "authorization" in rendered
    assert "Local records only" in rendered
    db.connection.close()
