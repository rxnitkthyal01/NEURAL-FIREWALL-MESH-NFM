import json
import urllib.request

import pytest

from nfm.controller.client import admin_request


class Response:
    def __init__(self, body: bytes):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def read(self, limit: int) -> bytes:
        assert limit == 2_000_001
        return self.body


def test_admin_request_uses_bearer_and_json(monkeypatch):
    observed = {}

    def fake_open(request, timeout):
        observed["request"] = request
        observed["timeout"] = timeout
        return Response(b'{"status":"ok"}')

    monkeypatch.setattr(urllib.request, "urlopen", fake_open)
    result = admin_request(
        "https://controller.example", "x" * 32, "/api/nodes/node-a/state",
        method="POST", payload={"security_state": "ISOLATED"},
    )

    request = observed["request"]
    assert result == {"status": "ok"}
    assert observed["timeout"] == 10
    assert request.get_header("Authorization") == f"Bearer {'x' * 32}"
    assert json.loads(request.data) == {"security_state": "ISOLATED"}
    assert request.get_method() == "POST"


@pytest.mark.parametrize(
    "url",
    ["http://controller.example", "https://user:password@controller.example", "https://controller.example/path"],
)
def test_admin_request_rejects_unsafe_controller_origins(url):
    with pytest.raises(ValueError):
        admin_request(url, "x" * 32, "/api/nodes")


def test_admin_request_rejects_unexpected_query_parameters():
    with pytest.raises(ValueError, match="invalid controller API path"):
        admin_request("https://controller.example", "x" * 32, "/api/nodes?all=true")
