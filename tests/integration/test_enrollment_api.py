from fastapi.testclient import TestClient

from nfm.controller.api import create_app
from nfm.identity.credentials import create_ca, create_enrollment_csr
from nfm.storage.database import Store


def test_remote_enrollment_requires_token_and_admin_approval(tmp_path, monkeypatch):
    ca, agent = tmp_path / "ca", tmp_path / "agent"
    create_ca(ca)
    csr = create_enrollment_csr(agent, "node-a", "application").decode("ascii")
    monkeypatch.setenv("NFM_ENROLLMENT_TOKEN", "e" * 48)
    db = Store(tmp_path / "controller.sqlite3")
    app = create_app(db, "a" * 48, ca_directory=ca)
    client = TestClient(app)
    body = {"request_id": "12345678-1234-4234-8234-123456789abc", "node_id": "node-a",
            "role": "application", "csr_pem": csr}
    assert client.post("/api/enrollment-requests", json=body).status_code == 401
    enrollment_headers = {"Authorization": "Bearer " + "e" * 48}
    admin_headers = {"Authorization": "Bearer " + "a" * 48}
    submitted = client.post("/api/enrollment-requests", json=body, headers=enrollment_headers)
    assert submitted.status_code == 200
    assert client.post("/api/enrollment-requests", json=body, headers=enrollment_headers).json() == submitted.json()
    request_id = submitted.json()["request_id"]
    assert client.get("/api/enrollment-requests").status_code == 401
    assert len(client.get("/api/enrollment-requests", headers=admin_headers).json()) == 1
    pending = client.get(f"/api/enrollment-requests/{request_id}/credential", headers=enrollment_headers)
    assert pending.status_code == 202
    approved = client.post(f"/api/enrollment-requests/{request_id}/approve", headers=admin_headers)
    assert approved.status_code == 200
    credential = client.get(f"/api/enrollment-requests/{request_id}/credential", headers=enrollment_headers)
    assert credential.status_code == 200
    assert "BEGIN CERTIFICATE" in credential.json()["certificate_pem"]
    assert db.nodes()[0]["node_id"] == "node-a"
    db.connection.close()
