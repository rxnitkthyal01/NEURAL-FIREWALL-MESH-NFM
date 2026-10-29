"""Bearer-authenticated local controller API for administrative state."""

from __future__ import annotations

import hmac
import os
import uuid
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from fastapi import Depends, FastAPI, HTTPException, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from nfm.crypto.policy_signing import create_bundle
from nfm.identity.credentials import issue_from_csr
from nfm.policy.engine import validate_policy
from nfm.storage.database import Store

bearer = HTTPBearer(auto_error=False)


class EnrollmentRequest(BaseModel):
    request_id: str = Field(min_length=36, max_length=36)
    node_id: str = Field(min_length=1, max_length=128)
    role: str = Field(min_length=1, max_length=63)
    csr_pem: str = Field(min_length=1, max_length=20000)


class NodeStateUpdate(BaseModel):
    security_state: str
    recovery_approved: bool = False


def create_app(db: Store, admin_token: str | None = None,
               policy_signing_key: Path | None = None,
               ca_directory: Path | None = None) -> FastAPI:
    token = admin_token or os.environ.get("NFM_ADMIN_TOKEN", "")
    if len(token) < 32:
        raise ValueError("Set NFM_ADMIN_TOKEN to a random secret of at least 32 characters")
    other_tokens = [os.environ.get("NFM_ENROLLMENT_TOKEN", ""), os.environ.get("NFM_AGENT_TOKEN", "")]
    if any(secret and len(secret) < 32 for secret in other_tokens):
        raise ValueError("Configured enrollment and agent tokens must be at least 32 characters")
    configured = [token, *(secret for secret in other_tokens if secret)]
    if len(configured) != len(set(configured)):
        raise ValueError("NFM_ADMIN_TOKEN, NFM_ENROLLMENT_TOKEN, and NFM_AGENT_TOKEN must be distinct")
    app = FastAPI(title="NFM Controller API", version="0.1.0", docs_url=None, redoc_url=None)

    async def authorize(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> None:
        if credentials is None or credentials.scheme.lower() != "bearer" or not hmac.compare_digest(credentials.credentials, token):
            raise HTTPException(status_code=401, detail="Administrative authentication required",
                                headers={"WWW-Authenticate": "Bearer"})

    async def authorize_enrollment(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> None:
        enrollment_token = os.environ.get("NFM_ENROLLMENT_TOKEN", "")
        if len(enrollment_token) < 32:
            raise HTTPException(status_code=503, detail="Enrollment is not configured")
        if credentials is None or credentials.scheme.lower() != "bearer" or not hmac.compare_digest(credentials.credentials, enrollment_token):
            raise HTTPException(status_code=401, detail="Enrollment token required",
                                headers={"WWW-Authenticate": "Bearer"})

    async def authorize_agent(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> None:
        agent_token = os.environ.get("NFM_AGENT_TOKEN", "")
        if len(agent_token) < 32:
            raise HTTPException(status_code=503, detail="Agent synchronization is not configured")
        if credentials is None or credentials.scheme.lower() != "bearer" or not hmac.compare_digest(credentials.credentials, agent_token):
            raise HTTPException(status_code=401, detail="Agent token required",
                                headers={"WWW-Authenticate": "Bearer"})

    @app.get("/api/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/nodes", dependencies=[Depends(authorize)])
    async def nodes() -> list[dict[str, Any]]:
        return db.nodes()

    @app.post("/api/nodes/{node_id}/revoke", dependencies=[Depends(authorize)])
    async def revoke(node_id: str) -> dict[str, Any]:
        if not db.revoke(node_id):
            raise HTTPException(status_code=404, detail="Active node not found")
        return {"node_id": node_id, "status": "revoked"}

    @app.post("/api/nodes/{node_id}/state", dependencies=[Depends(authorize)])
    async def set_node_state(node_id: str, update: NodeStateUpdate) -> dict[str, str]:
        try:
            db.set_security_state(node_id, update.security_state, recovery_approved=update.recovery_approved)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {"node_id": node_id, "security_state": update.security_state}

    @app.get("/api/security/events", dependencies=[Depends(authorize)])
    async def events(limit: int = 100) -> list[dict[str, Any]]:
        if not 1 <= limit <= 1000:
            raise HTTPException(status_code=422, detail="limit must be between 1 and 1000")
        return db.events(limit)

    @app.get("/api/sessions", dependencies=[Depends(authorize)])
    async def sessions(limit: int = 100) -> list[dict[str, Any]]:
        if not 1 <= limit <= 1000:
            raise HTTPException(status_code=422, detail="limit must be between 1 and 1000")
        return db.sessions(limit)

    @app.post("/api/sessions/{session_id}/revoke", dependencies=[Depends(authorize)])
    async def revoke_session(session_id: str) -> dict[str, str]:
        if not db.revoke_session(session_id):
            raise HTTPException(status_code=404, detail="Active session not found")
        return {"session_id": session_id, "status": "revocation_requested"}

    @app.get("/api/policies/active", dependencies=[Depends(authorize)])
    async def active_policy() -> dict[str, Any] | None:
        return db.active_policy()

    @app.get("/api/policies/active/bundle", dependencies=[Depends(authorize)])
    async def active_policy_bundle() -> dict[str, Any]:
        policy = db.active_policy()
        if policy is None:
            raise HTTPException(status_code=404, detail="No active policy")
        if policy_signing_key is None or not policy_signing_key.is_file():
            raise HTTPException(status_code=503, detail="Policy signing key is unavailable")
        return create_bundle(policy, policy_signing_key)

    @app.get("/api/mesh/snapshot", dependencies=[Depends(authorize_agent)])
    async def mesh_snapshot() -> dict[str, Any]:
        policy = db.active_policy()
        bundle = None
        if policy is not None:
            if policy_signing_key is None or not policy_signing_key.is_file():
                raise HTTPException(status_code=503, detail="Policy signing key is unavailable")
            bundle = create_bundle(policy, policy_signing_key)
        nodes = db.nodes()
        return {
            "policy_bundle": bundle,
            "nodes": [{field: node[field] for field in
                       ("node_id", "role", "cert_serial", "cert_expires_at", "status", "security_state", "enrolled_at")}
                      for node in nodes],
        }

    @app.put("/api/policies/active", dependencies=[Depends(authorize)])
    async def activate_policy(policy: dict[str, Any]) -> dict[str, Any]:
        try:
            validate_policy(policy)
            db.set_policy(policy)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {"policy_id": policy["policy_id"], "version": policy["version"], "status": "active"}

    @app.post("/api/policies/validate", dependencies=[Depends(authorize)])
    async def validate_policy_document(policy: dict[str, Any]) -> dict[str, Any]:
        try:
            validated = validate_policy(policy)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {"policy_id": validated["policy_id"], "version": validated["version"], "valid": True}

    @app.post("/api/enrollment-requests", dependencies=[Depends(authorize_enrollment)])
    async def submit_enrollment(request: EnrollmentRequest) -> dict[str, str]:
        try:
            csr = x509.load_pem_x509_csr(request.csr_pem.encode("ascii"))
            common_names = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if not csr.is_signature_valid or len(common_names) != 1 or common_names[0].value != request.node_id:
                raise ValueError("CSR signature or node identity is invalid")
            uuid.UUID(request.request_id)
            request_id = request.request_id
            db.request_enrollment(request_id, request.node_id, request.role, request.csr_pem)
            stored = db.enrollment(request_id)
        except (ValueError, UnicodeEncodeError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {"request_id": request_id,
                "status": "approved" if stored and stored["status"] == "approved" else "pending_approval"}

    @app.get("/api/enrollment-requests", dependencies=[Depends(authorize)])
    async def list_enrollment_requests() -> list[dict[str, Any]]:
        return db.pending_enrollments()

    @app.post("/api/enrollment-requests/{request_id}/approve", dependencies=[Depends(authorize)])
    async def approve_enrollment(request_id: str) -> dict[str, str]:
        request = db.enrollment(request_id)
        if request is None or request["status"] != "pending":
            raise HTTPException(status_code=404, detail="Pending enrollment request not found")
        if ca_directory is None:
            raise HTTPException(status_code=503, detail="CA signing key is unavailable")
        try:
            cert = issue_from_csr(request["csr_pem"].encode("ascii"), ca_directory,
                                 request["node_id"], request["role"])
            cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
            db.approve_enrollment(request_id, cert_pem, str(cert.serial_number), cert.not_valid_after_utc.isoformat())
        except (OSError, ValueError, UnicodeEncodeError) as exc:
            raise HTTPException(status_code=422, detail=f"Enrollment approval failed: {exc}") from exc
        return {"request_id": request_id, "status": "approved"}

    @app.get("/api/enrollment-requests/{request_id}/credential", dependencies=[Depends(authorize_enrollment)])
    async def enrollment_credential(request_id: str, response: Response) -> dict[str, str]:
        request = db.enrollment(request_id)
        if request is None:
            raise HTTPException(status_code=404, detail="Enrollment request not found")
        if request["status"] != "approved" or not request["cert_pem"]:
            response.status_code = status.HTTP_202_ACCEPTED
            return {"status": "pending_approval"}
        return {"status": "approved", "certificate_pem": request["cert_pem"]}

    return app
