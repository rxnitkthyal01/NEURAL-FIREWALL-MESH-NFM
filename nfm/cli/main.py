"""NFM command-line entry point."""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote, urlsplit

import typer
import yaml
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.x509.oid import NameOID
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.text import Text

from nfm import __version__
from nfm.cli.dashboard import build_dashboard
from nfm.controller.api import create_app
from nfm.controller.client import ControllerAdminError, admin_request
from nfm.crypto.policy_signing import create_bundle, create_signing_key, verify_bundle
from nfm.crypto.transport import exchange
from nfm.enforcement.proxy import ProtectedProxy
from nfm.identity.credentials import (
    certificate_node_id,
    create_ca,
    create_enrollment_csr,
    issue_from_csr,
    issue_node,
)
from nfm.mesh.sync import controller_request, sync_once
from nfm.policy.engine import evaluate, load_policy, validate_policy
from nfm.storage.database import Store

app = typer.Typer(no_args_is_help=True, help="Neural Firewall Mesh: cryptographic identity and explicit TCP service authorization")
node_app = typer.Typer(no_args_is_help=True)
policy_app = typer.Typer(no_args_is_help=True)
security_app = typer.Typer(no_args_is_help=True)
mesh_app = typer.Typer(no_args_is_help=True)
session_app = typer.Typer(no_args_is_help=True)
agent_app = typer.Typer(no_args_is_help=True)
admin_app = typer.Typer(no_args_is_help=True, help="Manage a remote controller over authenticated HTTPS")
app.add_typer(node_app, name="node")
app.add_typer(policy_app, name="policy")
app.add_typer(security_app, name="security")
app.add_typer(mesh_app, name="mesh")
app.add_typer(session_app, name="session")
app.add_typer(agent_app, name="agent")
app.add_typer(admin_app, name="admin")


@dataclass(frozen=True)
class AdminTarget:
    controller_url: str
    token: str


@admin_app.callback()
def admin_context(
    ctx: typer.Context,
    controller_url: str = typer.Option("https://localhost:8443", envvar="NFM_CONTROLLER_URL", help="HTTPS controller origin"),
    admin_token: str | None = typer.Option(
        None, envvar="NFM_ADMIN_TOKEN", prompt="Admin token", hide_input=True
    ),
) -> None:
    """Set the remote controller and admin token for this command."""
    if not admin_token:
        raise typer.BadParameter("set NFM_ADMIN_TOKEN")
    ctx.obj = AdminTarget(controller_url, admin_token)


def _admin_call(
    ctx: typer.Context, path: str, *, method: str = "GET", payload: object = None
) -> object:
    target: AdminTarget = ctx.obj
    try:
        return admin_request(target.controller_url, target.token, path, method=method, payload=payload)
    except (ControllerAdminError, OSError, ValueError) as exc:
        typer.echo(f"Controller request failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc


def _admin_table(rows: object, columns: tuple[tuple[str, str], ...], as_json: bool) -> None:
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        typer.echo("Controller returned an unexpected response format.", err=True)
        raise typer.Exit(code=1)
    if as_json:
        typer.echo(json.dumps(rows, indent=2))
        return
    table = Table(show_header=True, header_style="bold cyan", expand=True)
    for heading, _ in columns:
        table.add_column(heading, overflow="ellipsis", no_wrap=True)
    for row in rows:
        table.add_row(*(Text(str(row.get(key, "-")), no_wrap=True, overflow="ellipsis") for _, key in columns))
    Console().print(table)


@admin_app.command("nodes")
def admin_nodes(ctx: typer.Context, as_json: bool = typer.Option(False, "--json")) -> None:
    """List nodes from the remote controller."""
    _admin_table(_admin_call(ctx, "/api/nodes"), (("Node", "node_id"), ("Role", "role"),
                 ("Identity", "status"), ("State", "security_state"), ("Expires", "cert_expires_at")), as_json)


@admin_app.command("events")
def admin_events(ctx: typer.Context, limit: int = typer.Option(100, min=1, max=1000),
                 as_json: bool = typer.Option(False, "--json")) -> None:
    """Show security events stored by the remote controller."""
    _admin_table(_admin_call(ctx, f"/api/security/events?limit={limit}"),
                 (("Time", "created_at"), ("Severity", "severity"), ("Event", "event_type"),
                  ("Node", "node_id"), ("Details", "details")), as_json)


@admin_app.command("policy")
def admin_policy(ctx: typer.Context) -> None:
    """Show the remote controller's active policy."""
    policy = _admin_call(ctx, "/api/policies/active")
    typer.echo(json.dumps(policy, indent=2) if policy is not None else "No active policy (default deny).")


@admin_app.command("revoke-node")
def admin_revoke_node(ctx: typer.Context, node_id: str) -> None:
    """Revoke a node identity on the remote controller."""
    result = _admin_call(ctx, f"/api/nodes/{quote(node_id, safe='')}/revoke", method="POST")
    typer.echo(json.dumps(result, indent=2))


@admin_app.command("set-node-state")
def admin_set_node_state(
    ctx: typer.Context,
    node_id: str,
    security_state: str,
    approve_recovery: bool = typer.Option(False, "--approve-recovery"),
) -> None:
    """Set a node's security state on the remote controller."""
    result = _admin_call(
        ctx, f"/api/nodes/{quote(node_id, safe='')}/state", method="POST",
        payload={"security_state": security_state.upper(), "recovery_approved": approve_recovery},
    )
    typer.echo(json.dumps(result, indent=2))


@admin_app.command("validate-policy")
def admin_validate_policy(ctx: typer.Context, file: Path) -> None:
    """Validate a local YAML policy using the remote controller."""
    try:
        policy = load_policy(file)
    except (OSError, ValueError) as exc:
        typer.echo(f"Policy file rejected: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    result = _admin_call(ctx, "/api/policies/validate", method="POST", payload=policy)
    typer.echo(json.dumps(result, indent=2))


@admin_app.command("activate-policy")
def admin_activate_policy(ctx: typer.Context, file: Path) -> None:
    """Validate and activate a local YAML policy on the remote controller."""
    try:
        policy = load_policy(file)
    except (OSError, ValueError) as exc:
        typer.echo(f"Policy file rejected: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    _admin_call(ctx, "/api/policies/validate", method="POST", payload=policy)
    result = _admin_call(ctx, "/api/policies/active", method="PUT", payload=policy)
    typer.echo(json.dumps(result, indent=2))


@admin_app.command("enrollment-requests")
def admin_enrollment_requests(ctx: typer.Context) -> None:
    """List enrollment requests awaiting controller approval."""
    _admin_table(_admin_call(ctx, "/api/enrollment-requests"),
                 (("Request", "request_id"), ("Node", "node_id"),
                  ("Role", "role"), ("Requested", "requested_at")), False)


@admin_app.command("approve-enrollment")
def admin_approve_enrollment(ctx: typer.Context, request_id: str) -> None:
    """Approve a pending remote enrollment request."""
    result = _admin_call(
        ctx, f"/api/enrollment-requests/{quote(request_id, safe='')}/approve", method="POST"
    )
    typer.echo(json.dumps(result, indent=2))


@app.command("tui")
def terminal_dashboard(
    refresh: int = typer.Option(5, min=1, max=60, help="Refresh interval in seconds"),
    once: bool = typer.Option(False, help="Render one snapshot and exit"),
) -> None:
    """Show a live, read-only terminal view of this local NFM store."""
    db = store()
    console = Console()
    try:
        if once:
            console.print(build_dashboard(db))
            return
        with Live(build_dashboard(db), console=console, refresh_per_second=4, screen=True) as live:
            while True:
                time.sleep(refresh)
                live.update(build_dashboard(db), refresh=True)
    except KeyboardInterrupt:
        pass
    finally:
        db.connection.close()


def state_dir() -> Path:
    return Path(os.environ.get("NFM_HOME", str(Path.home() / ".nfm"))).expanduser()


def store() -> Store:
    return Store(state_dir() / "nfm.sqlite3")


@app.command()
def version() -> None:
    """Print the installed NFM version."""
    typer.echo(f"nfm {__version__}")


@app.command()
def init() -> None:
    """Initialize local state and a local enrollment CA."""
    root = state_dir()
    root.mkdir(parents=True, exist_ok=True)
    try:
        create_ca(root / "ca")
    except FileExistsError:
        typer.echo("CA already exists; leaving existing key material untouched.")
    try:
        create_signing_key(root / "policy-signing-key.pem", root / "policy-signing-public.pem")
    except FileExistsError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    store().connection.close()
    typer.echo(f"Initialized NFM state at {root}")
    typer.echo("Protect the ca/ca-key.pem file: anyone holding it can issue node identities.")


@node_app.command("issue")
def node_issue(node_id: str = typer.Argument(...), role: str = typer.Option(..., help="Workload role, e.g. application"),
               days: int = typer.Option(30, min=1, max=90)) -> None:
    """Issue a short-lived identity (local bootstrap workflow)."""
    root = state_dir()
    try:
        issue_node(root / "identities", root / "ca", node_id, role, days=days)
        cert = x509.load_pem_x509_certificate((root / "identities" / f"{node_id}-cert.pem").read_bytes())
        store().enroll(node_id, role, str(cert.serial_number), cert.not_valid_after_utc.isoformat())
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(f"Issued identity {node_id} (role={role}, expires={cert.not_valid_after_utc.isoformat()})")
    typer.echo(f"Private key: {root / 'identities' / f'{node_id}-key.pem'}")


@node_app.command("list")
def node_list(as_json: bool = typer.Option(False, "--json")) -> None:
    """List locally enrolled identities."""
    import json
    nodes = store().nodes()
    if as_json:
        typer.echo(json.dumps(nodes, indent=2))
        return
    for node in nodes:
        typer.echo(f"{node['node_id']}\t{node['role']}\t{node['status']}\t{node['security_state']}\t{node['cert_expires_at']}")
    if not nodes:
        typer.echo("No enrolled nodes.")


@node_app.command("inspect")
def node_inspect(node_id: str) -> None:
    """Show the locally stored, non-secret identity record."""
    import json
    node = next((item for item in store().nodes() if item["node_id"] == node_id), None)
    if node is None:
        typer.echo(f"Unknown node: {node_id}", err=True)
        raise typer.Exit(code=2)
    typer.echo(json.dumps(node, indent=2))


@node_app.command("revoke")
def node_revoke(node_id: str) -> None:
    """Revoke an enrolled identity in this controller's local state."""
    if not store().revoke(node_id):
        typer.echo(f"No active enrollment found for {node_id}.", err=True)
        raise typer.Exit(code=2)
    typer.echo(f"Revoked {node_id}; connected proxy sessions recheck revocation within one second.")


@node_app.command("state")
def node_state(node_id: str, state: str = typer.Argument(..., help="HEALTHY, DEGRADED, RESTRICTED, or ISOLATED"),
               approve_recovery: bool = typer.Option(False, "--approve-recovery",
                                                     help="Required to reduce RESTRICTED/ISOLATED state")) -> None:
    """Set an auditable node security state; restrictive states deny service access."""
    db = store()
    try:
        db.set_security_state(node_id, state.upper(), recovery_approved=approve_recovery)
    except ValueError as exc:
        typer.echo(f"Security state change rejected: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    finally:
        db.connection.close()
    typer.echo(f"Updated {node_id} security state to {state.upper()}.")


@node_app.command("requests")
def node_requests() -> None:
    """List enrollment requests awaiting local administrator approval."""
    pending = store().pending_enrollments()
    for request in pending:
        typer.echo(f"{request['request_id']}\t{request['node_id']}\t{request['role']}\t{request['requested_at']}")
    if not pending:
        typer.echo("No pending enrollment requests.")


@node_app.command("approve")
def node_approve(request_id: str) -> None:
    """Approve a pending CSR and issue a controller-signed node certificate."""
    db = store()
    request = db.enrollment(request_id)
    if request is None or request["status"] != "pending":
        typer.echo("Pending enrollment request not found.", err=True)
        raise typer.Exit(code=2)
    try:
        cert = issue_from_csr(request["csr_pem"].encode("ascii"), state_dir() / "ca",
                             request["node_id"], request["role"])
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
        db.approve_enrollment(request_id, cert_pem, str(cert.serial_number), cert.not_valid_after_utc.isoformat())
    except (OSError, ValueError) as exc:
        typer.echo(f"Enrollment approval failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"Approved {request['node_id']} ({request['role']}); agent can now fetch its certificate.")


@node_app.command("request")
def node_request(node_id: str, role: str = typer.Option(...),
                 controller_url: str = typer.Option(..., help="HTTPS controller origin"),
                 enrollment_token: str | None = typer.Option(None, envvar="NFM_ENROLLMENT_TOKEN", hide_input=True)) -> None:
    """Generate a local key/CSR and request administrator-approved enrollment."""
    if not enrollment_token or len(enrollment_token) < 32:
        typer.echo("Set NFM_ENROLLMENT_TOKEN to the enrollment secret.", err=True)
        raise typer.Exit(code=2)
    request_dir = state_dir() / "pending"
    try:
        try:
            csr = create_enrollment_csr(request_dir, node_id, role)
        except FileExistsError:
            csr = (request_dir / f"{node_id}.csr.pem").read_bytes()
            parsed_csr = x509.load_pem_x509_csr(csr)
            names = parsed_csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if not parsed_csr.is_signature_valid or len(names) != 1 or names[0].value != node_id:
                raise ValueError("existing local CSR is invalid") from None
        # Check transport scheme before sending the enrollment bearer secret.
        parsed_url = urlsplit(controller_url)
        if parsed_url.scheme != "https" or not parsed_url.hostname or parsed_url.username or parsed_url.password or parsed_url.query or parsed_url.fragment:
            raise ValueError("remote enrollment requires HTTPS")
        metadata = request_dir / f"{node_id}-request.json"
        if metadata.is_file():
            saved_request = json.loads(metadata.read_text(encoding="utf-8"))
            request_id = saved_request.get("request_id") if isinstance(saved_request, dict) else None
            try:
                uuid.UUID(request_id)
            except (ValueError, TypeError, AttributeError) as exc:
                raise ValueError("saved enrollment request metadata is malformed") from exc
        else:
            request_id = str(uuid.uuid4())
            metadata.write_text(json.dumps({"request_id": request_id}), encoding="utf-8")
        url = controller_url.rstrip("/") + "/api/enrollment-requests"
        request = urllib.request.Request(url, data=json.dumps({
            "request_id": request_id, "node_id": node_id, "role": role, "csr_pem": csr.decode("ascii")
        }).encode("utf-8"), headers={"Authorization": f"Bearer {enrollment_token}",
                                    "Content-Type": "application/json", "Accept": "application/json"})
        with urllib.request.urlopen(request, timeout=10) as response:
            result = json.loads(response.read(65536))
    except (OSError, ValueError) as exc:
        typer.echo(f"Enrollment request failed: {type(exc).__name__}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"Enrollment request submitted: {result['request_id']}")
    typer.echo("The node private key stays local. An administrator must approve the request.")


@node_app.command("fetch")
def node_fetch(node_id: str, request_id: str,
               controller_url: str = typer.Option(..., help="HTTPS controller origin"),
               enrollment_token: str | None = typer.Option(None, envvar="NFM_ENROLLMENT_TOKEN", hide_input=True)) -> None:
    """Fetch an approved certificate and bind it to the locally generated private key."""
    if not enrollment_token or len(enrollment_token) < 32:
        typer.echo("Set NFM_ENROLLMENT_TOKEN to the enrollment secret.", err=True)
        raise typer.Exit(code=2)
    try:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", node_id):
            raise ValueError("invalid node ID")
        try:
            request_id = str(uuid.UUID(request_id))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError("request ID must be a UUID") from exc
        parsed_url = urlsplit(controller_url)
        if parsed_url.scheme != "https" or not parsed_url.hostname or parsed_url.username or parsed_url.password or parsed_url.query or parsed_url.fragment:
            raise ValueError("credential retrieval requires HTTPS")
        result = controller_request(controller_url,
                                    f"/api/enrollment-requests/{request_id}/credential", enrollment_token)
        if result.get("status") != "approved":
            typer.echo("Enrollment is still awaiting administrator approval.")
            raise typer.Exit(code=3)
        cert_pem = result["certificate_pem"].encode("ascii")
        cert = x509.load_pem_x509_certificate(cert_pem)
        ca_cert = x509.load_pem_x509_certificate((state_dir() / "ca" / "ca-cert.pem").read_bytes())
        if ca_cert.subject != cert.issuer:
            raise ValueError("issued certificate does not match the trusted CA")
        cert.verify_directly_issued_by(ca_cert)
        if certificate_node_id(cert) != node_id:
            raise ValueError("issued certificate node ID does not match request")
        pending_dir = state_dir() / "pending"
        key_path = pending_dir / f"{node_id}-key.pem"
        private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        if private_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo):
            raise ValueError("issued certificate does not match this node's private key")
        role_uris = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.UniformResourceIdentifier)
        role_values = [uri.removeprefix("urn:nfm:role:") for uri in role_uris if uri.startswith("urn:nfm:role:")]
        if len(role_values) != 1:
            raise ValueError("issued certificate has invalid role identity")
        identity_dir = state_dir() / "identities"
        identity_dir.mkdir(parents=True, exist_ok=True)
        final_key, final_cert = identity_dir / f"{node_id}-key.pem", identity_dir / f"{node_id}-cert.pem"
        # Preserve pending material until both replacements and local enrollment
        # commit succeed, so a failed fetch can be safely retried.
        new_key, new_cert = final_key.with_suffix(".pem.new"), final_cert.with_suffix(".pem.new")
        new_key.unlink(missing_ok=True)
        key_descriptor = os.open(new_key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(key_descriptor, "wb") as private_file:
                private_file.write(key_path.read_bytes())
        except OSError:
            new_key.unlink(missing_ok=True)
            raise
        new_cert.write_bytes(cert_pem)
        os.replace(new_key, final_key)
        os.replace(new_cert, final_cert)
        db = store()
        try:
            db.enroll(node_id, role_values[0], str(cert.serial_number), cert.not_valid_after_utc.isoformat())
        finally:
            db.connection.close()
        for pending_file in (key_path, pending_dir / f"{node_id}.csr.pem", pending_dir / f"{node_id}-request.json"):
            pending_file.unlink(missing_ok=True)
    except urllib.error.HTTPError as exc:
        typer.echo(f"Credential fetch rejected: HTTP {exc.code}", err=True)
        raise typer.Exit(code=2) from exc
    except (OSError, ValueError, KeyError, InvalidSignature, x509.ExtensionNotFound) as exc:
        typer.echo(f"Credential fetch failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"Enrolled {node_id}; credential expires {cert.not_valid_after_utc.isoformat()}")


@agent_app.command("trust-ca")
def agent_trust_ca(certificate: Path) -> None:
    """Install a controller CA certificate received through a trusted channel."""
    try:
        cert = x509.load_pem_x509_certificate(certificate.read_bytes())
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if not constraints.ca:
            raise ValueError("certificate is not a CA certificate")
        target = state_dir() / "ca" / "ca-cert.pem"
        target.parent.mkdir(parents=True, exist_ok=True)
        pem = cert.public_bytes(serialization.Encoding.PEM)
        if target.exists() and target.read_bytes() != pem:
            raise FileExistsError("a different trusted CA is already installed")
        target.write_bytes(pem)
    except (OSError, ValueError, x509.ExtensionNotFound) as exc:
        typer.echo(f"CA installation failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"Trusted CA installed at {target}")


@agent_app.command("trust-policy-key")
def agent_trust_policy_key(public_key: Path) -> None:
    """Install the controller Ed25519 verification key out of band."""
    try:
        loaded = serialization.load_pem_public_key(public_key.read_bytes())
        if not isinstance(loaded, Ed25519PublicKey):
            raise ValueError("public key is not Ed25519")
        target = state_dir() / "policy-signing-public.pem"
        target.parent.mkdir(parents=True, exist_ok=True)
        pem = loaded.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        if target.exists() and target.read_bytes() != pem:
            raise FileExistsError("a different policy signing key is already trusted")
        target.write_bytes(pem)
    except (OSError, ValueError) as exc:
        typer.echo(f"Policy key installation failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"Trusted policy signing key installed at {target}")


@agent_app.command("sync")
def agent_sync(controller_url: str = typer.Option(..., help="HTTPS controller origin"),
               agent_token: str | None = typer.Option(None, envvar="NFM_AGENT_TOKEN", hide_input=True)) -> None:
    """Fetch and verify one signed policy and node-state snapshot."""
    if not agent_token or len(agent_token) < 32:
        typer.echo("Set NFM_AGENT_TOKEN to the agent synchronization secret.", err=True)
        raise typer.Exit(code=2)
    trusted_key = state_dir() / "policy-signing-public.pem"
    if not trusted_key.is_file():
        typer.echo("Install the controller key first with nfm agent trust-policy-key.", err=True)
        raise typer.Exit(code=2)
    try:
        db = store()
        result = sync_once(controller_url, agent_token, store=db, trusted_policy_key=trusted_key)
    except (OSError, ValueError) as exc:
        typer.echo(f"Agent synchronization failed: {type(exc).__name__}", err=True)
        raise typer.Exit(code=1) from exc
    finally:
        if "db" in locals():
            db.connection.close()
    typer.echo(f"Synchronized {result['nodes']} nodes and policy version {result['policy_version']}.")


@agent_app.command("start")
def agent_start(controller_url: str = typer.Option(..., help="HTTPS controller origin"),
                interval: int = typer.Option(30, min=1, max=3600),
                agent_token: str | None = typer.Option(None, envvar="NFM_AGENT_TOKEN", hide_input=True)) -> None:
    """Run the local synchronization loop; enforcement continues from cached state offline."""
    if not agent_token or len(agent_token) < 32:
        typer.echo("Set NFM_AGENT_TOKEN to the agent synchronization secret.", err=True)
        raise typer.Exit(code=2)
    trusted_key = state_dir() / "policy-signing-public.pem"
    if not trusted_key.is_file():
        typer.echo("Install the controller key first with nfm agent trust-policy-key.", err=True)
        raise typer.Exit(code=2)
    typer.echo(f"Agent sync started; polling every {interval}s. Press Ctrl+C to stop.")
    while True:
        try:
            db = store()
            try:
                result = sync_once(controller_url, agent_token, store=db, trusted_policy_key=trusted_key)
            finally:
                db.connection.close()
            typer.echo(f"Synchronized {result['nodes']} nodes; policy v{result['policy_version']}.")
        except (OSError, ValueError) as exc:
            typer.echo(
                f"Sync failed ({type(exc).__name__}); the proxy denies when cached state exceeds "
                "NFM_MAX_OFFLINE_AGE_SECONDS, and policy rejection may deny sooner.",
                err=True,
            )
        time.sleep(interval)


@policy_app.command("validate")
def policy_validate(file: Path) -> None:
    """Validate a YAML policy without activating it."""
    try:
        policy = load_policy(file)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        typer.echo(f"Invalid policy: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"Valid policy {policy['policy_id']} version {policy['version']}")


@policy_app.command("activate")
def policy_activate(file: Path) -> None:
    """Validate and activate a policy in local persistent state."""
    try:
        policy = load_policy(file)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        typer.echo(f"Invalid policy: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    try:
        store().set_policy(policy)
    except ValueError as exc:
        typer.echo(f"Policy activation rejected: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"Activated {policy['policy_id']} version {policy['version']}")


@policy_app.command("list")
def policy_list(as_json: bool = typer.Option(False, "--json")) -> None:
    """Show the active locally enforced policy."""
    import json
    policy = store().active_policy()
    if policy is None:
        typer.echo("No active policy (all requests are denied).")
    elif as_json:
        typer.echo(json.dumps(policy, indent=2))
    else:
        typer.echo(f"{policy['policy_id']} version {policy['version']} (active)")


@policy_app.command("create")
def policy_create(output: Path = typer.Argument(..., help="Path for a new deny-by-default YAML policy"),
                  policy_id: str = typer.Option("nfm-policy", help="Policy identifier")) -> None:
    """Create a starter policy that denies every request until edited."""
    definition = {
        "policy_id": policy_id,
        "version": 1,
        "rules": [{"effect": "deny", "source_roles": ["*"], "services": ["*"], "operations": ["*"]}],
    }
    try:
        validate_policy(definition)
        with output.open("x", encoding="utf-8") as policy_file:
            yaml.safe_dump(definition, policy_file, sort_keys=False)
    except FileExistsError as exc:
        typer.echo("Refusing to overwrite an existing policy file.", err=True)
        raise typer.Exit(code=2) from exc
    except (OSError, ValueError) as exc:
        typer.echo(f"Could not create policy: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"Created deny-by-default policy at {output}; edit it, then run nfm policy validate.")


@policy_app.command("revoke")
def policy_revoke(policy_id: str) -> None:
    """Deactivate a policy; connections that no longer authorize are terminated."""
    if not store().revoke_policy(policy_id):
        typer.echo(f"No active policy found with ID {policy_id}.", err=True)
        raise typer.Exit(code=2)
    typer.echo(f"Revoked active policy {policy_id}.")


@policy_app.command("export")
def policy_export(output: Path) -> None:
    """Write the active policy as an Ed25519-signed bundle."""
    import json
    db = store()
    policy = db.active_policy()
    if policy is None:
        typer.echo("No active policy to export.", err=True)
        raise typer.Exit(code=2)
    try:
        bundle = create_bundle(policy, state_dir() / "policy-signing-key.pem")
        output.write_text(json.dumps(bundle, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError) as exc:
        typer.echo(f"Policy export failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"Signed policy bundle written to {output}")


@policy_app.command("import")
def policy_import(file: Path, trusted_key: Path = typer.Option(..., help="Out-of-band trusted Ed25519 public key PEM")) -> None:
    """Verify a signed policy bundle before local activation."""
    import json
    try:
        bundle = json.loads(file.read_text(encoding="utf-8"))
        policy = verify_bundle(bundle, trusted_key)
        store().set_policy(policy)
    except (OSError, ValueError) as exc:
        typer.echo(f"Policy import rejected: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"Verified and activated {policy['policy_id']} version {policy['version']}")


@policy_app.command("evaluate")
def policy_evaluate(node_id: str, role: str, service: str, operation: str = "connect") -> None:
    """Evaluate a request using the active local policy."""
    db = store()
    node = next((item for item in db.nodes() if item["node_id"] == node_id), None)
    credential_valid = False
    if node is not None and node["status"] == "active" and node["role"] == role:
        try:
            expiration = datetime.fromisoformat(node["cert_expires_at"])
            credential_valid = expiration.tzinfo is not None and expiration > datetime.now(UTC)
        except (TypeError, ValueError):
            # Malformed or timezone-naive stored credential timestamps fail closed.
            credential_valid = False
    decision = evaluate(db.active_policy(), node_id=node_id, role=role, service=service,
                        operation=operation, credential_valid=credential_valid,
                        revoked=db.revoked(node_id),
                        security_state=node["security_state"] if node else "ISOLATED")
    try:
        max_age = int(os.environ.get("NFM_MAX_OFFLINE_AGE_SECONDS", "300"))
        if not db.sync_is_fresh(max_age):
            decision = type(decision)(False, "controller_sync_stale", decision.policy_id, decision.version)
    except ValueError as exc:
        typer.echo(f"Offline age configuration invalid: {exc}", err=True)
        db.connection.close()
        raise typer.Exit(code=2) from exc
    db.connection.close()
    typer.echo(f"{'ALLOW' if decision.allowed else 'DENY'}: {decision.reason}")
    if not decision.allowed:
        raise typer.Exit(code=1)


@app.command("serve-proxy")
def serve_proxy(node_id: str = typer.Option(..., help="Enrolled identity used by this proxy"),
                service: str = typer.Option(..., help="Policy service name"),
                listen: str = typer.Option("127.0.0.1"), port: int = typer.Option(..., min=1, max=65535),
                upstream_host: str = typer.Option(...), upstream_port: int = typer.Option(..., min=1, max=65535)) -> None:
    """Expose a TCP service through a mutual-TLS, policy-enforcing proxy."""
    root = state_dir()
    cert = root / "identities" / f"{node_id}-cert.pem"
    key = root / "identities" / f"{node_id}-key.pem"
    ca = root / "ca" / "ca-cert.pem"
    if not all(path.is_file() for path in (cert, key, ca)):
        typer.echo("Missing node identity or CA. Run nfm init and nfm node issue first.", err=True)
        raise typer.Exit(code=2)
    try:
        asyncio.run(ProtectedProxy(store=store(), ca_cert=ca, cert=cert, key=key,
                                   service=service, target_host=upstream_host,
                                   target_port=upstream_port).start(listen, port))
    except OSError as exc:
        typer.echo(f"Could not start protected proxy: {exc}", err=True)
        raise typer.Exit(code=2) from exc


@app.command("serve-controller")
def serve_controller(host: str = typer.Option("127.0.0.1"), port: int = typer.Option(8080, min=1, max=65535)) -> None:
    """Run the administrative API; set NFM_ADMIN_TOKEN before starting."""
    import uvicorn
    try:
        api = create_app(store(), policy_signing_key=state_dir() / "policy-signing-key.pem",
                         ca_directory=state_dir() / "ca")
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    uvicorn.run(api, host=host, port=port, log_level="info")


@app.command()
def connect(node_id: str = typer.Option(..., help="Enrolled client identity"),
            server_node_id: str = typer.Option(..., help="Expected NFM identity of the proxy"),
            host: str = typer.Option(...), port: int = typer.Option(..., min=1, max=65535),
            data: str = typer.Option(..., help="UTF-8 request payload for a request/response TCP service")) -> None:
    """Send a request through the authenticated mesh to an explicitly protected service."""
    root = state_dir()
    try:
        response = asyncio.run(exchange(host=host, port=port, server_node_id=server_node_id,
                                        ca_cert=root / "ca" / "ca-cert.pem",
                                        cert=root / "identities" / f"{node_id}-cert.pem",
                                        key=root / "identities" / f"{node_id}-key.pem",
                                        payload=data.encode("utf-8") + b"\n"))
    except (OSError, ValueError) as exc:
        typer.echo(f"Connection failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    if not response:
        typer.echo(
            "Connection closed without a response; check NFM security events to distinguish "
            "a policy denial from an upstream service that returned no data.",
            err=True,
        )
        raise typer.Exit(code=1)
    typer.echo(response.decode("utf-8", errors="replace"), nl=False)


@security_app.command("events")
def security_events(limit: int = typer.Option(100, min=1, max=1000), as_json: bool = typer.Option(False, "--json")) -> None:
    """Show recent security events."""
    import json
    events = store().events(limit)
    if as_json:
        typer.echo(json.dumps(events, indent=2))
    else:
        for event in events:
            typer.echo(f"{event['created_at']}\t{event['severity'].upper()}\t{event['event_type']}\t{event['node_id'] or '-'}\t{event['details']}")


@security_app.command("audit")
def security_audit(limit: int = typer.Option(100, min=1, max=1000)) -> None:
    """Export recent audit events as JSON to stdout."""
    import json
    typer.echo(json.dumps(store().events(limit), indent=2))


@mesh_app.command("status")
def mesh_status() -> None:
    """Summarize this controller's local mesh inventory and policy state."""
    db = store()
    nodes = db.nodes()
    active = sum(node["status"] == "active" for node in nodes)
    policy = db.active_policy()
    typer.echo(f"Enrolled nodes: {len(nodes)} (active: {active})")
    typer.echo(f"Active policy: {policy['policy_id']} v{policy['version']}" if policy else "Active policy: none (default deny)")


@mesh_app.command("peers")
def mesh_peers(as_json: bool = typer.Option(False, "--json")) -> None:
    """List identities currently present in the local synchronized inventory."""
    nodes = store().nodes()
    if as_json:
        typer.echo(json.dumps(nodes, indent=2))
    elif nodes:
        for node in nodes:
            typer.echo(f"{node['node_id']}\t{node['role']}\t{node['status']}\t{node['security_state']}")
    else:
        typer.echo("No peers in local inventory.")


@agent_app.command("status")
def agent_status() -> None:
    """Show the local trust anchors and cached policy/inventory used offline."""
    root = state_dir()
    db = store()
    try:
        nodes = db.nodes()
        policy = db.active_policy()
        sync = db.sync_status()
        checks = {
            "Trusted CA": (root / "ca" / "ca-cert.pem").is_file(),
            "Policy verification key": (root / "policy-signing-public.pem").is_file(),
        }
        for label, present in checks.items():
            typer.echo(f"{label}: {'installed' if present else 'missing'}")
        typer.echo(f"Cached inventory: {len(nodes)} nodes")
        typer.echo(f"Cached policy: {policy['policy_id']} v{policy['version']}" if policy else "Cached policy: none (default deny)")
        if sync["required"]:
            try:
                max_age = int(os.environ.get("NFM_MAX_OFFLINE_AGE_SECONDS", "300"))
                fresh = db.sync_is_fresh(max_age)
            except ValueError as exc:
                typer.echo(f"Offline age configuration invalid: {exc}", err=True)
                raise typer.Exit(code=2) from exc
            typer.echo(f"Controller snapshot: {'fresh' if fresh else 'STALE / FAIL-CLOSED'}; last success: {sync['last_success_at'] or 'never'}")
        else:
            typer.echo("Controller snapshot: sync not configured")
    finally:
        db.connection.close()


@session_app.command("list")
def session_list(limit: int = typer.Option(100, min=1, max=1000), as_json: bool = typer.Option(False, "--json")) -> None:
    """List recorded protected-service sessions."""
    import json
    sessions = store().sessions(limit)
    if as_json:
        typer.echo(json.dumps(sessions, indent=2))
        return
    for session in sessions:
        typer.echo(f"{session['session_id']}\t{session['node_id']}\t{session['service']}\t{session['status']}\t{session['started_at']}")
    if not sessions:
        typer.echo("No protected sessions recorded.")


@session_app.command("revoke")
def session_revoke(session_id: str) -> None:
    """Request termination of a live protected TCP session."""
    if not store().revoke_session(session_id):
        typer.echo(f"No active session found: {session_id}", err=True)
        raise typer.Exit(code=2)
    typer.echo(f"Revocation requested for session {session_id}; proxy will close it within one second.")


@app.command()
def doctor() -> None:
    """Check the local NFM state needed by the MVP."""
    root = state_dir()
    checks = {"state directory": root.is_dir(), "database": (root / "nfm.sqlite3").is_file(),
              "CA certificate": (root / "ca" / "ca-cert.pem").is_file(),
              "CA private key": (root / "ca" / "ca-key.pem").is_file(),
              "policy signing keypair": (root / "policy-signing-key.pem").is_file() and
              (root / "policy-signing-public.pem").is_file()}
    if checks["CA certificate"] and checks["CA private key"]:
        try:
            ca_cert = x509.load_pem_x509_certificate((root / "ca" / "ca-cert.pem").read_bytes())
            ca_key = serialization.load_pem_private_key((root / "ca" / "ca-key.pem").read_bytes(), password=None)
            ca_cert.verify_directly_issued_by(ca_cert)
            checks["CA keypair integrity"] = ca_key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            ) == ca_cert.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        except (OSError, ValueError, InvalidSignature):
            checks["CA keypair integrity"] = False
    if checks["policy signing keypair"]:
        try:
            private = serialization.load_pem_private_key((root / "policy-signing-key.pem").read_bytes(), password=None)
            public = serialization.load_pem_public_key((root / "policy-signing-public.pem").read_bytes())
            checks["policy signing keypair integrity"] = (
                isinstance(private, Ed25519PrivateKey) and isinstance(public, Ed25519PublicKey) and
                private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) ==
                public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            )
        except (OSError, ValueError):
            checks["policy signing keypair integrity"] = False
    for name, ok in checks.items():
        typer.echo(f"{'OK' if ok else 'MISSING'}  {name}")
    if not all(checks.values()):
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
