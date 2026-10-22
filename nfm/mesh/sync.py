"""Authenticated agent snapshot polling with normal TLS certificate validation."""

from __future__ import annotations

import ipaddress
import json
import re
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from nfm.crypto.policy_signing import verify_bundle
from nfm.storage.database import Store


def _validate_snapshot_nodes(nodes: list[Any]) -> None:
    required = {"node_id", "role", "cert_serial", "cert_expires_at", "status", "security_state"}
    states = {"HEALTHY", "DEGRADED", "RESTRICTED", "ISOLATED"}
    for item in nodes:
        if not isinstance(item, dict) or not required.issubset(item):
            raise ValueError("controller snapshot contains a malformed node")
        if not all(isinstance(item[field], str) and item[field] for field in required):
            raise ValueError("controller snapshot contains invalid node fields")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", item["node_id"]):
            raise ValueError("controller snapshot contains an invalid node ID")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}", item["role"]):
            raise ValueError("controller snapshot contains an invalid role")
        try:
            serial = int(item["cert_serial"])
        except ValueError as exc:
            raise ValueError("controller snapshot contains an invalid certificate serial") from exc
        if serial < 1:
            raise ValueError("controller snapshot contains an invalid certificate serial")
        try:
            expires_at = datetime.fromisoformat(item["cert_expires_at"])
        except ValueError as exc:
            raise ValueError("controller snapshot contains an invalid credential expiration") from exc
        if expires_at.tzinfo is None:
            raise ValueError("controller snapshot credential expiration must include a timezone")
        if item["status"] not in {"active", "revoked"}:
            raise ValueError("controller snapshot contains an unsupported node status")
        if item["security_state"] not in states:
            raise ValueError("controller snapshot contains an unsupported node security state")
        enrolled_at = item.get("enrolled_at")
        if enrolled_at is not None:
            if not isinstance(enrolled_at, str):
                raise ValueError("controller snapshot contains an invalid enrollment timestamp")
            try:
                parsed_enrolled_at = datetime.fromisoformat(enrolled_at)
            except ValueError as exc:
                raise ValueError("controller snapshot contains an invalid enrollment timestamp") from exc
            if parsed_enrolled_at.tzinfo is None:
                raise ValueError("controller snapshot enrollment timestamp must include a timezone")


def controller_request(base_url: str, path: str, token: str) -> dict[str, Any]:
    parsed = urlsplit(base_url)
    if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("controller URL must be an origin URL without credentials, query, or fragment")
    if parsed.scheme != "https":
        try:
            loopback = parsed.hostname == "localhost" or ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            loopback = False
        if parsed.scheme != "http" or not loopback:
            raise ValueError("controller URL must use HTTPS (HTTP is allowed only for loopback development)")
    url = base_url.rstrip("/") + path
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        body = json.loads(response.read(2_000_001))
    if not isinstance(body, dict):
        raise ValueError("controller response must be a JSON object")
    return body


def sync_once(base_url: str, token: str, *, store: Store, trusted_policy_key: Path) -> dict[str, int]:
    # Once agent sync is configured, failed polling must eventually fail closed.
    store.mark_sync_required()
    snapshot = controller_request(base_url, "/api/mesh/snapshot", token)
    bundle = snapshot.get("policy_bundle")
    nodes = snapshot.get("nodes")
    if not isinstance(nodes, list):
        raise ValueError("controller snapshot has no valid node list")
    policy = verify_bundle(bundle, trusted_policy_key) if bundle is not None else None
    # Validate all node entries before mutating local policy or inventory.
    _validate_snapshot_nodes(nodes)
    fields = {"node_id", "role", "cert_serial", "cert_expires_at", "status", "security_state"}
    for item in nodes:
        if not isinstance(item, dict) or not fields.issubset(item):
            raise ValueError("controller snapshot contains a malformed node")
        if not all(isinstance(item[field], str) and item[field] for field in fields):
            raise ValueError("controller snapshot contains invalid node fields")
        if item["status"] not in {"active", "revoked"}:
            raise ValueError("controller snapshot contains an unsupported node status")
        if item["security_state"] not in {"HEALTHY", "DEGRADED", "RESTRICTED", "ISOLATED"}:
            raise ValueError("controller snapshot contains an unsupported security state")
    policy_error: ValueError | None = None
    try:
        if policy is None:
            store.clear_policy()
        else:
            store.set_policy(policy)
    except ValueError as exc:
        # A stale signed bundle must not block revocation updates; deny access locally.
        store.clear_policy("controller_policy_rejected")
        policy_error = exc
    store.sync_nodes(nodes)
    if policy_error is not None:
        raise policy_error
    store.mark_sync_success()
    return {"nodes": len(nodes), "policy_version": policy["version"] if policy is not None else 0}
