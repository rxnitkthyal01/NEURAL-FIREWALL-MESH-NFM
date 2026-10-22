"""Authenticated HTTPS client for remote controller administration."""

from __future__ import annotations

import ipaddress
import json
import re
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlsplit


class ControllerAdminError(ValueError):
    """A controller rejected an administrative request."""


def admin_request(
    base_url: str,
    token: str,
    path: str,
    *,
    method: str = "GET",
    payload: Any = None,
) -> Any:
    """Send one bounded JSON request with normal TLS certificate verification."""
    parsed = urlsplit(base_url)
    if (
        not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError("controller URL must be an origin without credentials, path, query, or fragment")
    if parsed.scheme != "https":
        try:
            loopback = parsed.hostname == "localhost" or ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            loopback = False
        if parsed.scheme != "http" or not loopback:
            raise ValueError("controller URL must use HTTPS (HTTP is allowed only for loopback development)")
    parsed_path = urlsplit(path)
    valid_query = not parsed_path.query or bool(re.fullmatch(r"limit=[1-9][0-9]{0,3}", parsed_path.query))
    if parsed_path.scheme or parsed_path.netloc or not parsed_path.path.startswith("/api/") or parsed_path.fragment or not valid_query:
        raise ValueError("invalid controller API path")
    if len(token) < 32:
        raise ValueError("set NFM_ADMIN_TOKEN to the controller's admin secret (at least 32 characters)")

    data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        base_url.rstrip("/") + parsed_path.path + (f"?{parsed_path.query}" if parsed_path.query else ""),
        data=data, headers=headers, method=method.upper(),
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            body = response.read(2_000_001)
    except urllib.error.HTTPError as exc:
        try:
            error_body = exc.read(65_536)
            parsed_error = json.loads(error_body) if error_body else {}
            detail = parsed_error.get("detail", "request rejected") if isinstance(parsed_error, dict) else "request rejected"
        except (OSError, json.JSONDecodeError):
            detail = "request rejected"
        raise ControllerAdminError(f"HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise ControllerAdminError(f"controller connection failed: {exc.reason}") from exc
    if len(body) > 2_000_000:
        raise ControllerAdminError("controller response exceeded the 2 MB limit")
    try:
        return json.loads(body) if body else None
    except json.JSONDecodeError as exc:
        raise ControllerAdminError("controller returned malformed JSON") from exc
