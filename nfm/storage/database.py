"""SQLite persistence for identities, active policy, sessions, and audit events."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nfm.policy.engine import validate_policy


def timestamp() -> str:
    return datetime.now(UTC).isoformat()


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS nodes (
                node_id TEXT PRIMARY KEY, role TEXT NOT NULL, cert_serial TEXT NOT NULL, cert_expires_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active', security_state TEXT NOT NULL DEFAULT 'HEALTHY', enrolled_at TEXT NOT NULL,
                revoked_at TEXT
            );
            CREATE TABLE IF NOT EXISTS policies (
                policy_id TEXT NOT NULL, version INTEGER NOT NULL, definition TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL,
                PRIMARY KEY (policy_id, version)
            );
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY, node_id TEXT NOT NULL, service TEXT NOT NULL,
                started_at TEXT NOT NULL, ended_at TEXT, status TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS security_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT, node_id TEXT, event_type TEXT NOT NULL,
                severity TEXT NOT NULL, details TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS enrollment_requests (
                request_id TEXT PRIMARY KEY, node_id TEXT NOT NULL, role TEXT NOT NULL,
                csr_pem TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
                cert_pem TEXT, requested_at TEXT NOT NULL, approved_at TEXT
            );
            CREATE UNIQUE INDEX IF NOT EXISTS one_pending_enrollment_per_node
                ON enrollment_requests(node_id) WHERE status='pending';
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS agent_sync_state (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1), required INTEGER NOT NULL,
                last_success_at TEXT
            );
        """)
        applied = {row["version"] for row in self.connection.execute("SELECT version FROM schema_migrations")}
        if 1 not in applied:
            columns = {row["name"] for row in self.connection.execute("PRAGMA table_info(nodes)")}
            if "security_state" not in columns:
                self.connection.execute(
                    "ALTER TABLE nodes ADD COLUMN security_state TEXT NOT NULL DEFAULT 'HEALTHY'"
                )
            self.connection.execute(
                "INSERT INTO schema_migrations(version,applied_at) VALUES(1,?)", (timestamp(),)
            )
        self.connection.commit()

    def event(self, node_id: str | None, event_type: str, severity: str, details: dict[str, Any]) -> None:
        self.connection.execute(
            "INSERT INTO security_events(node_id,event_type,severity,details,created_at) VALUES(?,?,?,?,?)",
            (node_id, event_type, severity, json.dumps(details, sort_keys=True), timestamp()),
        )
        self.connection.commit()

    def mark_sync_required(self) -> None:
        self.connection.execute(
            "INSERT INTO agent_sync_state(singleton,required,last_success_at) VALUES(1,1,NULL) "
            "ON CONFLICT(singleton) DO UPDATE SET required=1"
        )
        self.connection.commit()

    def mark_sync_success(self) -> None:
        self.connection.execute(
            "INSERT INTO agent_sync_state(singleton,required,last_success_at) VALUES(1,1,?) "
            "ON CONFLICT(singleton) DO UPDATE SET required=1,last_success_at=excluded.last_success_at",
            (timestamp(),),
        )
        self.connection.commit()

    def sync_is_fresh(self, max_age_seconds: int, *, now: datetime | None = None) -> bool:
        if max_age_seconds < 1:
            raise ValueError("maximum offline age must be positive")
        row = self.connection.execute(
            "SELECT required,last_success_at FROM agent_sync_state WHERE singleton=1"
        ).fetchone()
        if row is None or not row["required"]:
            return True
        if not row["last_success_at"]:
            return False
        try:
            last_success = datetime.fromisoformat(row["last_success_at"])
        except ValueError:
            return False
        current = now or datetime.now(UTC)
        if last_success.tzinfo is None:
            return False
        age = (current - last_success.astimezone(UTC)).total_seconds()
        return 0 <= age <= max_age_seconds

    def sync_status(self) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT required,last_success_at FROM agent_sync_state WHERE singleton=1"
        ).fetchone()
        return dict(row) if row else {"required": 0, "last_success_at": None}

    def enroll(self, node_id: str, role: str, serial: str, expires_at: str) -> None:
        self.connection.execute(
            "INSERT INTO nodes(node_id,role,cert_serial,cert_expires_at,enrolled_at) VALUES(?,?,?,?,?) "
            "ON CONFLICT(node_id) DO UPDATE SET role=excluded.role,cert_serial=excluded.cert_serial,cert_expires_at=excluded.cert_expires_at,status='active',revoked_at=NULL",
            (node_id, role, serial, expires_at, timestamp()),
        )
        self.event(node_id, "identity_enrolled", "info", {"role": role, "serial": serial, "expires_at": expires_at})
        self.connection.commit()

    def revoked(self, node_id: str) -> bool:
        row = self.connection.execute("SELECT status FROM nodes WHERE node_id=?", (node_id,)).fetchone()
        return row is None or row["status"] != "active"

    def revoke(self, node_id: str) -> bool:
        cur = self.connection.execute(
            "UPDATE nodes SET status='revoked',revoked_at=? WHERE node_id=? AND status='active'",
            (timestamp(), node_id),
        )
        if cur.rowcount > 0:
            self.event(node_id, "identity_revoked", "high", {})
        self.connection.commit()
        return cur.rowcount > 0

    def set_security_state(self, node_id: str, state: str, *, recovery_approved: bool = False) -> None:
        state_rank = {"HEALTHY": 0, "DEGRADED": 1, "RESTRICTED": 2, "ISOLATED": 3}
        if state not in state_rank:
            raise ValueError("unsupported security state")
        row = self.connection.execute(
            "SELECT security_state FROM nodes WHERE node_id=?", (node_id,)
        ).fetchone()
        if row is None:
            raise ValueError("node not found")
        previous = row["security_state"]
        if previous not in state_rank:
            raise ValueError("stored security state is invalid; repair state through an administrator workflow")
        if state_rank[state] < state_rank[previous] and not recovery_approved:
            raise ValueError("recovery approval is required to reduce restrictions")
        if recovery_approved and state_rank[state] >= state_rank[previous]:
            raise ValueError("recovery approval is only valid when reducing restrictions")
        if previous == state:
            return
        self.connection.execute("UPDATE nodes SET security_state=? WHERE node_id=?", (state, node_id))
        severity = "critical" if state == "ISOLATED" else "high" if state == "RESTRICTED" else "warning"
        self.event(node_id, "security_state_changed", severity,
                   {"previous": previous, "current": state, "recovery_approved": recovery_approved})
        self.connection.commit()

    def set_policy(self, policy: dict[str, Any]) -> None:
        policy = validate_policy(policy)
        latest = self.connection.execute(
            "SELECT MAX(version) AS version FROM policies WHERE policy_id=?", (policy["policy_id"],)
        ).fetchone()["version"]
        if latest is not None:
            if policy["version"] < latest:
                raise ValueError(f"stale policy version {policy['version']}; latest is {latest}")
            if policy["version"] == latest:
                previous = self.connection.execute(
                    "SELECT definition FROM policies WHERE policy_id=? AND version=?",
                    (policy["policy_id"], policy["version"]),
                ).fetchone()
                if previous and json.loads(previous["definition"]) != policy:
                    raise ValueError("policy content cannot change without incrementing its version")
        if self.active_policy() == policy:
            return
        self.connection.execute("UPDATE policies SET active=0")
        self.connection.execute(
            "INSERT INTO policies(policy_id,version,definition,active,created_at) VALUES(?,?,?,1,?) "
            "ON CONFLICT(policy_id,version) DO UPDATE SET definition=excluded.definition,active=1",
            (policy["policy_id"], policy["version"], json.dumps(policy, sort_keys=True), timestamp()),
        )
        self.event(None, "policy_activated", "info", {"policy_id": policy["policy_id"], "version": policy["version"]})
        self.connection.commit()

    def active_policy(self) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT definition FROM policies WHERE active=1 ORDER BY created_at DESC LIMIT 1").fetchone()
        return json.loads(row["definition"]) if row else None

    def revoke_policy(self, policy_id: str) -> bool:
        cur = self.connection.execute("UPDATE policies SET active=0 WHERE policy_id=? AND active=1", (policy_id,))
        if cur.rowcount > 0:
            self.event(None, "policy_revoked", "high", {"policy_id": policy_id})
        self.connection.commit()
        return cur.rowcount > 0

    def clear_policy(self, reason: str = "controller_policy_revoked") -> None:
        cur = self.connection.execute("UPDATE policies SET active=0 WHERE active=1")
        if cur.rowcount > 0:
            self.event(None, "active_policy_cleared", "high", {"reason": reason})
        self.connection.commit()

    def nodes(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self.connection.execute("SELECT * FROM nodes ORDER BY node_id")]

    def events(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.connection.execute("SELECT * FROM security_events ORDER BY event_id DESC LIMIT ?", (limit,))
        return [dict(row) for row in rows]

    def sessions(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.connection.execute("SELECT * FROM sessions ORDER BY started_at DESC LIMIT ?", (limit,))
        return [dict(row) for row in rows]

    def session_status(self, session_id: str) -> str | None:
        row = self.connection.execute("SELECT status FROM sessions WHERE session_id=?", (session_id,)).fetchone()
        return row["status"] if row else None

    def revoke_session(self, session_id: str) -> bool:
        cur = self.connection.execute(
            "UPDATE sessions SET status='revocation_requested' WHERE session_id=? AND status='active'",
            (session_id,),
        )
        if cur.rowcount:
            row = self.connection.execute("SELECT node_id FROM sessions WHERE session_id=?", (session_id,)).fetchone()
            self.event(row["node_id"], "session_revocation_requested", "high", {"session_id": session_id})
        self.connection.commit()
        return cur.rowcount > 0

    def request_enrollment(self, request_id: str, node_id: str, role: str, csr_pem: str) -> None:
        existing = self.enrollment(request_id)
        if existing is not None:
            if existing["node_id"] == node_id and existing["role"] == role and existing["csr_pem"] == csr_pem:
                return
            raise ValueError("enrollment request ID is already in use")
        try:
            self.connection.execute(
                "INSERT INTO enrollment_requests(request_id,node_id,role,csr_pem,requested_at) VALUES(?,?,?,?,?)",
                (request_id, node_id, role, csr_pem, timestamp()),
            )
        except sqlite3.IntegrityError as exc:
            raise ValueError("an enrollment request is already pending for this node") from exc
        self.event(node_id, "enrollment_requested", "info", {"request_id": request_id, "role": role})
        self.connection.commit()

    def enrollment(self, request_id: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT * FROM enrollment_requests WHERE request_id=?", (request_id,)).fetchone()
        return dict(row) if row else None

    def pending_enrollments(self) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT request_id,node_id,role,status,requested_at FROM enrollment_requests WHERE status='pending' ORDER BY requested_at"
        )
        return [dict(row) for row in rows]

    def sync_nodes(self, nodes: list[dict[str, Any]]) -> None:
        """Apply validated controller inventory/revocation state to this local agent."""
        required = {"node_id", "role", "cert_serial", "cert_expires_at", "status", "security_state"}
        states = {"HEALTHY", "DEGRADED", "RESTRICTED", "ISOLATED"}
        for item in nodes:
            if not isinstance(item, dict) or not required.issubset(item):
                raise ValueError("malformed node inventory entry")
            if not all(isinstance(item[field], str) and item[field] for field in required):
                raise ValueError("node inventory fields must be non-empty strings")
            if item["status"] not in {"active", "revoked"}:
                raise ValueError("unsupported node status in controller snapshot")
            if item["security_state"] not in states:
                raise ValueError("unsupported node security state in controller snapshot")
        for item in nodes:
            existing = self.connection.execute("SELECT status,security_state FROM nodes WHERE node_id=?", (item["node_id"],)).fetchone()
            revoked_at = timestamp() if item["status"] == "revoked" else None
            self.connection.execute(
                "INSERT INTO nodes(node_id,role,cert_serial,cert_expires_at,status,security_state,enrolled_at,revoked_at) "
                "VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(node_id) DO UPDATE SET role=excluded.role, "
                "cert_serial=excluded.cert_serial,cert_expires_at=excluded.cert_expires_at, "
                "status=excluded.status,security_state=excluded.security_state,revoked_at=CASE WHEN excluded.status='revoked' "
                "THEN COALESCE(nodes.revoked_at,excluded.revoked_at) ELSE NULL END",
                (item["node_id"], item["role"], item["cert_serial"], item["cert_expires_at"],
                 item["status"], item["security_state"], item.get("enrolled_at", timestamp()), revoked_at),
            )
            if item["status"] == "revoked" and (existing is None or existing["status"] != "revoked"):
                self.connection.execute(
                    "INSERT INTO security_events(node_id,event_type,severity,details,created_at) VALUES(?,?,?,?,?)",
                    (item["node_id"], "identity_revoked", "high", '{"source":"controller_sync"}', timestamp()),
                )
            state_changed = existing is not None and existing["security_state"] != item["security_state"]
            if state_changed or (existing is None and item["security_state"] in {"RESTRICTED", "ISOLATED"}):
                severity = "critical" if item["security_state"] == "ISOLATED" else "high" if item["security_state"] == "RESTRICTED" else "info"
                self.connection.execute(
                    "INSERT INTO security_events(node_id,event_type,severity,details,created_at) VALUES(?,?,?,?,?)",
                    (item["node_id"], "security_state_changed", severity,
                     json.dumps({"previous": existing["security_state"] if existing else None,
                                 "current": item["security_state"], "source": "controller_sync"}, sort_keys=True), timestamp()),
                )
        self.connection.commit()

    def approve_enrollment(self, request_id: str, cert_pem: str, serial: str, expires_at: str) -> dict[str, Any]:
        request = self.enrollment(request_id)
        if request is None or request["status"] != "pending":
            raise ValueError("pending enrollment request not found")
        self.enroll(request["node_id"], request["role"], serial, expires_at)
        self.connection.execute(
            "UPDATE enrollment_requests SET status='approved',cert_pem=?,approved_at=? WHERE request_id=? AND status='pending'",
            (cert_pem, timestamp(), request_id),
        )
        self.event(request["node_id"], "enrollment_approved", "info", {"request_id": request_id, "serial": serial})
        self.connection.commit()
        return request

    def start_session(self, session_id: str, node_id: str, service: str) -> None:
        self.connection.execute("INSERT INTO sessions VALUES(?,?,?, ?,NULL,'active')", (session_id, node_id, service, timestamp()))
        self.connection.commit()

    def end_session(self, session_id: str, status: str) -> None:
        self.connection.execute("UPDATE sessions SET ended_at=?,status=? WHERE session_id=?", (timestamp(), status, session_id))
        self.connection.commit()
