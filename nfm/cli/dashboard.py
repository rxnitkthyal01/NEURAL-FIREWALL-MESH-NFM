"""Read-only terminal dashboard for the local NFM state store."""

from __future__ import annotations

from datetime import datetime, timedelta

from rich.console import Group
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from nfm.storage.database import Store


def _cell(value: object, limit: int) -> Text:
    """Keep database strings on one line and render them as untrusted text."""
    content = str(value).replace("\r", " ").replace("\n", " ")
    if len(content) > limit:
        content = content[: limit - 3] + "..."
    return Text(content, no_wrap=True, overflow="ellipsis")


def _compact_time(value: object) -> str:
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return str(value)[:16]
    suffix = "Z" if parsed.utcoffset() == timedelta(0) else parsed.strftime("%z")
    return parsed.strftime("%m-%d %H:%M") + suffix


def build_dashboard(store: Store) -> Group:
    """Build a terminal view from actual records in the selected local store."""
    nodes = store.nodes()
    all_sessions = store.sessions(1000)
    sessions = all_sessions[:8]
    events = store.events(8)
    policy = store.active_policy()

    overview = Table.grid(expand=True, padding=(0, 2))
    overview.add_column(ratio=1)
    overview.add_column(ratio=1)
    overview.add_row(
        f"[bold cyan]NODES[/] {len(nodes)}",
        f"[bold]POLICY[/] {escape(str(policy['policy_id']))} v{policy['version']}"
        if policy else "[bold yellow]POLICY[/] DEFAULT DENY",
    )
    overview.add_row(
        f"[bold green]ACTIVE IDENTITIES[/] {sum(node['status'] == 'active' for node in nodes)}",
        f"[bold cyan]ACTIVE SESSIONS*[/] {sum(session['status'] == 'active' for session in all_sessions)}",
    )

    node_table = Table(title="Node inventory", expand=True, show_lines=False)
    for heading, width in (("Node", 16), ("Role", 12), ("Identity", 8), ("State", 10)):
        node_table.add_column(heading, max_width=width, no_wrap=True, overflow="ellipsis")
    for node in nodes:
        state_style = "green" if node["security_state"] == "HEALTHY" else "yellow"
        node_table.add_row(
            _cell(node["node_id"], 16), _cell(node["role"], 12), _cell(node["status"], 8),
            Text(str(node["security_state"]), style=state_style, no_wrap=True),
        )
    if not nodes:
        node_table.add_row("No enrolled nodes", "", "", "")

    session_table = Table(title="Recent protected sessions", expand=True, show_lines=False)
    for heading, width in (("Time", 11), ("Node", 13), ("Service", 10), ("Status", 11)):
        session_table.add_column(heading, max_width=width, no_wrap=True, overflow="ellipsis")
    for session in sessions:
        session_table.add_row(
            _cell(_compact_time(session["started_at"]), 12), _cell(session["node_id"], 13),
            _cell(session["service"], 10), _cell(session["status"], 11),
        )
    if not sessions:
        session_table.add_row("No session records", "", "", "")

    event_table = Table(title="Recent security events", expand=True, show_lines=False)
    for heading, width in (("Time", 11), ("Sev", 3), ("Event", 18), ("Node", 12)):
        event_table.add_column(heading, max_width=width, no_wrap=True, overflow="ellipsis")
    for event in events:
        severity = str(event["severity"]).upper()
        style = "red" if severity in {"HIGH", "CRITICAL"} else "yellow" if severity == "WARNING" else "dim"
        event_table.add_row(
            _cell(_compact_time(event["created_at"]), 12), Text(severity[:3], style=style, no_wrap=True),
            _cell(event["event_type"], 18), _cell(event["node_id"] or "-", 12),
        )
    if not events:
        event_table.add_row("No security events", "", "", "")

    updated = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    header = Text("NFM  /  NO TRUST. ONLY MATH.                         Local state view", style="bold cyan")
    return Group(
        Panel(header, border_style="cyan"),
        Panel(overview, title="Overview", border_style="blue"),
        node_table,
        session_table,
        event_table,
        Text(f"Updated {updated}  |  Ctrl+C to exit  |  Read-only  |  *Local records only", style="dim"),
        Text("Full event details: nfm security events --json; expiry: nfm node inspect <node-id>.", style="dim"),
    )
