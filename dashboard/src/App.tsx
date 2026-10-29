import { useCallback, useEffect, useMemo, useState } from "react";
import { Background, Controls, MarkerType, MiniMap, ReactFlow } from "@xyflow/react";
import type { Edge, Node } from "@xyflow/react";

type MeshNode = {
  node_id: string;
  role: string;
  status: string;
  security_state: string;
  cert_expires_at: string;
};
type Session = { session_id: string; node_id: string; service: string; status: string; started_at: string };
type EventRow = { event_id: number; node_id: string | null; event_type: string; severity: string; details: string; created_at: string };

const api = async <T,>(path: string, token: string, init?: RequestInit): Promise<T> => {
  const response = await fetch(`/api${path}`, {
    ...init,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json", ...init?.headers },
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.detail ?? `Controller returned HTTP ${response.status}`);
  }
  return response.json() as Promise<T>;
};

const stateOptions = ["HEALTHY", "DEGRADED", "RESTRICTED", "ISOLATED"];

export default function App() {
  const [token, setToken] = useState("");
  const [draft, setDraft] = useState("");
  const [nodes, setNodes] = useState<MeshNode[]>([]);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [events, setEvents] = useState<EventRow[]>([]);
  const [policy, setPolicy] = useState<Record<string, unknown> | null>(null);
  const [policyText, setPolicyText] = useState("");
  const [editingPolicy, setEditingPolicy] = useState(false);
  const [error, setError] = useState("");
  const [updated, setUpdated] = useState<Date | null>(null);

  const refresh = useCallback(async () => {
    if (!token) return;
    try {
      const [nodeData, sessionData, eventData, policyData] = await Promise.all([
        api<MeshNode[]>("/nodes", token),
        api<Session[]>("/sessions?limit=100", token),
        api<EventRow[]>("/security/events?limit=100", token),
        api<Record<string, unknown> | null>("/policies/active", token),
      ]);
      setNodes(nodeData);
      setSessions(sessionData);
      setEvents(eventData);
      setPolicy(policyData);
      if (!editingPolicy) setPolicyText(policyData ? JSON.stringify(policyData, null, 2) : "");
      setUpdated(new Date());
      setError("");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not reach NFM controller");
    }
  }, [token, editingPolicy]);

  useEffect(() => {
    if (!token) return;
    void refresh();
    const timer = window.setInterval(() => void refresh(), 5000);
    return () => window.clearInterval(timer);
  }, [token, refresh]);

  const changeState = async (node: MeshNode, next: string) => {
    const recovery = ["RESTRICTED", "ISOLATED"].includes(node.security_state) && ["HEALTHY", "DEGRADED"].includes(next);
    if (recovery && !window.confirm(`Approve recovery for ${node.node_id} to ${next}?`)) return;
    try {
      await api(`/nodes/${encodeURIComponent(node.node_id)}/state`, token, {
        method: "POST", body: JSON.stringify({ security_state: next, recovery_approved: recovery }),
      });
      await refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "State update failed");
    }
  };

  const revoke = async (node: MeshNode) => {
    if (!window.confirm(`Revoke identity ${node.node_id}?`)) return;
    try {
      await api(`/nodes/${encodeURIComponent(node.node_id)}/revoke`, token, { method: "POST" });
      await refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Revocation failed");
    }
  };

  const validatePolicy = async () => {
    try {
      const candidate = JSON.parse(policyText);
      const result = await api<{ valid: boolean; policy_id: string; version: number }>("/policies/validate", token, {
        method: "POST", body: JSON.stringify(candidate),
      });
      window.alert(`Valid policy ${result.policy_id}, version ${result.version}`);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Policy validation failed");
    }
  };

  const activatePolicy = async () => {
    try {
      const candidate = JSON.parse(policyText);
      await api("/policies/validate", token, { method: "POST", body: JSON.stringify(candidate) });
      await api("/policies/active", token, { method: "PUT", body: JSON.stringify(candidate) });
      setEditingPolicy(false);
      await refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Policy activation failed");
    }
  };

  const revokeSession = async (session: Session) => {
    if (!window.confirm(`Terminate protected session ${session.session_id}?`)) return;
    try {
      await api(`/sessions/${encodeURIComponent(session.session_id)}/revoke`, token, { method: "POST" });
      await refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Session revocation failed");
    }
  };

  const graph = useMemo(() => {
    const used = sessions.slice(0, 24);
    const nodeIds = [...new Set(used.map((session) => session.node_id))];
    const serviceIds = [...new Set(used.map((session) => session.service))];
    const flowNodes: Node[] = [
      ...nodeIds.map((id, index) => {
        const info = nodes.find((item) => item.node_id === id);
        return { id: `node:${id}`, position: { x: 40, y: 35 + index * 115 }, data: { label: `${id} · ${info?.security_state ?? "UNKNOWN"}` }, className: "flow-node" };
      }),
      ...serviceIds.map((service, index) => ({
        id: `service:${service}`, position: { x: 390, y: 35 + index * 115 },
        data: { label: `service · ${service}` }, className: "flow-service",
      })),
    ];
    const flowEdges: Edge[] = used.map((session) => ({
      id: session.session_id,
      source: `node:${session.node_id}`,
      target: `service:${session.service}`,
      label: session.status,
      markerEnd: { type: MarkerType.ArrowClosed },
      animated: session.status === "active",
    }));
    return { nodes: flowNodes, edges: flowEdges };
  }, [nodes, sessions]);

  if (!token) return (
    <main className="login-shell">
      <section className="login-card">
        <div className="brand-mark">N</div>
        <p className="eyebrow">CONTROL PLANE · AUTHENTICATED ACCESS</p>
        <h1>NFM Control</h1>
        <p className="muted">Connect to your controller with its administrator bearer token. The token stays in this page's memory.</p>
        <form onSubmit={(event) => { event.preventDefault(); setToken(draft.trim()); }}>
          <label htmlFor="token">Administrator token</label>
          <input id="token" type="password" autoComplete="off" value={draft} onChange={(event) => setDraft(event.target.value)} placeholder="Paste NFM_ADMIN_TOKEN" required />
          <button className="primary" type="submit">Connect to controller <span>→</span></button>
        </form>
        <div className="login-foot"><i /> No trust. Only math. <span>API: same origin /api</span></div>
      </section>
    </main>
  );

  const activeNodes = nodes.filter((node) => node.status === "active").length;
  const restrictedNodes = nodes.filter((node) => node.security_state !== "HEALTHY").length;
  const activeSessions = sessions.filter((session) => session.status === "active").length;

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand"><div className="brand-mark small">N</div><div><strong>NFM</strong><small>CONTROL PLANE</small></div></div>
        <nav><a className="selected" href="#overview">Overview <span>01</span></a><a href="#mesh">Mesh topology <span>02</span></a><a href="#nodes">Node inventory <span>03</span></a><a href="#policy">Policy <span>04</span></a><a href="#events">Security events <span>05</span></a></nav>
        <div className="sidebar-bottom"><div className={`controller-status ${error ? "disconnected" : ""}`}><i /> {error ? "Controller unavailable" : "Controller connected"}</div><button className="quiet" onClick={() => { setToken(""); setDraft(""); }}>Disconnect</button></div>
      </aside>
      <section className="workspace">
        <header className="topbar"><div><p className="eyebrow">NEURAL FIREWALL MESH / ADMINISTRATION</p><h1>Security overview</h1></div><div className="top-meta"><span className={`live-dot ${error ? "offline" : ""}`} /> {error ? "Data stale" : "Live data"} <span className="divider" /> {updated ? `Updated ${updated.toLocaleTimeString()}` : "Loading"}<button className="icon-button" title="Refresh" onClick={() => void refresh()}>↻</button></div></header>
        {error && <div className="error-banner"><strong>Controller request failed</strong><span>{error}</span><button onClick={() => setError("")}>Dismiss</button></div>}
        <div className="content">
          <section id="overview" className="metrics">
            <Metric label="Enrolled nodes" value={nodes.length} note={`${activeNodes} active identities`} />
            <Metric label="Active session records" value={activeSessions} note={`${sessions.length} records loaded`} />
            <Metric label="Non-healthy states" value={restrictedNodes} note="All non-healthy states deny access" warn={restrictedNodes > 0} />
            <Metric label="Policy" value={policy ? String(policy.policy_id ?? "Active") : "DENY"} note={policy ? `Version ${policy.version}` : "No active policy"} />
          </section>
          <section id="mesh" className="panel topology-panel">
            <div className="panel-head"><div><p className="eyebrow">OBSERVED RELATIONSHIPS</p><h2>Recorded session topology</h2></div><span className="panel-tag">{sessions.length} records</span></div>
            <p className="panel-note">Edges come from controller session records and point to the named protected service.</p>
            <div className="flow-wrap">
              {graph.nodes.length ? <ReactFlow nodes={graph.nodes} edges={graph.edges} fitView minZoom={0.4} maxZoom={1.5} nodesDraggable={false} nodesConnectable={false} elementsSelectable={false} proOptions={{ hideAttribution: true }}><Background color="#2b343c" gap={22} /><MiniMap pannable zoomable /><Controls /></ReactFlow> : <Empty>No session records yet. Connections appear here after protected services accept them.</Empty>}
            </div>
          </section>
          <section id="nodes" className="panel">
            <div className="panel-head"><div><p className="eyebrow">IDENTITY INVENTORY</p><h2>Nodes</h2></div><span className="panel-tag">{nodes.length} total</span></div>
            <div className="table-scroll"><table><thead><tr><th>Node</th><th>Role</th><th>Identity</th><th>Security state</th><th>Credential expiry</th><th>Actions</th></tr></thead><tbody>
              {nodes.map((node) => <tr key={node.node_id}><td className="mono strong">{node.node_id}</td><td>{node.role}</td><td><Badge value={node.status} /></td><td><Badge value={node.security_state} /></td><td>{new Date(node.cert_expires_at).toLocaleString()}</td><td className="actions"><select aria-label={`Set state for ${node.node_id}`} value={node.security_state} onChange={(event) => void changeState(node, event.target.value)}>{stateOptions.map((state) => <option key={state}>{state}</option>)}</select><button className="danger-link" onClick={() => void revoke(node)} disabled={node.status !== "active"}>Revoke</button></td></tr>)}
            </tbody></table>{!nodes.length && <Empty>No nodes enrolled.</Empty>}</div>
          </section>
          <section className="two-col">
            <div id="policy" className="panel"><div className="panel-head"><div><p className="eyebrow">DETERMINISTIC AUTHORIZATION</p><h2>Policy centre</h2></div><span className={`status-pill ${policy ? "good" : "bad"}`}>{policy ? "ACTIVE" : "DEFAULT DENY"}</span></div><textarea className="policy-json policy-editor" aria-label="Policy JSON" value={editingPolicy ? policyText : policy ? JSON.stringify(policy, null, 2) : policyText} onFocus={() => { setEditingPolicy(true); setPolicyText(policy ? JSON.stringify(policy, null, 2) : policyText); }} onChange={(event) => setPolicyText(event.target.value)} placeholder={'{"policy_id":"example","version":1,"rules":[]}'} />{editingPolicy && <div className="policy-actions"><button className="quiet" onClick={() => void validatePolicy()}>Validate</button><button className="primary compact" onClick={() => void activatePolicy()}>Activate version</button><button className="quiet" onClick={() => { setEditingPolicy(false); setPolicyText(policy ? JSON.stringify(policy, null, 2) : ""); }}>Cancel</button></div>}</div>
            <div className="panel"><div className="panel-head"><div><p className="eyebrow">SESSION LIFECYCLE</p><h2>Recent sessions</h2></div><span className="panel-tag">Latest 100</span></div><div className="session-list">{sessions.slice(0, 8).map((session) => <div className="session-row" key={session.session_id}><span className={`session-dot ${session.status}`} /><div><strong>{session.node_id}</strong><small>to {session.service}</small></div><span className="session-state">{session.status}</span>{session.status === "active" && <button className="danger-link" onClick={() => void revokeSession(session)}>Revoke</button>}</div>)}{!sessions.length && <Empty>No protected sessions recorded.</Empty>}</div></div>
          </section>
          <section id="events" className="panel"><div className="panel-head"><div><p className="eyebrow">AUDIT TRAIL</p><h2>Security events</h2></div><span className="panel-tag">Latest {events.length}</span></div><div className="table-scroll"><table><thead><tr><th>Time</th><th>Severity</th><th>Event</th><th>Node</th><th>Details</th></tr></thead><tbody>{events.map((event) => <tr key={event.event_id}><td>{new Date(event.created_at).toLocaleString()}</td><td><Badge value={event.severity} /></td><td className="mono">{event.event_type}</td><td>{event.node_id ?? "—"}</td><td className="details">{event.details}</td></tr>)}</tbody></table>{!events.length && <Empty>No security events recorded.</Empty>}</div></section>
          <footer>Cryptographic identity · Explicit authorization · Local enforcement <span>NFM MVP 0.1</span></footer>
        </div>
      </section>
    </main>
  );
}

function Metric({ label, value, note, warn = false }: { label: string; value: string | number; note: string; warn?: boolean }) {
  return <article className="metric-card"><span>{label}</span><strong className={warn ? "warn" : ""}>{value}</strong><small>{note}</small></article>;
}
function Badge({ value }: { value: string }) {
  return <span className={`badge badge-${value.toLowerCase().replaceAll("_", "-")}`}>{value.replaceAll("_", " ")}</span>;
}
function Empty({ children }: { children: string }) {
  return <div className="empty"><span>—</span>{children}</div>;
}
