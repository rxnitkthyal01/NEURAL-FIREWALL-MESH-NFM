<div align="center">
  <img src="assets/logo.svg" alt="Neural Firewall Mesh shield and cryptographic mesh logo" width="132" height="132" />
  <h1>Neural Firewall Mesh</h1>
  <p><strong>NO TRUST. ONLY MATH.</strong></p>
  <p>Cryptographic identity and deterministic zero-trust authorization for protected TCP services.</p>
  <p>
    <a href="https://github.com/rxnitkthyal01/-NEURAL-FIREWALL-MESH-NFM-/releases/latest"><img src="https://img.shields.io/github/v/release/rxnitkthyal01/-NEURAL-FIREWALL-MESH-NFM-?style=flat-square&amp;label=release" alt="Latest GitHub release" /></a>
    <a href="LICENSE"><img src="https://img.shields.io/github/license/rxnitkthyal01/-NEURAL-FIREWALL-MESH-NFM-?style=flat-square" alt="GitHub license" /></a>
    <a href="https://github.com/rxnitkthyal01/-NEURAL-FIREWALL-MESH-NFM-/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/rxnitkthyal01/-NEURAL-FIREWALL-MESH-NFM-/ci.yml?style=flat-square&amp;label=CI" alt="GitHub Actions CI status" /></a>
    <a href="https://github.com/rxnitkthyal01/-NEURAL-FIREWALL-MESH-NFM-/stargazers"><img src="https://img.shields.io/github/stars/rxnitkthyal01/-NEURAL-FIREWALL-MESH-NFM-?style=flat-square" alt="GitHub stars" /></a>
    <a href="https://github.com/rxnitkthyal01/-NEURAL-FIREWALL-MESH-NFM-/releases"><img src="https://img.shields.io/github/downloads/rxnitkthyal01/-NEURAL-FIREWALL-MESH-NFM-/total?style=flat-square&amp;label=downloads" alt="GitHub release downloads" /></a>
  </p>
</div>

NFM is a Python security core for protecting explicitly configured TCP services. Its current implementation uses TLS 1.3 mutual authentication, short-lived CA-signed node certificates, a deterministic deny-by-default policy engine, SQLite audit state, and a TCP proxy that checks identity and policy before connecting to an upstream service.

This is an early MVP foundation, not a host-wide firewall or a replacement for SSH, curl, or netcat. It does not inspect arbitrary host traffic. The API supports administrator-approved remote enrollment, Ed25519-signed policies, HTTPS-authenticated identity/revocation snapshots, and administrator-controlled node isolation. NFM is operated from its CLI; `nfm tui` provides a live, read-only terminal overview of local controller state. A separate optional React dashboard is also available. nftables integration, automated compromise detection, and post-quantum transport remain outstanding.

## Requirements

- Python 3.12 or newer
- Node.js 20.19 or newer for the optional dashboard
- Linux is the target for the initial protected-service deployment. The Python CLI and local core are designed to be portable, but this release has not been validated across operating systems.

## Install

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
nfm init
```

On Windows **Command Prompt (CMD)**, use these commands instead of `source`:

```bat
python --version
python -m venv .venv
.venv\Scripts\activate.bat
python -m pip install -e ".[dev]"
set "NFM_HOME=%CD%\.nfm"
nfm init
```

`NFM_HOME` puts demo state under the project in the ignored `.nfm` directory. In every new CMD window, repeat `set "NFM_HOME=%CD%\.nfm"` before running NFM commands. This is useful if Windows cannot create the default `%USERPROFILE%\.nfm` directory. Use `.venv\Scripts\Activate.ps1` to activate from PowerShell. Open a new terminal for each demo process and activate `.venv` there too. The virtual environment keeps dependencies isolated from the user-wide Python packages.

The first `nfm init` creates a local CA, policy-signing keypair, and SQLite state in `~/.nfm` (or `$NFM_HOME`). Treat `~/.nfm/ca/ca-key.pem` and `~/.nfm/policy-signing-key.pem` as root credentials. The policy-signing public key may be distributed out of band to agents. Local certificate issuance is useful for a single-host lab; remote agents can enroll through the approved CSR workflow below. Do not distribute either private key to mesh nodes.

## Reproducible local demonstration

This demonstrates actual TLS and policy behavior on one machine. Use separate state directories for controller/server and client identities only after arranging a secure way to copy the client's certificate and key; this starter bootstrap keeps all material under one local state directory for simplicity.

1. Initialize a lab CA, and create client and server node identities:

   ```sh
   nfm init
   nfm node issue client-a --role application
   nfm node issue server-b --role database
   ```

2. Start the included one-request echo upstream on `127.0.0.1:9001`:

   ```sh
   python examples/echo_server.py --host 127.0.0.1 --port 9001
   ```
3. Activate the example policy and start the protected proxy:

   ```sh
   nfm policy validate configs/example-policy.yaml
   nfm policy activate configs/example-policy.yaml
   nfm serve-proxy --node-id server-b --service database --listen 127.0.0.1 --port 9443 --upstream-host 127.0.0.1 --upstream-port 9001
   ```

4. In another terminal, send a request through mutual TLS:

   ```sh
   nfm connect --node-id client-a --server-node-id server-b --host 127.0.0.1 --port 9443 --data 'hello'
   ```

   The example policy permits role `application` to `database`; the proxy will connect only after certificate, enrollment, and policy checks succeed.

5. Revoke the client identity from a third terminal and repeat the request:

   ```sh
   nfm node revoke client-a
   ```

   The proxy denies subsequent sessions. It rechecks revocation, credential expiration, and policy for open sessions every second and closes sessions that are no longer authorized. This assumes the proxy and revocation command use the same local state directory.

The example policy includes a deny rule for node ID `compromised-node`; explicit deny rules take precedence over allow rules. The proxy forwards raw TCP bytes. The one-shot `nfm connect` helper sends a UTF-8 line (appending a newline) and reads up to 1 MiB of response data until the upstream closes; it is not an interactive client.

## Multi-node enrollment and synchronization

The controller's API must be reachable over HTTPS for remote agents. `nfm serve-controller` binds to loopback by default; put it behind a TLS reverse proxy before exposing it to other hosts. Configure three independent random secrets of at least 32 characters on the controller: `NFM_ADMIN_TOKEN`, `NFM_ENROLLMENT_TOKEN`, and `NFM_AGENT_TOKEN`.

1. On the controller, initialize NFM, activate a policy, and start the API. Securely copy only `ca-cert.pem` and `policy-signing-public.pem` to each enforcement host; never copy the CA or policy signing private keys.
2. On every enforcement host (including both the client host and the protected-service host), install those trust anchors and submit an enrollment request over HTTPS. For example, enroll the client as `node-a` with role `application` and the protected-service host as `node-b` with role `database`:

   ```sh
   nfm agent trust-ca ca-cert.pem
   nfm agent trust-policy-key policy-signing-public.pem
   nfm node request node-a --role application --controller-url https://controller.example
   # On the protected-service host, use its own state directory and run:
   nfm node request node-b --role database --controller-url https://controller.example
   ```

   Set `NFM_ENROLLMENT_TOKEN` in the agent environment. The node generates its private key locally; only its CSR is sent.
3. On the controller, review pending requests and approve the intended node:

   ```sh
   nfm node requests
   nfm node approve <request-id>
   ```

4. On each enforcement host, fetch that host's approved certificate and run the sync agent using the same `NFM_HOME` as its proxy. Set `NFM_AGENT_TOKEN` to the controller's agent-sync secret. Keep `nfm agent start` running on both hosts:

   ```sh
   nfm node fetch node-a <request-id> --controller-url https://controller.example
   nfm agent start --controller-url https://controller.example --interval 30
   ```

   Repeat with `node-b` and its request ID on the protected-service host. The proxy fails closed if its last successful synchronization becomes older than `NFM_MAX_OFFLINE_AGE_SECONDS` (default 300 seconds). Choose a value that matches the revocation delay your lab accepts.

The agent verifies signed policy bundles before activation, synchronizes the controller's node inventory, revocations, and security states, and keeps the last accepted policy while temporarily offline. Set an affected node to `RESTRICTED` or `ISOLATED` on the controller with `nfm node state`; the proxy denies new requests and terminates existing sessions on its next state check. Moving a restricted or isolated node back to a less restrictive state requires `--approve-recovery`. This state control is administrator-driven; NFM does not detect endpoint compromise automatically. Sync polling is not instantaneous; use the configured interval when considering revocation exposure. When the controller explicitly clears its policy, agents fail closed by clearing the cached active policy.

## Commands

```text
nfm init
nfm node issue <node-id> --role <role> [--days 30]
nfm node list [--json]
nfm node inspect <node-id>
nfm node revoke <node-id>
nfm node state <node-id> <HEALTHY|DEGRADED|RESTRICTED|ISOLATED> [--approve-recovery]
nfm node requests
nfm node approve <request-id>
nfm node request <node-id> --role <role> --controller-url <https-url>
nfm node fetch <node-id> <request-id> --controller-url <https-url>
nfm policy validate <file>
nfm policy create <output.yaml> [--policy-id nfm-policy]
nfm policy activate <file>
nfm policy list [--json]
nfm policy revoke <policy-id>
nfm policy export <output.json>
nfm policy import <bundle.json> --trusted-key <controller-public-key.pem>
nfm policy evaluate <node-id> <role> <service> [operation]
nfm serve-proxy --node-id ... --service ... --port ... --upstream-host ... --upstream-port ...
nfm connect --node-id ... --server-node-id ... --host ... --port ... --data ...
nfm security events [--json]
nfm security audit
nfm session list [--json]
nfm session revoke <session-id>
nfm mesh status
nfm mesh peers [--json]
nfm serve-controller [--host 127.0.0.1] [--port 8080]
nfm agent trust-ca <certificate.pem>
nfm agent trust-policy-key <public-key.pem>
nfm agent status
nfm agent sync --controller-url <https-url>
nfm agent start --controller-url <https-url> [--interval 30]
nfm tui [--refresh 5] [--once]
nfm doctor
```

Run `nfm tui` for a continuously refreshed terminal overview of the selected local state (`NFM_HOME`). Use `nfm tui --once` for a single snapshot. The view is read-only; use the CLI commands above to change node, policy, and session state.

### Remote controller administration from the CLI

The `nfm admin` command group manages a controller over HTTPS using the same bearer-authenticated API as the optional web interface. The URL must be HTTPS; HTTP is accepted only for loopback development. TLS certificate validation stays enabled. Set the controller origin and admin secret in the shell rather than putting secrets in command history:

```sh
export NFM_CONTROLLER_URL=https://localhost:8443
export NFM_ADMIN_TOKEN="$(cat ~/.config/nfm/admin.token)"
nfm admin nodes
nfm admin policy
nfm admin events --json
nfm admin enrollment-requests
nfm admin validate-policy configs/example-policy.yaml
nfm admin activate-policy configs/example-policy.yaml
nfm admin revoke-node client-a
nfm admin set-node-state server-b ISOLATED
```

Remote admin events are controller-local. Protected-session records and proxy enforcement events remain in each node's local store; use `NFM_HOME` with `nfm session list`, `nfm security events`, or `nfm tui` on that node to inspect them. Node revocation and security-state updates reach agents during signed snapshot synchronization.

The local controller API exposes node and policy administration, signed policy bundles, approved enrollment requests, and agent snapshots. Administrative routes use `NFM_ADMIN_TOKEN`; enrollment routes use `NFM_ENROLLMENT_TOKEN`; agent snapshots use `NFM_AGENT_TOKEN`. Keep these secrets separate. The default listener is loopback. Use TLS termination before binding it beyond localhost; the API does not yet provide individual user accounts or role-based administrator permissions.

## Optional web dashboard

The React dashboard reads node, policy, session, and audit data from the controller API. It supports policy validation/activation, node revocation, and audited security-state changes. Its topology view draws edges only from recorded proxy sessions and labels protected services rather than inventing peer-to-peer links.

```sh
# Terminal 1: run the local controller API
export NFM_ADMIN_TOKEN='replace-with-a-random-secret-of-at-least-32-characters'
nfm serve-controller --host 127.0.0.1 --port 8080

# Terminal 2: run the dashboard development server
cd dashboard
npm install
npm run dev
```

Open the local Vite URL and enter `NFM_ADMIN_TOKEN`. The dashboard keeps that token in page memory only. Vite proxies `/api` to `http://127.0.0.1:8080`; set `NFM_DASHBOARD_API` if your local controller uses another origin. For deployment, serve the built dashboard and API behind the same-origin HTTPS reverse proxy. The UI is a separate management tool and is not required for node enforcement.

In PowerShell, set the controller token with `$env:NFM_ADMIN_TOKEN = 'replace-with-a-random-secret-of-at-least-32-characters'` in the controller terminal before starting it.

## Security design

- ECDSA P-256 X.509 identities, signed by a local CA; certificates expire within 90 days.
- TLS 1.3 minimum with CA validation and mandatory client certificates at protected proxies.
- The client validates the server's CA chain and exact `urn:nfm:node:<id>` identity SAN.
- The proxy requires the identity to be enrolled and active in its local SQLite store, checks role consistency, and evaluates policy before opening an upstream connection. It rechecks active-session policy, credential expiration, and revocation once per second.
- A missing policy, missing enrollment, revoked node, non-healthy state, or unmatched rule denies access. Explicit deny wins on conflict.
- Private keys are written with owner-only POSIX mode where supported. On Windows, use filesystem ACLs to restrict access.

See [architecture](docs/architecture.md), [security model](docs/security-model.md), [threat model](docs/threat-model.md), [deployment](docs/deployment.md), and [limitations](docs/limitations.md).

## Development

```sh
python -m pip install -e '.[dev]'
pytest
ruff check .
mypy nfm
```

Automated tests are included but have not been run in the authoring environment yet. Do not treat the current code as production-ready until tests and a security review have run on a supported Python 3.12+ environment.

## License

MIT. See [LICENSE](LICENSE).
