# Architecture

## Current data path

```text
NFM client -- TLS 1.3 + client certificate --> NFM protected proxy
                                                  |
                                      identity/enrollment/revocation check
                                                  |
                                      deny-by-default policy decision
                                                  |
                                                  v
                                     configured upstream TCP service
```

The controller is an administrative API and CLI over one SQLite state directory. Administrators approve CSRs; node private keys remain on the requesting agent. An agent polls authenticated snapshots containing controller node state and an Ed25519-signed active policy. Proxies make decisions locally and do not call the controller for each connection.

The optional React dashboard uses the authenticated controller API to read inventory, recorded sessions, policies, and audit events. Policy and node-state changes go through the same admin-authenticated API. It has no enforcement role.

## Components

- `nfm.identity.credentials`: local CA and short-lived X.509 client/server certificate issuance.
- `nfm.crypto.transport`: TLS 1.3 client setup and server identity SAN validation.
- `nfm.policy.engine`: deterministic rule matching with explicit deny precedence and default deny.
- `nfm.storage.database`: SQLite node, policy, session, and security-event state.
- `nfm.enforcement.proxy`: asyncio TLS server, authorization gate, upstream TCP relay, and revocation polling.
- `nfm.controller.api` and CLI session controls: administrator-triggered identity/state/session revocation; proxies close live sessions after the next one-second local check.
- `nfm.cli`: Typer commands for local bootstrap, policy, node lifecycle, proxy, and event inspection.

## Database evolution

Tables are currently created with idempotent `CREATE TABLE IF NOT EXISTS` statements at startup. A versioned migration framework and PostgreSQL backend are not present yet.

## Offline behavior

The proxy uses its local SQLite policy and revocation state. The agent polls authenticated snapshots, verifies signed policy bundles, and updates its local store; therefore a controller outage does not interrupt an already running proxy process. A revocation that has not reached the local database cannot be enforced there. There is no maximum offline policy age, so this trades revocation freshness for availability during partitions.
