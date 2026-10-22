# Threat model

## Assets

- Node private keys and CA signing key
- Protected upstream services
- Active authorization policy and node enrollment state
- Session and security-event records

## Trust boundaries and assumptions

- The local machine, Python runtime, OS account, and local state directory are trusted by this MVP.
- The CA private key is a high-value authority. Anyone who can use it can issue an identity accepted by proxies trusting that CA.
- The proxy host and its SQLite database are trusted to enforce local policy.
- Upstream services are reachable only through the protected listener if administrators configure their network accordingly. NFM does not automatically block alternate paths.
- Current local operations assume a trusted administrator invokes the CLI and controls filesystem access.

## Threat coverage

| Threat | Current mitigation | Remaining risk |
|---|---|---|
| Stolen node credential | Short-lived certs, local revocation check | No hardware-backed keys; stolen key works until expiration/revocation reaches proxy |
| Compromised endpoint | Administrator can mark a node RESTRICTED or ISOLATED; proxy denies and terminates affected protected sessions after state sync | State is not automatically inferred; valid key does not prove host integrity; offline nodes may retain stale state |
| Malicious enrollment | HTTPS-protected enrollment token, locally generated signed CSR, administrator approval, CSR signature and key-type validation | Enrollment token theft can create requests; administrator must inspect request identity/role; no device attestation or per-admin roles |
| Replay | TLS 1.3 record protection and fresh handshakes | Application-level replay semantics depend on upstream protocol |
| Unauthorized policy update | Ed25519-signed policy bundles, out-of-band public-key pinning, controller HTTPS authentication, local signature and version validation | Compromise of controller signing key permits malicious policy bundles; admin token and signing key are not hardware protected |
| Controller compromise | None beyond OS controls | Local CA key and state are single administrative authority |
| Network partition | Agent retains locally validated policy and node state; expired credentials are still rejected by TLS | Revocations/updates cannot arrive until reconnect; no maximum policy or revocation age, so stale authorization may persist |
| Denial of service | asyncio backlog and connection timeout to upstream | No global per-peer rate limit, quotas, or hardened resource accounting yet |
| Expired credentials | TLS certificate validation | Depends on correct system clock and TLS implementation |
| Incorrect enforcement | Proxy gates configured listener | Alternate direct paths and host firewall rules are outside this proxy |

Repeated application-level authorization failures are recorded and do not automatically isolate a node. TLS handshakes rejected before the asyncio connection handler are not currently captured in the NFM audit database. The current MVP has no automatic host isolation or operating-system repair.

Remote enrollment and synchronization use shared bearer tokens, not individually scoped node credentials. Deploy the controller behind correctly configured HTTPS, use distinct high-entropy enrollment, agent, and administrator tokens, and protect the CA/signing key files. The controller remains a trust authority for enrollment and revocation distribution; signed policy validation lets agents enforce cached policy during outages but does not eliminate stale-revocation risk.
