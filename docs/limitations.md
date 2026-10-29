# Current limitations

- Protected-service TCP proxy only; no packet-level or host-wide enforcement.
- SQLite state and a controller-hosted CA. Remote enrollment is available through signed CSRs and explicit administrator approval; there is no device attestation or per-admin authorization model.
- Signed policy bundles are distributed by agent polling; updates are not pushed and can be delayed by the sync interval or network outage. After an agent has entered sync mode, its proxy fails closed when the last successful snapshot is older than `NFM_MAX_OFFLINE_AGE_SECONDS` (default 300 seconds).
- Revocations propagate through snapshot polling and are delayed by the configured polling interval or a disconnected agent. The offline-age limit bounds stale authorization only on nodes whose agent synchronization has been configured; a node never placed in sync mode cannot know that its controller has new revocation data.
- Controller-outage behavior uses cached locally validated policy and inventory; there is no distributed trust authority.
- Security states can be set by an administrator and enforced after synchronization, but there are no automated endpoint integrity checks, compromise detection, or automatic self-healing.
- Re-enrollment can replace an identity serial, and proxies reject older serials after synchronization. There is no automated scheduled credential rotation workflow.
- TLS handshake failures rejected before the application handler are not persisted to the NFM event log.
- Session records can remain marked active after an unclean proxy process exit; the proxy only controls its currently live in-process connections.
- No nftables adapter; host firewall changes are not performed.
- No PostgreSQL backend, container deployment, or benchmark results. SQLite has a minimal versioned migration ledger. The dashboard is an administrative interface only and is not production hardened.
- The dashboard pins direct package versions but has no checked-in npm lockfile yet; dependency installation must run with npm registry access before a reproducible frontend artifact is available.
- Audit and session data remain local to each SQLite store. The dashboard reads controller-local records; it does not aggregate agent event/session streams across the mesh.
- `nfm connect` is a bounded request/response CLI helper, not a general-purpose interactive TCP or SSH replacement.
- No ML-KEM, ML-DSA, or post-quantum security claim.
- Cross-platform source portability is intended, but only Windows authoring environment was available and no runtime test could be completed; Linux deployment remains unverified.
