# Deployment

This release is intended for local development and isolated labs. It has not been validated for production deployment.

1. Install Python 3.12+ and the package (`pip install -e .`).
2. Run `nfm init` as the account that will manage the local lab CA and state.
3. Issue node identities. Keep each key on its corresponding node and do not distribute the CA private key.
4. Configure a policy with narrow service and role matches, then activate it.
5. Run `nfm serve-proxy` on the protected-service host. Bind to the intended reachable interface and configure the upstream so it cannot be reached through an unintended path.
6. Configure host firewall rules separately if network topology requires it. NFM does not change host firewalls.
7. Monitor `nfm security events` and back up SQLite state securely.

The controller supports remote enrollment using a locally generated node key/CSR, enrollment bearer token, and explicit administrator approval. Agents poll node/revocation snapshots over HTTPS with a shared agent token and verify Ed25519-signed policy bundles. After an agent sync is attempted, local enforcement fails closed if there has been no successful snapshot within `NFM_MAX_OFFLINE_AGE_SECONDS` (default 300 seconds); set a deliberate value on each enforcing process. Securely provision only `ca-cert.pem` and `policy-signing-public.pem` to agents; never copy `ca-key.pem` or `policy-signing-key.pem`. The API uses separate shared bearer tokens for administration, enrollment, and agent sync, and should remain bound to loopback unless protected by a correctly configured TLS endpoint. The optional React dashboard can run locally through the Vite API proxy; a deployed dashboard should share a same-origin HTTPS reverse proxy with the API. Container deployment remains future work.
