# Security model

## Authentication and authorization

TLS client authentication proves that a peer possesses the private key corresponding to a currently valid certificate issued by the configured CA. It does not grant service access. The proxy separately checks the node's active enrollment, stored role, revocation status, and active policy. Authorization defaults to deny.

TLS certificate validity is checked by the standard library/OpenSSL TLS implementation. The peer identity is taken from a URI SAN, not an IP address or a self-asserted request field. The client checks the server's CA chain and expected NFM identity.

## Cryptography

The current implementation uses the maintained `cryptography` package for ECDSA P-256/X.509 and Ed25519 policy signatures, and Python's `ssl` module for TLS 1.3. It implements no cryptographic primitive or transport protocol of its own. No post-quantum algorithms are negotiated or claimed.

## Policy semantics

Each rule can constrain source node IDs, source roles, service names, and operation names. Every rule must specify a source selector, service, and operation; `*` makes a wildcard explicit. Any matching deny wins; otherwise a matching allow permits; no match denies. The service proxy evaluates the `connect` operation and only permits a node in `HEALTHY` state. `DEGRADED`, `RESTRICTED`, and `ISOLATED` currently all deny protected access. An administrator sets state through the CLI; movement from `RESTRICTED`/`ISOLATED` to a less restrictive state requires explicit recovery approval. This is a manual response control, not automatic endpoint detection. Policy bundles are signed with an Ed25519 controller key and verified against an out-of-band public key before agent activation. Agents poll for updates; stale signed policy versions are rejected. Key rotation is manual and requires a trusted-key replacement workflow.

## Key handling

Node private keys are never stored in SQLite or printed by the CLI. The bootstrap CA key is stored unencrypted on disk, so operating-system access control and administrator handling are critical. Production enrollment should place the CA key in a separate protected control-plane environment or an HSM-backed service and deliver only node-specific credentials securely.

## Revocation

Revocation is represented in the controller inventory and synchronized to agents by authenticated polling. A proxy checks its local database before each upstream connection and re-evaluates revocation, credential expiry, and current policy every second for open sessions. It is not a PKI CRL/OCSP implementation. Propagation waits for the next successful poll; disconnected agents retain stale inventory indefinitely because no maximum offline age is enforced.
