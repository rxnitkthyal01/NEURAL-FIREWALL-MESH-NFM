# Neural Firewall Mesh (NFM) v2.0 Architecture

## Overview

Neural Firewall Mesh (NFM) v2.0 transitions the cryptographic and control-plane architecture from classical primitives (ECDSA/Ed25519 stored on disk) to a post-quantum, hardware-backed, and resilient distributed architecture.

---

## 1. Post-Quantum Cryptography (PQC)

- **Policy Signatures:** Transitioning policy signing bundles from Ed25519 to NIST-standardized **ML-DSA** (CRYSTALS-Dilithium) to ensure quantum-resistant administrative policy updates.
- **Transport Security:** Incorporating hybrid key encapsulation mechanisms (**ML-KEM** / CRYSTALS-Kyber combined with ECDH) in TLS 1.3 transport tunnels to protect against store-now-decrypt-later quantum attacks.

---

## 2. Hardware Security Module (HSM) & TPM 2.0 Integration

- **Controller CA & Signing Keys:** Replacing unencrypted PEM disk storage with PKCS#11 hardware security module integration (supporting Cloud KMS, Vault, or physical HSM appliances) for CA operations and policy signing.
- **Node-Bound Private Keys:** Integrating TPM 2.0 endorsement keys and persistent hierarchy storage so node private keys are generated inside secure cryptoprocessors and cannot be extracted from host filesystems.

---

## 3. Distributed Consensus & Replication (Raft)

- **High Availability Controller:** Replacing single-node SQLite files with a lightweight Raft consensus state machine for controller metadata replication (node inventory, enrollment requests, active policy state).
- **Fault Tolerance:** Eliminating controller single points of failure while preserving local agent fallback and offline synchronization guarantees.
