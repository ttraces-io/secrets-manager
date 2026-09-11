---
icon: code
description: "Complete REST API and JSON-RPC reference for traces-sm enclave and host gateway services."
---

# API & Protocol Reference

The `traces-sm` API exposes secure REST and JSON-RPC endpoints for managing sealed secrets, hardware key generation, cryptographic signatures, zero-knowledge proofs, and attestation.

## Authentication

All protected endpoints require an in-enclave issued JWT token passed via HTTP `Authorization: Bearer <token>` header:

```http
GET /v1/secrets/550e8400-e29b-41d4-a716-446655440000 HTTP/1.1
Host: 127.0.0.1:8080
Authorization: Bearer eyJhbGciOiJFZDI1NTE5...
```

## Available Endpoint Families

* [Secrets API](endpoints/secrets.md) — Create, retrieve, and delete sealed secrets.
* [Keys & Crypto API](endpoints/keys.md) — In-enclave keypair generation, signing, and verification.
* [ZKP & Homomorphic API](endpoints/zkp.md) — Schnorr PoK, Bulletproofs range proofs, and Paillier PHE.
* [DKG & FROST API](endpoints/dkg.md) — Threshold secret sharing and distributed key generation.
* [Remote Attestation API](endpoints/attest.md) — Fetch Intel SGX DCAP quotes and measurements.
* [Entropy Health API](endpoints/entropy.md) — NIST SP 800-90B continuous DRBG telemetry.
