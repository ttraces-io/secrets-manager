---
icon: infinity
description: "Zero-knowledge proof verification and Paillier partially homomorphic encryption endpoints."
---

# Zero-Knowledge Proofs & Homomorphic Encryption API

## Pedersen Commitment Generation

`POST /v1/zkp/pedersen/commit`

```json
{
  "value": 1500
}
```

### Response
```json
{
  "status": "ok",
  "data": {
    "commitment_hex": "4a7b293c...",
    "blinding_hex": "9f1e82d4..."
  }
}
```

---

## Schnorr Proof of Knowledge

`POST /v1/zkp/schnorr/prove`

Generates non-interactive zero-knowledge proof of knowledge for a discrete log witness.
