---
icon: key
description: "REST API specifications for sealed secret CRUD and envelope encryption."
---

# Secrets Management API

## Create Sealed Secret

`POST /v1/secrets`

Encrypts and seals a confidential plaintext payload inside the SGX enclave.

### Request Body
```json
{
  "name": "database-password",
  "plaintext_base64": "c3VwZXJfc2VjcmV0X3Bhc3N3b3JkXzEyMw==",
  "owner": "admin-principal",
  "secret_type": "opaque"
}
```

### Response
```json
{
  "status": "ok",
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "database-password",
    "version": 1,
    "created_at": "2026-09-11T20:00:00Z"
  }
}
```

---

## Retrieve Sealed Secret

`GET /v1/secrets/{id}`

Unseals and returns the decrypted plaintext payload.

### Response
```json
{
  "status": "ok",
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "database-password",
    "plaintext_base64": "c3VwZXJfc2VjcmV0X3Bhc3N3b3JkXzEyMw=="
  }
}
```
