---
icon: fingerprint
description: "In-enclave key generation, digital signing, and signature verification endpoints."
---

# Keys & Cryptographic Operations API

## Generate In-Enclave Keypair

`POST /v1/keys`

### Request Body
```json
{
  "name": "primary-ed25519-key",
  "algorithm": "Ed25519"
}
```

### Supported Algorithms
* `Rsa2048`, `Rsa4096`
* `EcdsaP256`, `EcdsaP384`, `Secp256k1`
* `Ed25519`, `X25519`
* `MlKem512`, `MlKem768`, `MlKem1024` (PQC KEM)
* `MlDsa3`, `MlDsa5` (PQC Dilithium)
* `Aes128Gcm`, `Aes256Gcm`, `ChaCha20Poly1305`

---

## Sign Message

`POST /v1/keys/{id}/sign`

```json
{
  "data_base64": "RU5DTEFWRV9UUkFOU0FDVElPTl9QQVlMT0FE"
}
```

---

## Verify Signature

`POST /v1/keys/{id}/verify`

```json
{
  "data_base64": "RU5DTEFWRV9UUkFOU0FDVElPTl9QQVlMT0FE",
  "signature_base64": "WjEw..."
}
```
