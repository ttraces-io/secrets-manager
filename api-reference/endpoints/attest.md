---
icon: certificate
description: "Intel SGX DCAP Remote Attestation quote generation and quote verification endpoints."
---

# Remote Attestation API

## Get SGX Attestation Quote

`GET /v1/attest/quote`

Fetches raw Intel DCAP quote containing `MRENCLAVE`, `MRSIGNER`, and cryptographic hardware signatures.

### Response
```json
{
  "status": "ok",
  "data": {
    "measurements": {
      "mr_enclave": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      "mr_signer": "5d41402abc4b2a76b9719d911017c592"
    },
    "quote_base64": "AwACAAAAAAAHAAkAAAA..."
  }
}
```
