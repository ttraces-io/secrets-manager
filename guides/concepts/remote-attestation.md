---
icon: certificate
description: "Intel SGX DCAP Remote Attestation and RA-TLS mutual authentication."
---

# Intel SGX Remote Attestation & RA-TLS

Remote Attestation allows remote parties to cryptographically verify that they are communicating with an authentic `traces-sm` enclave running on genuine Intel SGX hardware.

## Attestation Quote Attributes

* **`MRENCLAVE`**: Cryptographic SHA-256 hash of the exact binary code and data loaded into EPC RAM.
* **`MRSIGNER`**: Cryptographic hash of the enclave author's release signing key.
* **`ISVSVN`**: Security version number enforcing anti-rollback policies.

## RA-TLS Handshake

The enclave generates an ephemeral X.509 certificate embedding the Intel DCAP quote in ASN.1 extension OID `1.3.6.1.4.1.311.21.10`. Clients verify the quote against Intel Provisioning Certificate Service (PCCS) during the TLS handshake.
