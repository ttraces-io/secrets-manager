---
icon: wave-pulse
description: "NIST SP 800-90B continuous DRBG entropy health telemetry endpoints."
---

# Entropy & Health Probes API

## Continuous DRBG Health Telemetry

`GET /v1/entropy/health`

Evaluates NIST SP 800-90B Repetition Count Test (RCT) and Adaptive Proportion Test (APT).

### Response
```json
{
  "status": "ok",
  "data": {
    "rct_passed": true,
    "apt_passed": true,
    "shannon_entropy_bits_per_byte": 7.9942,
    "health_status": "OPTIMAL"
  }
}
```
