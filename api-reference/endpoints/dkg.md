---
icon: users-viewfinder
description: "Distributed Key Generation, Shamir secret sharing, and FROST threshold signature endpoints."
---

# Threshold DKG & FROST API

## List Active DKG Nodes

`GET /v1/dkg/nodes`

Returns current threshold cluster topology, participant weights, and RA-TLS verification status.

## Split Secret (Shamir & VSS)

`POST /v1/dkg/split`

Splits a master secret into $M$-of-$N$ threshold polynomial shares.
