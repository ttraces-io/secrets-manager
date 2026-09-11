//! Host HTTP API Route Handlers.
//!
//! # Route Groups
//! - [`attest`]: Attestation quote forwarding and measurement queries.
//! - [`dkg`]: DKG cluster topology and node status routes.
//! - [`entropy`]: System entropy health telemetry endpoints.
//! - [`keys`]: Asymmetric and symmetric key management gateway.
//! - [`lifecycle`]: Key lifecycle transition and crypto-shredding routes.
//! - [`secrets`]: Secret CRUD gateway routes.
//! - [`tokens`]: Authentication token query and revocation routes.

pub mod attest;
pub mod dkg;
pub mod entropy;
pub mod keys;
pub mod lifecycle;
pub mod secrets;
pub mod tokens;
