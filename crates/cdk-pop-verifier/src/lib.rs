//! PoP (Proof of Power) verifier SDK.
//!
//! NUT-24 HTTP-402 + MPP-Cashu dual-emit verifier for `pop_<ts>` Cashu
//! credentials. Skeleton — real surface arrives in Commit 2+.

#![warn(missing_docs)]

pub mod challenge;
pub mod error;

pub use challenge::{decode_token, encode_challenge, PopRequirement};
pub use error::Error;

/// Placeholder for the PoP verifier. Real surface lands in Commit 2+.
#[derive(Debug)]
pub struct PopVerifier;
