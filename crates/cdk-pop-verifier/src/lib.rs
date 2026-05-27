//! PoP (Proof of Power) verifier SDK.
//!
//! NUT-24 HTTP-402 + MPP-Cashu dual-emit verifier for `pop_<ts>` Cashu
//! credentials. Skeleton — real surface arrives in Commit 2+.

#![warn(missing_docs)]

pub mod challenge;
pub mod error;
pub mod mint_client;
pub mod validator;

pub use challenge::{decode_token, encode_challenge, PopRequirement};
pub use error::Error;
pub use mint_client::{MintClient, MintClientError};
pub use validator::{PopValidator, ValidatedPop, ValidationError};

/// Placeholder for the PoP verifier. Real surface lands in Commit 2+.
#[derive(Debug)]
pub struct PopVerifier;
