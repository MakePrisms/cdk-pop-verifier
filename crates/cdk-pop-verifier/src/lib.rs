//! PoP (Proof of Power) verifier SDK.
//!
//! MPP-Cashu HTTP-402 verifier for `pop_<ts>` Cashu credentials. The
//! verifier challenges holders with `WWW-Authenticate: Payment
//! method="cashu", challenge="creqA…"` and accepts proofs on
//! `Authorization: Payment method="cashu", token="cashuB…"`. The
//! `creqA…` and `cashuB…` payloads are standard NUT-18 / cashu wire
//! formats — only the envelope is MPP. Skeleton — real surface arrives
//! in Commit 2+.

#![warn(missing_docs)]

pub mod auth_header;
pub mod cdk_mint_client;
pub mod challenge;
pub mod error;
pub mod middleware;
pub mod mint_client;
pub mod validator;

pub use auth_header::{parse_payment_authorization, AuthParseError};
pub use cdk_mint_client::CdkMintClient;
pub use challenge::{decode_token, encode_challenge, PopRequirement};
pub use error::Error;
pub use middleware::{require_pop, PopMiddlewareState};
pub use mint_client::{MintClient, MintClientError};
pub use validator::{PopValidator, ValidatedPop, ValidationError};

/// Placeholder for the PoP verifier. Real surface lands in Commit 2+.
#[derive(Debug)]
pub struct PopVerifier;
