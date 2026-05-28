//! Error type for `cdk-pop-verifier`.
//!
//! Surfaces failures that originate at the cashu-token boundary:
//! encoding a challenge for the response, or decoding a `cashuB…` token
//! from the retry request. Wraps the underlying cashu error message as
//! a string so consumers do not need to depend on `cashu` directly to
//! match on it.

use thiserror::Error;

/// Errors returned by the PoP verifier surface.
#[derive(Debug, Error)]
pub enum Error {
    /// The supplied token string was structurally invalid (missing or
    /// unrecognized token prefix).
    #[error("invalid token: {0}")]
    InvalidHeader(String),

    /// The string carried a recognized prefix but the payload failed to
    /// decode (base64, CBOR, or token shape).
    #[error("failed to decode token: {0}")]
    DecodeFailed(String),

    /// Encoding a `PaymentRequest` into the `creqA...` string form failed.
    #[error("failed to encode challenge: {0}")]
    EncodeFailed(String),
}
