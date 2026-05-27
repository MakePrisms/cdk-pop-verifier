//! Error type for `cdk-pop-verifier`.
//!
//! Surfaces failures that originate at the NUT-24 `X-Cashu` header boundary:
//! encoding a challenge for the response, or decoding a token from the
//! retry request. Wraps the underlying cashu error message as a string so
//! consumers do not need to depend on `cashu` directly to match on it.

use thiserror::Error;

/// Errors returned by the PoP verifier surface.
#[derive(Debug, Error)]
pub enum Error {
    /// The supplied `X-Cashu` header value was structurally invalid (missing
    /// or unrecognized token prefix).
    #[error("invalid X-Cashu header: {0}")]
    InvalidHeader(String),

    /// The header value carried a recognized prefix but the payload failed to
    /// decode (base64, CBOR, or token shape).
    #[error("failed to decode token: {0}")]
    DecodeFailed(String),

    /// Encoding a `PaymentRequest` into the `creqA...` string form failed.
    #[error("failed to encode challenge: {0}")]
    EncodeFailed(String),
}
