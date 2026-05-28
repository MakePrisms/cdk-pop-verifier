//! PoP (Proof of Power) verifier SDK.
//!
//! Per `draft-httpauth-payment-00`, an HTTP-402 verifier for `pop_<ts>`
//! Cashu credentials. The verifier challenges holders with
//! `WWW-Authenticate: Payment id="…", realm="…", method="cashu",
//! intent="charge", request="<base64url(json{cashu_request:creqA…})>"`
//! and accepts proofs on
//! `Authorization: Payment <base64url(json{challenge:{…}, payload:{cashu_token:cashuB…}})>`.
//! The `creqA…` and `cashuB…` payloads are standard NUT-18 / cashu wire
//! formats — only the envelope is draft-httpauth-payment-00.

#![warn(missing_docs)]

pub mod auth_header;
pub mod cdk_mint_client;
pub mod challenge;
pub mod error;
pub mod middleware;
pub mod mint_client;
pub mod validator;

pub use auth_header::{
    encode_payment_credentials, parse_payment_authorization, AuthParseError, CashuPayload,
    EchoedChallenge, PaymentCredentials,
};
pub use cdk_mint_client::CdkMintClient;
pub use challenge::{
    decode_request_envelope, decode_token, encode_challenge, encode_request_envelope,
    PopRequirement,
};
pub use error::Error;
pub use middleware::{require_pop, PopMiddlewareState, DEFAULT_REALM, INTENT_CHARGE};
pub use mint_client::{MintClient, MintClientError};
pub use validator::{PopValidator, ValidatedPop, ValidationError};

/// Placeholder type retained for backwards compatibility.
#[derive(Debug)]
pub struct PopVerifier;
